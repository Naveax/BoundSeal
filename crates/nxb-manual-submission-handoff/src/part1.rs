use std::collections::{BTreeMap, BTreeSet};

use nxb_knowledge_reporting::{ExportManifest, ReportBundle, ReportDocument};
use nxb_run_closure::{ClosureDisposition, RunClosureCertificate};
use nxb_unified_operator::UnifiedOperatorPlan;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MANUAL_HANDOFF_VERSION: u32 = 1;
pub const MAX_HANDOFF_METADATA: usize = 64;
pub const MAX_PROGRAM_HANDLE_BYTES: usize = 192;
pub const MAX_FINDINGS: usize = 10_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionPlatform {
    HackerOne,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManualReviewDecision {
    ApprovedForManualSubmission,
    Hold,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManualReviewAttestation {
    pub reviewer_id: String,
    pub decision: ManualReviewDecision,
    pub reviewed_at_epoch_seconds: i64,
    pub acknowledged_untested_scope_sha256: BTreeSet<String>,
    pub review_note_sha256: Option<String>,
}

impl ManualReviewAttestation {
    fn validate(
        &self,
        closure: &RunClosureCertificate,
        generated_at_epoch_seconds: i64,
    ) -> Result<(), ManualHandoffError> {
        validate_identifier(&self.reviewer_id)?;
        if self.reviewed_at_epoch_seconds < closure.manifest.generated_at_epoch_seconds
            || self.reviewed_at_epoch_seconds > generated_at_epoch_seconds
        {
            return Err(ManualHandoffError::InvalidReviewWindow);
        }
        if let Some(digest) = &self.review_note_sha256 {
            validate_sha256(digest)?;
        }
        for digest in &self.acknowledged_untested_scope_sha256 {
            validate_sha256(digest)?;
        }
        match closure.manifest.disposition {
            ClosureDisposition::Complete => {
                if !self.acknowledged_untested_scope_sha256.is_empty() {
                    return Err(ManualHandoffError::UntestedScopeMismatch);
                }
            }
            ClosureDisposition::Partial => {
                if self.acknowledged_untested_scope_sha256
                    != closure.manifest.untested_scope_sha256
                {
                    return Err(ManualHandoffError::UntestedScopeMismatch);
                }
            }
            ClosureDisposition::Aborted => {
                return Err(ManualHandoffError::AbortedClosureNotSubmittable)
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManualSubmissionHandoffManifest {
    pub version: u32,
    pub handoff_id: String,
    pub platform: SubmissionPlatform,
    pub program_handle: String,
    pub closure_id: String,
    pub closure_manifest_sha256: String,
    pub closure_signature_sha256: String,
    pub plan_sha256: String,
    pub policy_snapshot_sha256: String,
    pub report_id: String,
    pub report_json_sha256: String,
    pub report_markdown_sha256: String,
    pub evidence_export_root_sha256: String,
    pub source_audit_tail_sha256: String,
    pub finding_count: u64,
    pub finding_set_sha256: String,
    pub review: ManualReviewAttestation,
    pub metadata: BTreeMap<String, String>,
    pub generated_at_epoch_seconds: i64,
    pub manifest_sha256: String,
}

impl ManualSubmissionHandoffManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        plan: &UnifiedOperatorPlan,
        closure: &RunClosureCertificate,
        closure_public_key: &[u8],
        report: &ReportBundle,
        export_manifest: &ExportManifest,
        platform: SubmissionPlatform,
        program_handle: impl Into<String>,
        review: ManualReviewAttestation,
        metadata: BTreeMap<String, String>,
        generated_at_epoch_seconds: i64,
    ) -> Result<Self, ManualHandoffError> {
        closure.verify(plan, closure_public_key)?;
        verify_report_bundle(report)?;
        export_manifest.verify()?;
        let program_handle = program_handle.into();
        validate_program_handle(&program_handle)?;
        validate_metadata(&metadata)?;
        if generated_at_epoch_seconds < closure.manifest.generated_at_epoch_seconds
            || generated_at_epoch_seconds < report.document.generated_at_epoch_seconds
        {
            return Err(ManualHandoffError::InvalidGenerationTime);
        }
        review.validate(closure, generated_at_epoch_seconds)?;
        verify_component_bindings(closure, report, export_manifest)?;
        if review.decision != ManualReviewDecision::ApprovedForManualSubmission {
            return Err(ManualHandoffError::ReviewNotApproved);
        }
        if report.document.findings.is_empty() || report.document.findings.len() > MAX_FINDINGS {
            return Err(ManualHandoffError::InvalidFindingCount);
        }
        let finding_set_sha256 = calculate_finding_set_sha256(&report.document)?;
        let mut manifest = Self {
            version: MANUAL_HANDOFF_VERSION,
            handoff_id: String::new(),
            platform,
            program_handle,
            closure_id: closure.manifest.closure_id.clone(),
            closure_manifest_sha256: closure.manifest.manifest_sha256.clone(),
            closure_signature_sha256: hash_bytes(
                &decode_hex(&closure.signature_hex)
                    .map_err(|_| ManualHandoffError::InvalidClosureSignatureEncoding)?,
            ),
            plan_sha256: closure.manifest.plan_sha256.clone(),
            policy_snapshot_sha256: closure.manifest.policy_snapshot_sha256.clone(),
            report_id: report.document.report_id.clone(),
            report_json_sha256: report.json_sha256.clone(),
            report_markdown_sha256: report.markdown_sha256.clone(),
            evidence_export_root_sha256: export_manifest.root_sha256.clone(),
            source_audit_tail_sha256: report.document.source_audit_tail_hash.clone(),
            finding_count: report.document.findings.len() as u64,
            finding_set_sha256,
            review,
            metadata,
            generated_at_epoch_seconds,
            manifest_sha256: String::new(),
        };
        manifest.handoff_id = manifest.calculate_handoff_id()?;
        manifest.manifest_sha256 = manifest.calculate_sha256()?;
        manifest.verify(plan, closure, report, export_manifest)?;
        Ok(manifest)
    }

    pub fn verify(
        &self,
        plan: &UnifiedOperatorPlan,
        closure: &RunClosureCertificate,
        report: &ReportBundle,
        export_manifest: &ExportManifest,
    ) -> Result<(), ManualHandoffError> {
        if self.version != MANUAL_HANDOFF_VERSION
            || self.plan_sha256 != plan.plan_sha256
            || self.policy_snapshot_sha256 != plan.binding.policy_sha256
            || self.closure_id != closure.manifest.closure_id
            || self.closure_manifest_sha256 != closure.manifest.manifest_sha256
            || self.generated_at_epoch_seconds <= 0
        {
            return Err(ManualHandoffError::ComponentMismatch);
        }
        validate_identifier(&self.handoff_id)?;
        validate_program_handle(&self.program_handle)?;
        validate_sha256(&self.manifest_sha256)?;
        validate_sha256(&self.closure_signature_sha256)?;
        validate_sha256(&self.finding_set_sha256)?;
        validate_metadata(&self.metadata)?;
        self.review.validate(closure, self.generated_at_epoch_seconds)?;
        if self.review.decision != ManualReviewDecision::ApprovedForManualSubmission {
            return Err(ManualHandoffError::ReviewNotApproved);
        }
        verify_report_bundle(report)?;
        export_manifest.verify()?;
        verify_component_bindings(closure, report, export_manifest)?;
        if self.report_id != report.document.report_id
            || self.report_json_sha256 != report.json_sha256
            || self.report_markdown_sha256 != report.markdown_sha256
            || self.evidence_export_root_sha256 != export_manifest.root_sha256
            || self.source_audit_tail_sha256 != report.document.source_audit_tail_hash
            || self.finding_count != report.document.findings.len() as u64
            || self.finding_set_sha256 != calculate_finding_set_sha256(&report.document)?
        {
            return Err(ManualHandoffError::ComponentMismatch);
        }
        if self.handoff_id != self.calculate_handoff_id()? {
            return Err(ManualHandoffError::HandoffIdMismatch);
        }
        if self.manifest_sha256 != self.calculate_sha256()? {
            return Err(ManualHandoffError::ManifestDigestMismatch);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, ManualHandoffError> {
        validate_identifier(&self.handoff_id)?;
        validate_sha256(&self.manifest_sha256)?;
        if self.handoff_id != self.calculate_handoff_id()?
            || self.manifest_sha256 != self.calculate_sha256()?
        {
            return Err(ManualHandoffError::ManifestDigestMismatch);
        }
        serde_json::to_vec(self)
            .map_err(|error| ManualHandoffError::Serialization(error.to_string()))
    }

    fn calculate_handoff_id(&self) -> Result<String, ManualHandoffError> {
        let mut material = self.clone();
        material.handoff_id.clear();
        material.manifest_sha256.clear();
        let digest = hash_serializable(&material)?;
        Ok(format!("handoff-{}", &digest[..24]))
    }

    fn calculate_sha256(&self) -> Result<String, ManualHandoffError> {
        let mut material = self.clone();
        material.manifest_sha256.clear();
        hash_serializable(&material)
    }
}
