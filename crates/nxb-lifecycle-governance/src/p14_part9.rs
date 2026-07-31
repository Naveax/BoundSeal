impl ContinuityAuthority {
    pub fn new(
        authority_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, LifecycleError> {
        let authority_id = authority_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_identifier(&authority_id, "continuity authority")?;
        validate_sha256(&policy_snapshot_sha256, "continuity authority policy")?;
        Ok(Self {
            authority_id,
            policy_snapshot_sha256,
            audit: LifecycleAuditChain::new(audit_genesis)?,
        })
    }

    pub fn certify(
        &mut self,
        maintenance: &MaintenanceReleaseCertificate,
        archive: &ArchiveBundle,
        retention: &RetentionPolicy,
        redaction: &RedactionManifest,
        recovery: &RecoveryPlan,
        quorum: &RecoveryQuorum,
    ) -> Result<ContinuityCertificate, LifecycleError> {
        maintenance.verify()?;
        archive.verify()?;
        retention.verify()?;
        redaction.verify()?;
        recovery.verify()?;
        quorum.verify()?;
        if maintenance.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || archive.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || retention.policy_snapshot_sha256 != self.policy_snapshot_sha256
            || archive.maintenance_release_certificate_sha256 != maintenance.certificate_sha256
            || redaction.archive_bundle_sha256 != archive.bundle_sha256
            || redaction
                .object_dispositions
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                != archive.object_ids
            || recovery.archive_bundle_sha256 != archive.bundle_sha256
            || recovery.retention_policy_sha256 != retention.policy_sha256
            || recovery.redaction_manifest_sha256 != redaction.manifest_sha256
            || quorum.recovery_plan_sha256 != recovery.plan_sha256
            || quorum.archive_bundle_sha256 != archive.bundle_sha256
            || quorum.maximum_final_virtual_tick > recovery.maximum_virtual_ticks
        {
            return Err(LifecycleError::InvalidContinuity(
                "continuity policy or certificate closure".into(),
            ));
        }
        let seed = hash_serializable(&(
            &self.authority_id,
            &self.policy_snapshot_sha256,
            &maintenance.certificate_sha256,
            &archive.bundle_sha256,
            &recovery.plan_sha256,
            &quorum.quorum_sha256,
        ))?;
        let certificate_id = format!("continuity-{}", &seed[..24]);
        self.audit.append(LifecycleAuditEvent {
            action: "continuity_certified".into(),
            subject_id: certificate_id.clone(),
            outcome: "certified".into(),
            metadata: BTreeMap::from([
                ("archive_bundle_sha256".into(), archive.bundle_sha256.clone()),
                ("recovery_quorum_sha256".into(), quorum.quorum_sha256.clone()),
            ]),
        })?;
        let authority_audit_tail_hash = self.audit.tail_hash().to_owned();
        let certificate_sha256 = hash_serializable(&(
            &certificate_id,
            &self.policy_snapshot_sha256,
            &maintenance.certificate_sha256,
            &archive.bundle_sha256,
            &retention.policy_sha256,
            &redaction.manifest_sha256,
            &recovery.plan_sha256,
            &quorum.quorum_sha256,
            &quorum.result_root_sha256,
            &authority_audit_tail_hash,
        ))?;
        let certificate = ContinuityCertificate {
            certificate_id,
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            maintenance_release_certificate_sha256: maintenance.certificate_sha256.clone(),
            archive_bundle_sha256: archive.bundle_sha256.clone(),
            retention_policy_sha256: retention.policy_sha256.clone(),
            redaction_manifest_sha256: redaction.manifest_sha256.clone(),
            recovery_plan_sha256: recovery.plan_sha256.clone(),
            recovery_quorum_sha256: quorum.quorum_sha256.clone(),
            recovery_result_root_sha256: quorum.result_root_sha256.clone(),
            authority_audit_tail_hash,
            certificate_sha256,
        };
        certificate.verify()?;
        Ok(certificate)
    }

    pub fn audit(&self) -> &LifecycleAuditChain {
        &self.audit
    }
}
