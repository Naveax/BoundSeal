#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportFinding {
    pub finding_id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub origin: String,
    pub endpoint_sha256: String,
    pub summary: String,
    pub evidence_ids: BTreeSet<String>,
}

impl TryFrom<&FindingLifecycleRecord> for ReportFinding {
    type Error = KnowledgeError;

    fn try_from(record: &FindingLifecycleRecord) -> Result<Self, Self::Error> {
        if record.state != FindingState::Reportable
            || !record.finding.validated
            || record.evidence_ids.is_empty()
            || !record.cleanup_clear
        {
            return Err(KnowledgeError::FindingNotReportable);
        }
        Ok(Self {
            finding_id: record.finding.finding_id.clone(),
            rule_id: record.finding.rule_id.clone(),
            title: record.finding.title.clone(),
            severity: record.finding.severity,
            confidence: record.finding.confidence,
            origin: record.finding.origin.clone(),
            endpoint_sha256: record.finding.endpoint_sha256.clone(),
            summary: record.finding.summary.clone(),
            evidence_ids: record.evidence_ids.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportDocument {
    pub report_id: String,
    pub program_name: String,
    pub policy_snapshot_sha256: String,
    pub generated_at_epoch_seconds: i64,
    pub findings: Vec<ReportFinding>,
    pub evidence_manifest_sha256: String,
    pub source_audit_tail_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportBundle {
    pub document: ReportDocument,
    pub markdown: String,
    pub json: String,
    pub markdown_sha256: String,
    pub json_sha256: String,
}

#[derive(Debug)]
pub struct ReportBuilder {
    program_name: String,
    policy_snapshot_sha256: String,
    generated_at_epoch_seconds: i64,
    findings: BTreeMap<String, ReportFinding>,
}

impl ReportBuilder {
    pub fn new(
        program_name: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        generated_at_epoch_seconds: i64,
    ) -> Result<Self, KnowledgeError> {
        let program_name = program_name.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "report policy snapshot")?;
        if program_name.is_empty()
            || program_name.len() > 256
            || program_name.bytes().any(|byte| byte == 0)
            || generated_at_epoch_seconds <= 0
        {
            return Err(KnowledgeError::ReportLimit);
        }
        reject_secret_like_text(&program_name)?;
        Ok(Self {
            program_name,
            policy_snapshot_sha256,
            generated_at_epoch_seconds,
            findings: BTreeMap::new(),
        })
    }

    pub fn add_finding(
        &mut self,
        record: &FindingLifecycleRecord,
    ) -> Result<(), KnowledgeError> {
        if self.findings.len() >= MAX_REPORT_FINDINGS {
            return Err(KnowledgeError::ReportLimit);
        }
        if record.finding.policy_snapshot_sha256 != self.policy_snapshot_sha256 {
            return Err(KnowledgeError::InvalidEvidence(
                "finding/report policy mismatch".into(),
            ));
        }
        let finding = ReportFinding::try_from(record)?;
        reject_secret_like_text(&finding.title)?;
        reject_secret_like_text(&finding.summary)?;
        self.findings.insert(finding.finding_id.clone(), finding);
        Ok(())
    }

    pub fn build(
        self,
        evidence_manifest_sha256: impl Into<String>,
        source_audit_tail_hash: impl Into<String>,
    ) -> Result<ReportBundle, KnowledgeError> {
        let evidence_manifest_sha256 = evidence_manifest_sha256.into();
        let source_audit_tail_hash = source_audit_tail_hash.into();
        validate_sha256(&evidence_manifest_sha256, "evidence manifest")?;
        validate_sha256(&source_audit_tail_hash, "source audit tail")?;
        let findings = self.findings.into_values().collect::<Vec<_>>();
        let report_id = format!(
            "report-{}",
            &hash_serializable(&(
                &self.program_name,
                &self.policy_snapshot_sha256,
                self.generated_at_epoch_seconds,
                &findings,
                &evidence_manifest_sha256,
                &source_audit_tail_hash,
            ))?[..24]
        );
        let document = ReportDocument {
            report_id,
            program_name: self.program_name,
            policy_snapshot_sha256: self.policy_snapshot_sha256,
            generated_at_epoch_seconds: self.generated_at_epoch_seconds,
            findings,
            evidence_manifest_sha256,
            source_audit_tail_hash,
        };
        let json = serde_json::to_string_pretty(&document)
            .map_err(|error| KnowledgeError::ReportSerialization(error.to_string()))?;
        let markdown = render_markdown(&document);
        if json.len() > MAX_REPORT_BYTES || markdown.len() > MAX_REPORT_BYTES {
            return Err(KnowledgeError::ReportLimit);
        }
        Ok(ReportBundle {
            markdown_sha256: hash_bytes(markdown.as_bytes()),
            json_sha256: hash_bytes(json.as_bytes()),
            document,
            markdown,
            json,
        })
    }
}

fn render_markdown(document: &ReportDocument) -> String {
    let mut output = String::new();
    output.push_str("# NXBounty validated findings report\n\n");
    output.push_str(&format!("- Report: `{}`\n", document.report_id));
    output.push_str(&format!("- Program: {}\n", markdown_text(&document.program_name)));
    output.push_str(&format!(
        "- Policy snapshot: `{}`\n",
        document.policy_snapshot_sha256
    ));
    output.push_str(&format!(
        "- Evidence manifest: `{}`\n\n",
        document.evidence_manifest_sha256
    ));
    if document.findings.is_empty() {
        output.push_str("No reportable validated findings.\n");
        return output;
    }
    for (index, finding) in document.findings.iter().enumerate() {
        output.push_str(&format!(
            "## {}. {}\n\n",
            index + 1,
            markdown_text(&finding.title)
        ));
        output.push_str(&format!("- Finding: `{}`\n", finding.finding_id));
        output.push_str(&format!("- Rule: `{}`\n", finding.rule_id));
        output.push_str(&format!("- Severity: `{:?}`\n", finding.severity));
        output.push_str(&format!("- Confidence: `{:?}`\n", finding.confidence));
        output.push_str(&format!("- Origin: `{}`\n", finding.origin));
        output.push_str(&format!(
            "- Endpoint SHA-256: `{}`\n",
            finding.endpoint_sha256
        ));
        output.push_str("\n### Summary\n\n");
        output.push_str(&markdown_text(&finding.summary));
        output.push_str("\n\n### Evidence references\n\n");
        for evidence_id in &finding.evidence_ids {
            output.push_str(&format!("- `{evidence_id}`\n"));
        }
        output.push('\n');
    }
    output
}

fn markdown_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportManifestEntry {
    pub logical_path: String,
    pub class: String,
    pub content_sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportManifest {
    pub export_id: String,
    pub policy_snapshot_sha256: String,
    pub entries: BTreeMap<String, ExportManifestEntry>,
    pub root_sha256: String,
}

impl ExportManifest {
    pub fn new(
        export_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
    ) -> Result<Self, KnowledgeError> {
        let export_id = export_id.into();
        validate_identifier(&export_id, "export_id")?;
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "manifest policy snapshot")?;
        let mut manifest = Self {
            export_id,
            policy_snapshot_sha256,
            entries: BTreeMap::new(),
            root_sha256: String::new(),
        };
        manifest.recompute_root()?;
        Ok(manifest)
    }

    pub fn add_entry(
        &mut self,
        logical_path: impl Into<String>,
        class: impl Into<String>,
        content_sha256: impl Into<String>,
        bytes: u64,
    ) -> Result<(), KnowledgeError> {
        if self.entries.len() >= MAX_MANIFEST_ENTRIES {
            return Err(KnowledgeError::InvalidManifest("entry limit".into()));
        }
        let logical_path = logical_path.into();
        let class = class.into();
        let content_sha256 = content_sha256.into();
        if logical_path.is_empty()
            || logical_path.len() > 512
            || logical_path.starts_with('/')
            || logical_path.contains("..")
            || logical_path.contains('\\')
            || class.is_empty()
            || class.len() > 96
        {
            return Err(KnowledgeError::InvalidManifest(
                "logical path or class".into(),
            ));
        }
        validate_sha256(&content_sha256, "manifest content")?;
        if self.entries.contains_key(&logical_path) {
            return Err(KnowledgeError::InvalidManifest(
                "duplicate logical path".into(),
            ));
        }
        self.entries.insert(
            logical_path.clone(),
            ExportManifestEntry {
                logical_path,
                class,
                content_sha256,
                bytes,
            },
        );
        self.recompute_root()?;
        Ok(())
    }

    pub fn verify(&self) -> Result<(), KnowledgeError> {
        let expected = hash_serializable(&(
            &self.export_id,
            &self.policy_snapshot_sha256,
            &self.entries,
        ))?;
        if self.root_sha256 != expected {
            return Err(KnowledgeError::InvalidManifest(
                "root hash mismatch".into(),
            ));
        }
        Ok(())
    }

    fn recompute_root(&mut self) -> Result<(), KnowledgeError> {
        self.root_sha256 = hash_serializable(&(
            &self.export_id,
            &self.policy_snapshot_sha256,
            &self.entries,
        ))?;
        Ok(())
    }
}
