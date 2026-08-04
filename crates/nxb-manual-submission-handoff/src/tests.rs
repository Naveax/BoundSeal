#[cfg(test)]
mod tests {
    use super::*;

    fn sha(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn report_document(finding_ids: &[&str]) -> ReportDocument {
        let findings = finding_ids
            .iter()
            .enumerate()
            .map(|(index, finding_id)| {
                serde_json::json!({
                    "finding_id": finding_id,
                    "rule_id": format!("rule-{index:03}"),
                    "title": format!("Validated finding {index}"),
                    "severity": "medium",
                    "confidence": "high",
                    "origin": "https://example.com",
                    "endpoint_sha256": sha(char::from(b'a' + index as u8)),
                    "summary": format!("Safely redacted finding summary {index}"),
                    "evidence_ids": [format!("evidence-{index:03}")]
                })
            })
            .collect::<Vec<_>>();
        serde_json::from_value(serde_json::json!({
            "report_id": "report-handoff-test",
            "program_name": "Example Program",
            "policy_snapshot_sha256": sha('b'),
            "generated_at_epoch_seconds": 1_200,
            "findings": findings,
            "evidence_manifest_sha256": sha('c'),
            "source_audit_tail_hash": sha('d')
        }))
        .expect("report fixture")
    }

    fn report_bundle(document: ReportDocument) -> ReportBundle {
        let json = serde_json::to_string_pretty(&document).expect("canonical report JSON");
        let markdown = "# Safely redacted report\n".to_string();
        ReportBundle {
            document,
            markdown_sha256: hash_bytes(markdown.as_bytes()),
            json_sha256: hash_bytes(json.as_bytes()),
            markdown,
            json,
        }
    }

    #[test]
    fn canonical_report_bundle_is_accepted() {
        verify_report_bundle(&report_bundle(report_document(&["finding-001"])))
            .expect("canonical report");
    }

    #[test]
    fn report_json_must_use_canonical_pretty_encoding() {
        let document = report_document(&["finding-001"]);
        let mut bundle = report_bundle(document.clone());
        bundle.json = serde_json::to_string(&document).expect("compact JSON");
        bundle.json_sha256 = hash_bytes(bundle.json.as_bytes());
        assert!(matches!(
            verify_report_bundle(&bundle),
            Err(ManualHandoffError::ReportDigestMismatch)
        ));
    }

    #[test]
    fn empty_report_is_not_submission_ready() {
        let bundle = report_bundle(report_document(&[]));
        assert!(matches!(
            verify_report_bundle(&bundle),
            Err(ManualHandoffError::InvalidReportDocument)
        ));
    }

    #[test]
    fn finding_order_and_identity_are_canonical() {
        let reversed = report_bundle(report_document(&["finding-002", "finding-001"]));
        assert!(matches!(
            verify_report_bundle(&reversed),
            Err(ManualHandoffError::NonCanonicalFindingOrder)
        ));

        let duplicate = report_bundle(report_document(&["finding-001", "finding-001"]));
        assert!(matches!(
            verify_report_bundle(&duplicate),
            Err(ManualHandoffError::NonCanonicalFindingOrder)
        ));
    }

    #[test]
    fn credential_like_handoff_metadata_is_rejected() {
        for unsafe_value in [
            "client_secret=hidden",
            "access_token=hidden",
            "refresh_token=hidden",
            "api_key=hidden",
            "authorization: bearer hidden",
            "https://example.com/private",
        ] {
            let metadata = BTreeMap::from([("review_context".into(), unsafe_value.into())]);
            assert!(matches!(
                validate_metadata(&metadata),
                Err(ManualHandoffError::UnsafeMetadata)
            ));
        }
    }

    #[test]
    fn credential_like_report_text_is_rejected() {
        let mut document = report_document(&["finding-001"]);
        document.findings[0].summary = "access_token=hidden".into();
        let bundle = report_bundle(document);
        assert!(matches!(
            verify_report_bundle(&bundle),
            Err(ManualHandoffError::InvalidReportDocument)
        ));
    }

    #[test]
    fn program_handle_remains_identifier_only() {
        validate_program_handle("example-program_01.test").expect("safe program handle");
        for invalid in ["", "example/program", "https://example.com", "program name"] {
            assert!(matches!(
                validate_program_handle(invalid),
                Err(ManualHandoffError::InvalidProgramHandle)
            ));
        }
    }

    #[test]
    fn signature_hex_is_lowercase_and_even_length() {
        assert_eq!(decode_hex("00ff").expect("lowercase hex"), vec![0, 255]);
        for invalid in ["", "0", "00FF", "zz"] {
            assert!(matches!(
                decode_hex(invalid),
                Err(ManualHandoffError::InvalidSignature)
            ));
        }
    }

    #[test]
    fn finding_set_digest_binds_evidence_membership() {
        let original = report_document(&["finding-001"]);
        let mut changed = original.clone();
        changed.findings[0]
            .evidence_ids
            .insert("evidence-additional".into());
        assert_ne!(
            calculate_finding_set_sha256(&original).expect("original digest"),
            calculate_finding_set_sha256(&changed).expect("changed digest")
        );
    }
}
