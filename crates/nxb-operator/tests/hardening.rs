use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

#[cfg(windows)]
use std::path::PathBuf;

use nxb_operator::{
    write_report_bundle, CoverageSummary, DiscoveryCandidate, DiscoveryScheduler,
    FindingDisposition, OperatorConfig, OperatorFinding, OperatorReport, ReleaseArtifact,
    ReleaseManifest, ReportBundle, SessionManifest, StopReason,
};
use nxb_passive_analyzers::{Confidence, Severity};
use sha2::{Digest, Sha256};
use url::Url;

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fixture_report(summary: &str) -> Result<OperatorReport, nxb_operator::OperatorError> {
    let finding = OperatorFinding {
        finding_id: "finding-hardening-1".into(),
        rule_id: "fixture_rule".into(),
        title: "Bounded fixture finding".into(),
        severity: Severity::Low,
        confidence: Confidence::High,
        origin: "https://example.com:443".into(),
        endpoint_sha256: "b".repeat(64),
        evidence_sha256: "c".repeat(64),
        summary: summary.into(),
        disposition: FindingDisposition::Candidate,
        affected_endpoints: BTreeSet::from(["b".repeat(64)]),
        reproduction_metadata: BTreeMap::from([("source".into(), "hardening_test".into())]),
    };
    OperatorReport::build(
        "hardening-run-1",
        "Hardening Fixture",
        "a".repeat(64),
        &Url::parse("https://example.com/").unwrap(),
        1_800_000_000,
        vec![finding],
        CoverageSummary {
            discovered_endpoints: 1,
            tested_endpoints: 1,
            requests_issued: 1,
            request_budget: 4,
            depth_reached: 0,
            maximum_depth: 2,
            saturation_reached: false,
        },
        vec!["Authenticated coverage was intentionally omitted.".into()],
        StopReason::Completed,
    )
}

#[test]
fn malformed_operator_and_session_inputs_never_panic() {
    let corpus: &[&[u8]] = &[
        b"",
        b"null",
        b"[]",
        b"{}",
        b"{",
        b"\xff\xfe\xfd",
        br#"{"schema_version":18446744073709551615}"#,
        br#"{"schema_version":1,"passive_only":false,"maximum_depth":65535}"#,
        br#"{"schema_version":1,"references":[{"value":"plaintext-secret"}]}"#,
    ];
    for bytes in corpus {
        let config = std::panic::catch_unwind(|| OperatorConfig::migrate_json(bytes));
        assert!(config.is_ok(), "operator config parser panicked");
        let session = std::panic::catch_unwind(|| SessionManifest::from_json(bytes));
        assert!(session.is_ok(), "session parser panicked");
    }
}

#[test]
fn scheduler_is_deterministic_under_reordered_input() {
    let config = OperatorConfig {
        maximum_depth: 4,
        maximum_endpoints: 16,
        maximum_requests: 16,
        ..OperatorConfig::default()
    };
    let candidates = [
        ("https://example.com/z", 2_u16),
        ("https://example.com/a", 1_u16),
        ("https://example.com/b", 1_u16),
        ("https://example.com/root", 0_u16),
    ];

    let collect = |ordered: Vec<(&str, u16)>| {
        let mut scheduler = DiscoveryScheduler::new(config.clone()).unwrap();
        for (url, depth) in ordered {
            scheduler.enqueue(DiscoveryCandidate {
                canonical_url: url.into(),
                canonical_url_sha256: hash_bytes(url.as_bytes()),
                method: "GET".into(),
                depth,
                source_kind: "hardening_fixture".into(),
            });
        }
        let mut output = Vec::new();
        while let Some(candidate) = scheduler.next_candidate() {
            output.push((candidate.depth, candidate.canonical_url));
        }
        output
    };

    let forward = collect(candidates.to_vec());
    let reverse = collect(candidates.iter().rev().copied().collect());
    assert_eq!(forward, reverse);
    assert_eq!(
        forward,
        vec![
            (0, "https://example.com/root".into()),
            (1, "https://example.com/a".into()),
            (1, "https://example.com/b".into()),
            (2, "https://example.com/z".into()),
        ]
    );
}

#[test]
fn secret_like_report_material_is_rejected_before_export() {
    let error = fixture_report("Authorization: Bearer should-never-be-exported")
        .expect_err("secret-like material must be rejected");
    assert!(error.to_string().contains("secret-like"));
}

#[test]
fn stale_temporary_export_is_recovered_atomically() {
    let root = std::env::temp_dir().join(format!(
        "nxb-operator-recovery-{}-{}",
        std::process::id(),
        1_800_000_000_u64
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let report = fixture_report("No secret material is present in this finding.").unwrap();
    let bundle = ReportBundle::build(report).unwrap();
    let stale = root.join(format!(
        ".report.json.{}.tmp",
        &hash_bytes(bundle.json.as_bytes())[..16]
    ));
    fs::write(&stale, b"partial-crash-output").unwrap();

    let manifest = write_report_bundle(&root, &bundle).unwrap();
    assert!(!stale.exists());
    assert_eq!(
        fs::read_to_string(root.join("report.json")).unwrap(),
        bundle.json
    );
    assert_eq!(
        manifest.entries["report.json"].content_sha256,
        bundle.json_sha256
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unwritable_output_boundary_fails_closed() {
    let root = std::env::temp_dir().join(format!("nxb-operator-unwritable-{}", std::process::id()));
    let _ = fs::remove_file(&root);
    let _ = fs::remove_dir_all(&root);
    fs::write(&root, b"not-a-directory").unwrap();

    let report = fixture_report("No secret material is present in this finding.").unwrap();
    let bundle = ReportBundle::build(report).unwrap();
    assert!(write_report_bundle(&root, &bundle).is_err());
    fs::remove_file(root).unwrap();
}

#[test]
fn release_manifest_is_order_independent_and_path_safe() {
    let sbom = br#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#;
    let first = ReleaseManifest::build(
        vec![
            ReleaseArtifact {
                logical_path: "bin/nxb.exe".into(),
                content_sha256: "b".repeat(64),
                bytes: 20,
            },
            ReleaseArtifact {
                logical_path: "docs/operator.md".into(),
                content_sha256: "a".repeat(64),
                bytes: 10,
            },
        ],
        sbom,
    )
    .unwrap();
    let second = ReleaseManifest::build(
        vec![
            ReleaseArtifact {
                logical_path: "docs/operator.md".into(),
                content_sha256: "a".repeat(64),
                bytes: 10,
            },
            ReleaseArtifact {
                logical_path: "bin/nxb.exe".into(),
                content_sha256: "b".repeat(64),
                bytes: 20,
            },
        ],
        sbom,
    )
    .unwrap();
    assert_eq!(first, second);
    assert!(first.checksum_lines().contains("bin/nxb.exe"));

    let unsafe_path = ReleaseManifest::build(
        vec![ReleaseArtifact {
            logical_path: "../nxb.exe".into(),
            content_sha256: "a".repeat(64),
            bytes: 1,
        }],
        sbom,
    );
    assert!(unsafe_path.is_err());
}

#[cfg(windows)]
#[test]
fn windows_long_path_export_is_bounded_and_complete() {
    let component = "nxb".repeat(30);
    let root: PathBuf = std::env::temp_dir()
        .join("nxb-operator-windows-long-path")
        .join(component);
    let _ = fs::remove_dir_all(&root);
    let report = fixture_report("No secret material is present in this finding.").unwrap();
    let bundle = ReportBundle::build(report).unwrap();
    let result = write_report_bundle(&root, &bundle);
    match result {
        Ok(_) => {
            assert!(root.join("manifest.json").is_file());
            fs::remove_dir_all(root).unwrap();
        }
        Err(error) => {
            assert!(error.to_string().contains("filesystem"));
        }
    }
}
