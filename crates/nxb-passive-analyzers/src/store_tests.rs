#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct FixtureSealer {
        key: Vec<u8>,
        key_id: String,
    }

    impl FixtureSealer {
        fn new() -> Self {
            let key = b"fixture-only-nxb122-key-material".to_vec();
            let key_id = hash_bytes(&key);
            Self { key, key_id }
        }
    }

    impl SegmentSealer for FixtureSealer {
        fn algorithm_id(&self) -> &str {
            "fixture-xor-sha256-authenticated"
        }

        fn key_id_sha256(&self) -> &str {
            &self.key_id
        }

        fn maximum_overhead_bytes(&self) -> u64 {
            64
        }

        fn seal(
            &mut self,
            context: &SegmentSealContext,
            plaintext: SensitiveBytes,
        ) -> Result<SealedPayload, FindingStoreError> {
            let context_bytes = serde_json::to_vec(context).map_err(serialization_error)?;
            let nonce_digest = Sha256::digest(
                [self.key.as_slice(), context_bytes.as_slice(), b"nonce"].concat(),
            );
            let nonce = nonce_digest[..12].to_vec();
            let mut ciphertext = Vec::with_capacity(plaintext.len());
            let mut counter = 0_u64;
            while ciphertext.len() < plaintext.len() {
                let block = Sha256::digest(
                    [
                        self.key.as_slice(),
                        nonce.as_slice(),
                        &counter.to_be_bytes(),
                    ]
                    .concat(),
                );
                let remaining = plaintext.len() - ciphertext.len();
                let take = remaining.min(block.len());
                let offset = ciphertext.len();
                for index in 0..take {
                    ciphertext.push(plaintext.as_slice()[offset + index] ^ block[index]);
                }
                counter = counter.saturating_add(1);
            }
            let tag_digest = Sha256::digest(
                [
                    self.key.as_slice(),
                    context_bytes.as_slice(),
                    nonce.as_slice(),
                    ciphertext.as_slice(),
                    b"tag",
                ]
                .concat(),
            );
            Ok(SealedPayload {
                algorithm: self.algorithm_id().into(),
                key_id_sha256: self.key_id.clone(),
                nonce,
                ciphertext,
                authentication_tag: tag_digest[..16].to_vec(),
            })
        }
    }

    fn temporary_root(label: &str) -> PathBuf {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nxb122-{label}-{}-{now}-{sequence}",
            std::process::id()
        ))
    }

    fn config(root: PathBuf) -> FindingStoreConfig {
        FindingStoreConfig {
            root,
            segment_max_findings: 64,
            segment_max_plaintext_bytes: 64 * 1024,
            disk_budget_bytes: 32 * 1024 * 1024,
        }
    }

    fn finding(index: u64) -> Finding {
        Finding {
            finding_id: format!("{index:064x}"),
            rule_id: format!("NXB-FIXTURE-{index:06}"),
            title: "Synthetic encrypted-store finding".into(),
            severity: Severity::Low,
            confidence: Confidence::High,
            origin: "https://fixture.example:443".into(),
            endpoint_sha256: format!("{:064x}", index.saturating_add(10_000)),
            evidence_sha256: format!("{:064x}", index.saturating_add(20_000)),
            summary: "Metadata-only append-only storage fixture.".into(),
            metadata: BTreeMap::from([
                ("fixture".into(), "nxb122".into()),
                ("cookie_name_sha256".into(), "a".repeat(64)),
            ]),
        }
    }

    #[test]
    fn one_thousand_findings_are_segmented_and_never_written_as_plaintext() {
        let root = temporary_root("thousand");
        let mut sink = AppendOnlyEncryptedFindingSink::open(
            config(root.clone()),
            "store-main",
            FixtureSealer::new(),
        )
        .unwrap();

        for index in 1..=1_000 {
            sink.append(&finding(index)).unwrap();
        }
        let checkpoint = sink.finish().unwrap();
        assert_eq!(checkpoint.committed_findings, 1_000);
        assert_eq!(checkpoint.committed_segments, 16);
        assert!(checkpoint.committed_sealed_bytes > 0);

        for entry in fs::read_dir(&root).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".nxb") {
                let bytes = fs::read(entry.path()).unwrap();
                let text = String::from_utf8(bytes).unwrap();
                assert!(!text.contains("Synthetic encrypted-store finding"));
                assert!(!text.contains("Metadata-only append-only storage fixture"));
                assert!(!text.contains("https://fixture.example"));
            }
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn store_reopens_and_extends_the_manifest_chain() {
        let root = temporary_root("reopen");
        let store_config = config(root.clone());
        let mut first = AppendOnlyEncryptedFindingSink::open(
            store_config.clone(),
            "store-reopen",
            FixtureSealer::new(),
        )
        .unwrap();
        first.append(&finding(1)).unwrap();
        let first_checkpoint = first.finish().unwrap();

        let mut second = AppendOnlyEncryptedFindingSink::open(
            store_config,
            "store-reopen",
            FixtureSealer::new(),
        )
        .unwrap();
        assert_eq!(second.checkpoint(), first_checkpoint);
        second.append(&finding(2)).unwrap();
        let second_checkpoint = second.finish().unwrap();
        assert_eq!(second_checkpoint.committed_findings, 2);
        assert_eq!(second_checkpoint.committed_segments, 2);
        assert_ne!(
            second_checkpoint.manifest_tail_sha256,
            first_checkpoint.manifest_tail_sha256
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_segment_is_rejected_on_open() {
        let root = temporary_root("tamper");
        let store_config = config(root.clone());
        let mut sink = AppendOnlyEncryptedFindingSink::open(
            store_config.clone(),
            "store-tamper",
            FixtureSealer::new(),
        )
        .unwrap();
        sink.append(&finding(1)).unwrap();
        sink.finish().unwrap();

        let segment = root.join("segment-00000000000000000001.nxb");
        let mut bytes = fs::read(&segment).unwrap();
        let midpoint = bytes.len() / 2;
        bytes[midpoint] ^= 1;
        fs::write(&segment, bytes).unwrap();

        let error = AppendOnlyEncryptedFindingSink::open(
            store_config,
            "store-tamper",
            FixtureSealer::new(),
        )
        .err()
        .unwrap();
        assert!(matches!(error, FindingStoreError::SegmentFileHash(_)));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disk_budget_applies_backpressure_without_clearing_the_buffer() {
        let root = temporary_root("budget");
        let mut store_config = config(root.clone());
        store_config.segment_max_plaintext_bytes = 1024;
        store_config.disk_budget_bytes = 1024;
        let mut sink = AppendOnlyEncryptedFindingSink::open(
            store_config,
            "store-budget",
            FixtureSealer::new(),
        )
        .unwrap();
        sink.append(&finding(1)).unwrap();
        assert!(matches!(sink.flush(), Err(FindingStoreError::DiskBudget)));
        assert_eq!(sink.pending_findings(), 1);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn secret_bearing_metadata_keys_are_rejected() {
        let root = temporary_root("secret-key");
        let mut sink = AppendOnlyEncryptedFindingSink::open(
            config(root.clone()),
            "store-secret-key",
            FixtureSealer::new(),
        )
        .unwrap();
        let mut item = finding(1);
        item.metadata
            .insert("authorization_value".into(), "redacted?".into());
        assert!(matches!(
            sink.append(&item),
            Err(FindingStoreError::InvalidFinding(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn orphan_segment_or_temporary_file_is_fail_closed() {
        let root = temporary_root("orphan");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("manifest.jsonl"), b"").unwrap();
        fs::write(root.join("segment-00000000000000000001.nxb.tmp"), b"x").unwrap();

        let error = AppendOnlyEncryptedFindingSink::open(
            config(root.clone()),
            "store-orphan",
            FixtureSealer::new(),
        )
        .err()
        .unwrap();
        assert!(matches!(error, FindingStoreError::OrphanSegment(_)));
        fs::remove_dir_all(root).unwrap();
    }
}
