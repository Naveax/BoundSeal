pub struct AppendOnlyEncryptedFindingSink<S: SegmentSealer> {
    config: FindingStoreConfig,
    store_id: String,
    sealer: S,
    buffer: SensitiveBytes,
    buffered_findings: usize,
    manifest: Vec<SegmentManifestRecord>,
    manifest_tail: String,
    committed_findings: u64,
    committed_plaintext_bytes: u64,
    committed_sealed_bytes: u64,
    disk_bytes: u64,
}

impl<S: SegmentSealer> AppendOnlyEncryptedFindingSink<S> {
    pub fn open(
        config: FindingStoreConfig,
        store_id: impl Into<String>,
        sealer: S,
    ) -> Result<Self, FindingStoreError> {
        config.validate()?;
        let store_id = store_id.into();
        validate_identifier(&store_id, "store_id")?;
        validate_sealer(&sealer)?;

        fs::create_dir_all(&config.root).map_err(io_error)?;
        let manifest_path = config.root.join("manifest.jsonl");
        if !manifest_path.exists() {
            File::create(&manifest_path)
                .map_err(io_error)?
                .sync_all()
                .map_err(io_error)?;
        }

        let manifest = load_and_verify_manifest(&config.root, &manifest_path, &store_id)?;
        reject_orphan_segments(&config.root, &manifest)?;
        let manifest_tail = manifest
            .last()
            .map(|record| record.record_hash.clone())
            .unwrap_or_else(|| hash_bytes(format!("nxb-finding-store:{store_id}").as_bytes()));
        let committed_findings = manifest
            .iter()
            .fold(0_u64, |sum, record| sum.saturating_add(record.finding_count));
        let committed_plaintext_bytes = manifest.iter().fold(0_u64, |sum, record| {
            sum.saturating_add(record.plaintext_bytes)
        });
        let committed_sealed_bytes = manifest
            .iter()
            .fold(0_u64, |sum, record| sum.saturating_add(record.sealed_bytes));
        let disk_bytes = directory_accounted_bytes(&config.root)?;

        if disk_bytes > config.disk_budget_bytes {
            return Err(FindingStoreError::DiskBudget);
        }

        Ok(Self {
            config,
            store_id,
            sealer,
            buffer: SensitiveBytes::empty(),
            buffered_findings: 0,
            manifest,
            manifest_tail,
            committed_findings,
            committed_plaintext_bytes,
            committed_sealed_bytes,
            disk_bytes,
        })
    }

    pub fn append(&mut self, finding: &Finding) -> Result<(), FindingStoreError> {
        validate_finding(finding)?;
        let mut encoded = serde_json::to_vec(finding).map_err(serialization_error)?;
        encoded.push(b'\n');

        if encoded.len() > self.config.segment_max_plaintext_bytes {
            return Err(FindingStoreError::FindingTooLarge);
        }

        let would_overflow_count = self.buffered_findings >= self.config.segment_max_findings;
        let would_overflow_bytes = self.buffer.len().saturating_add(encoded.len())
            > self.config.segment_max_plaintext_bytes;

        if self.buffered_findings > 0 && (would_overflow_count || would_overflow_bytes) {
            self.flush()?;
        }

        self.buffer.extend_from_slice(&encoded);
        self.buffered_findings = self.buffered_findings.saturating_add(1);
        encoded.fill(0);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<Option<SegmentManifestRecord>, FindingStoreError> {
        if self.buffered_findings == 0 {
            return Ok(None);
        }

        let sequence = self.manifest.len() as u64 + 1;
        let conservative_required = (self.buffer.len() as u64)
            .saturating_add(self.sealer.maximum_overhead_bytes())
            .saturating_mul(2)
            .saturating_add(8192);
        if self.disk_bytes.saturating_add(conservative_required)
            > self.config.disk_budget_bytes
        {
            return Err(FindingStoreError::DiskBudget);
        }

        let plaintext = self.buffer.duplicate();
        let plaintext_bytes = plaintext.len() as u64;
        let plaintext_sha256 = hash_bytes(plaintext.as_slice());
        let context = SegmentSealContext {
            store_id: self.store_id.clone(),
            sequence,
            previous_manifest_hash: self.manifest_tail.clone(),
            plaintext_sha256: plaintext_sha256.clone(),
            finding_count: self.buffered_findings as u64,
            plaintext_bytes,
        };
        let payload = self.sealer.seal(&context, plaintext)?;
        validate_payload(&payload, &self.sealer)?;

        let ciphertext_sha256 = hash_bytes(&payload.ciphertext);
        let segment_file = SegmentFile {
            version: STORE_FORMAT_VERSION,
            sequence,
            algorithm: payload.algorithm.clone(),
            key_id_sha256: payload.key_id_sha256.clone(),
            nonce_hex: lower_hex(&payload.nonce),
            ciphertext_hex: lower_hex(&payload.ciphertext),
            authentication_tag_hex: lower_hex(&payload.authentication_tag),
            plaintext_sha256: plaintext_sha256.clone(),
            finding_count: self.buffered_findings as u64,
            plaintext_bytes,
        };
        let file_bytes = serde_json::to_vec(&segment_file).map_err(serialization_error)?;
        let file_name = format!("segment-{sequence:020}.nxb");
        let file_sha256 = hash_bytes(&file_bytes);

        let mut record = SegmentManifestRecord {
            sequence,
            previous_hash: self.manifest_tail.clone(),
            file_name: file_name.clone(),
            file_sha256,
            ciphertext_sha256,
            plaintext_sha256,
            algorithm: payload.algorithm,
            key_id_sha256: payload.key_id_sha256,
            finding_count: self.buffered_findings as u64,
            plaintext_bytes,
            sealed_bytes: file_bytes.len() as u64,
            record_hash: String::new(),
        };
        record.record_hash = manifest_record_hash(&record)?;
        let mut manifest_line = serde_json::to_vec(&record).map_err(serialization_error)?;
        manifest_line.push(b'\n');

        let required = (file_bytes.len() as u64).saturating_add(manifest_line.len() as u64);
        if self.disk_bytes.saturating_add(required) > self.config.disk_budget_bytes {
            return Err(FindingStoreError::DiskBudget);
        }

        atomic_write_segment(&self.config.root, &file_name, &file_bytes)?;
        append_manifest_line(&self.config.root.join("manifest.jsonl"), &manifest_line)?;

        self.disk_bytes = self.disk_bytes.saturating_add(required);
        self.committed_findings = self
            .committed_findings
            .saturating_add(record.finding_count);
        self.committed_plaintext_bytes = self
            .committed_plaintext_bytes
            .saturating_add(record.plaintext_bytes);
        self.committed_sealed_bytes = self
            .committed_sealed_bytes
            .saturating_add(record.sealed_bytes);
        self.manifest_tail = record.record_hash.clone();
        self.manifest.push(record.clone());
        self.buffer.clear();
        self.buffered_findings = 0;

        Ok(Some(record))
    }

    pub fn pending_findings(&self) -> u64 {
        self.buffered_findings as u64
    }

    pub fn finish(mut self) -> Result<FindingStoreCheckpoint, FindingStoreError> {
        self.flush()?;
        self.verify()?;
        Ok(self.checkpoint())
    }

    pub fn checkpoint(&self) -> FindingStoreCheckpoint {
        FindingStoreCheckpoint {
            store_id: self.store_id.clone(),
            committed_segments: self.manifest.len() as u64,
            committed_findings: self.committed_findings,
            committed_plaintext_bytes: self.committed_plaintext_bytes,
            committed_sealed_bytes: self.committed_sealed_bytes,
            disk_bytes: self.disk_bytes,
            manifest_tail_sha256: self.manifest_tail.clone(),
        }
    }

    pub fn verify(&self) -> Result<(), FindingStoreError> {
        let manifest_path = self.config.root.join("manifest.jsonl");
        let verified =
            load_and_verify_manifest(&self.config.root, &manifest_path, &self.store_id)?;
        if verified != self.manifest {
            return Err(FindingStoreError::ManifestChain { record_index: 0 });
        }
        reject_orphan_segments(&self.config.root, &verified)
    }
}
