impl DiskBackedExactDedupIndex {
    pub fn open(
        config: ExactDedupConfig,
        index_id: impl Into<String>,
    ) -> Result<Self, ExactDedupError> {
        config.validate()?;
        let index_id = index_id.into();
        validate_index_identifier(&index_id)?;
        fs::create_dir_all(&config.root).map_err(dedup_io_error)?;

        let manifest_path = config.root.join("dedup-manifest.jsonl");
        if !manifest_path.exists() {
            File::create(&manifest_path)
                .map_err(dedup_io_error)?
                .sync_all()
                .map_err(dedup_io_error)?;
        }

        let runs = load_and_verify_dedup_manifest(&config.root, &manifest_path, &index_id)?;
        reject_orphan_runs(&config.root, &runs)?;
        if runs.len() > MAX_RUNS {
            return Err(ExactDedupError::RunLimit);
        }
        let manifest_tail = runs
            .last()
            .map(|record| record.record_hash.clone())
            .unwrap_or_else(|| dedup_hash(format!("bsl-exact-dedup:{index_id}").as_bytes()));
        let committed_unique_ids = runs.iter().fold(0_u64, |sum, record| {
            sum.saturating_add(record.entry_count)
        });
        let disk_bytes = dedup_directory_bytes(&config.root)?;
        if disk_bytes > config.disk_budget_bytes {
            return Err(ExactDedupError::DiskBudget);
        }

        Ok(Self {
            config,
            index_id,
            hot_set: BTreeSet::new(),
            runs,
            manifest_tail,
            committed_unique_ids,
            duplicate_observations: 0,
            disk_bytes,
        })
    }

    pub fn classify_and_insert(
        &mut self,
        finding_id: &str,
    ) -> Result<ExactDedupOutcome, ExactDedupError> {
        validate_finding_id(finding_id)?;
        if self.contains(finding_id)? {
            self.duplicate_observations = self.duplicate_observations.saturating_add(1);
            return Ok(ExactDedupOutcome::Duplicate);
        }

        if self.hot_set.len() >= self.config.hot_set_max_entries {
            self.flush_one_run()?;
        }
        self.hot_set.insert(finding_id.to_owned());
        Ok(ExactDedupOutcome::Unique)
    }

    pub fn contains(&self, finding_id: &str) -> Result<bool, ExactDedupError> {
        validate_finding_id(finding_id)?;
        if self.hot_set.contains(finding_id) {
            return Ok(true);
        }
        for run in self.runs.iter().rev() {
            if finding_id >= run.first_finding_id.as_str()
                && finding_id <= run.last_finding_id.as_str()
                && run_contains_exact(&self.config.root.join(&run.file_name), run, finding_id)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn flush(&mut self) -> Result<u64, ExactDedupError> {
        let mut committed = 0_u64;
        while !self.hot_set.is_empty() {
            committed = committed.saturating_add(self.flush_one_run()?);
        }
        Ok(committed)
    }

    fn flush_one_run(&mut self) -> Result<u64, ExactDedupError> {
        if self.hot_set.is_empty() {
            return Ok(0);
        }
        if self.runs.len() >= MAX_RUNS {
            return Err(ExactDedupError::RunLimit);
        }

        let ids = self
            .hot_set
            .iter()
            .take(self.config.run_max_entries)
            .cloned()
            .collect::<Vec<_>>();
        let entry_count = ids.len() as u64;
        let run_bytes = encode_fixed_run(&ids)?;
        let sequence = self.runs.len() as u64 + 1;
        let file_name = format!("dedup-run-{sequence:020}.idx");
        let file_sha256 = dedup_hash(&run_bytes);

        let mut record = DedupRunRecord {
            sequence,
            previous_hash: self.manifest_tail.clone(),
            file_name: file_name.clone(),
            file_sha256,
            first_finding_id: ids.first().cloned().ok_or_else(|| {
                ExactDedupError::RunStructure("run unexpectedly empty".into())
            })?,
            last_finding_id: ids.last().cloned().ok_or_else(|| {
                ExactDedupError::RunStructure("run unexpectedly empty".into())
            })?,
            entry_count,
            file_bytes: run_bytes.len() as u64,
            record_hash: String::new(),
        };
        record.record_hash = dedup_manifest_record_hash(&record)?;
        let mut manifest_line =
            serde_json::to_vec(&record).map_err(dedup_serialization_error)?;
        manifest_line.push(b'\n');

        let required = record
            .file_bytes
            .saturating_add(manifest_line.len() as u64)
            .saturating_add(4096);
        if self.disk_bytes.saturating_add(required) > self.config.disk_budget_bytes {
            return Err(ExactDedupError::DiskBudget);
        }

        atomic_write_dedup_run(&self.config.root, &file_name, &run_bytes)?;
        append_dedup_manifest_line(
            &self.config.root.join("dedup-manifest.jsonl"),
            &manifest_line,
        )?;

        for id in &ids {
            self.hot_set.remove(id);
        }
        self.disk_bytes = self
            .disk_bytes
            .saturating_add(record.file_bytes)
            .saturating_add(manifest_line.len() as u64);
        self.committed_unique_ids = self.committed_unique_ids.saturating_add(entry_count);
        self.manifest_tail = record.record_hash.clone();
        self.runs.push(record);
        Ok(entry_count)
    }

    pub fn checkpoint(&self) -> ExactDedupCheckpoint {
        ExactDedupCheckpoint {
            index_id: self.index_id.clone(),
            committed_runs: self.runs.len() as u64,
            committed_unique_ids: self.committed_unique_ids,
            pending_unique_ids: self.hot_set.len() as u64,
            duplicate_observations: self.duplicate_observations,
            disk_bytes: self.disk_bytes,
            manifest_tail_sha256: self.manifest_tail.clone(),
        }
    }

    pub fn finish(mut self) -> Result<ExactDedupCheckpoint, ExactDedupError> {
        self.flush()?;
        self.verify()?;
        Ok(self.checkpoint())
    }

    pub fn verify(&self) -> Result<(), ExactDedupError> {
        let verified = load_and_verify_dedup_manifest(
            &self.config.root,
            &self.config.root.join("dedup-manifest.jsonl"),
            &self.index_id,
        )?;
        if verified != self.runs {
            return Err(ExactDedupError::ManifestChain { record_index: 0 });
        }
        reject_orphan_runs(&self.config.root, &verified)
    }
}
