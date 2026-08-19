#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn temporary_root(label: &str) -> PathBuf {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nxb123-{label}-{}-{now}-{sequence}",
            std::process::id()
        ))
    }

    fn config(root: PathBuf) -> ExactDedupConfig {
        ExactDedupConfig {
            root,
            hot_set_max_entries: 128,
            run_max_entries: 128,
            disk_budget_bytes: 32 * 1024 * 1024,
        }
    }

    fn id(index: u64) -> String {
        format!("{index:064x}")
    }

    #[test]
    fn ten_thousand_unique_ids_survive_flush_and_reopen() {
        let root = temporary_root("ten-thousand");
        let index_config = config(root.clone());
        let mut index =
            DiskBackedExactDedupIndex::open(index_config.clone(), "index-main").unwrap();

        for value in 1..=10_000 {
            assert_eq!(
                index.classify_and_insert(&id(value)).unwrap(),
                ExactDedupOutcome::Unique
            );
        }
        let checkpoint = index.finish().unwrap();
        assert_eq!(checkpoint.committed_unique_ids, 10_000);
        assert_eq!(checkpoint.pending_unique_ids, 0);
        assert!(checkpoint.committed_runs > 1);

        let reopened = DiskBackedExactDedupIndex::open(index_config, "index-main").unwrap();
        for value in [1, 2, 127, 128, 129, 5_000, 9_999, 10_000] {
            assert!(reopened.contains(&id(value)).unwrap());
        }
        assert!(!reopened.contains(&id(10_001)).unwrap());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_decision_requires_full_exact_match() {
        let root = temporary_root("exact");
        let mut index = DiskBackedExactDedupIndex::open(config(root.clone()), "index-exact")
            .unwrap();
        let first = format!("{}1", "a".repeat(63));
        let second = format!("{}2", "a".repeat(63));

        assert_eq!(
            index.classify_and_insert(&first).unwrap(),
            ExactDedupOutcome::Unique
        );
        index.flush().unwrap();
        assert_eq!(
            index.classify_and_insert(&second).unwrap(),
            ExactDedupOutcome::Unique
        );
        assert_eq!(
            index.classify_and_insert(&first).unwrap(),
            ExactDedupOutcome::Duplicate
        );
        assert_eq!(index.checkpoint().duplicate_observations, 1);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_is_detected_after_reopen_without_loading_ids_into_hot_set() {
        let root = temporary_root("reopen");
        let index_config = config(root.clone());
        let target = id(42);
        let mut first =
            DiskBackedExactDedupIndex::open(index_config.clone(), "index-reopen").unwrap();
        first.classify_and_insert(&target).unwrap();
        first.finish().unwrap();

        let mut second =
            DiskBackedExactDedupIndex::open(index_config, "index-reopen").unwrap();
        assert_eq!(second.checkpoint().pending_unique_ids, 0);
        assert_eq!(
            second.classify_and_insert(&target).unwrap(),
            ExactDedupOutcome::Duplicate
        );
        assert_eq!(second.checkpoint().committed_unique_ids, 1);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_run_is_rejected() {
        let root = temporary_root("tamper");
        let index_config = config(root.clone());
        let mut index =
            DiskBackedExactDedupIndex::open(index_config.clone(), "index-tamper").unwrap();
        index.classify_and_insert(&id(1)).unwrap();
        index.finish().unwrap();

        let run = root.join("dedup-run-00000000000000000001.idx");
        let mut bytes = fs::read(&run).unwrap();
        bytes[0] = if bytes[0] == b'a' { b'b' } else { b'a' };
        fs::write(&run, bytes).unwrap();

        let error = DiskBackedExactDedupIndex::open(index_config, "index-tamper")
            .err()
            .unwrap();
        assert!(matches!(error, ExactDedupError::RunHash(_)));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disk_backpressure_keeps_the_hot_set_intact() {
        let root = temporary_root("budget");
        let index_config = ExactDedupConfig {
            root: root.clone(),
            hot_set_max_entries: 64,
            run_max_entries: 64,
            disk_budget_bytes: 65 * 64 + 4096,
        };
        let mut index =
            DiskBackedExactDedupIndex::open(index_config, "index-budget").unwrap();
        for value in 1..=64 {
            index.classify_and_insert(&id(value)).unwrap();
        }
        let result = index.flush();
        assert!(matches!(result, Err(ExactDedupError::DiskBudget)));
        assert_eq!(index.checkpoint().pending_unique_ids, 64);
        assert_eq!(index.checkpoint().committed_unique_ids, 0);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn orphan_run_and_noncanonical_identifier_are_fail_closed() {
        let root = temporary_root("orphan");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("dedup-manifest.jsonl"), b"").unwrap();
        fs::write(root.join("dedup-run-00000000000000000001.idx.tmp"), b"x").unwrap();
        let error = DiskBackedExactDedupIndex::open(config(root.clone()), "index-orphan")
            .err()
            .unwrap();
        assert!(matches!(error, ExactDedupError::OrphanRun(_)));
        fs::remove_dir_all(&root).unwrap();

        let root = temporary_root("uppercase");
        let mut index =
            DiskBackedExactDedupIndex::open(config(root.clone()), "index-uppercase").unwrap();
        assert!(matches!(
            index.classify_and_insert(&"A".repeat(64)),
            Err(ExactDedupError::InvalidFindingId)
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
