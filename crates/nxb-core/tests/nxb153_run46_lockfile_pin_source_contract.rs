use std::{
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

const ACTIVE_NXB153_LOCK_PINS: &[&str] = &[
    "scripts/review-nxb-153-evidence-linux-inner.sh",
    "scripts/review-nxb-153-evidence-linux-secure.py",
    "scripts/review-nxb-153-evidence-linux.py",
    "scripts/review-nxb-153-evidence-windows-inner.ps1",
    "scripts/review-nxb-153-evidence.ps1",
    "scripts/validate-nxb-153-linux-inner.sh",
    "scripts/validate-nxb-153-windows-inner.ps1",
    "docs/NXB-153-IMMUTABLE-SOURCE-AUTHORITY.md",
];

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn active_nxb153_integrity_pins_match_the_exact_cargo_lock_bytes() {
    let root = repository_root();
    let lock = fs::read(root.join("Cargo.lock")).expect("read repository Cargo.lock");
    let expected = format!("{:x}", Sha256::digest(&lock));

    for relative in ACTIVE_NXB153_LOCK_PINS {
        let path = root.join(relative);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()));
        assert!(
            source.contains(&expected),
            "{} must pin the current Cargo.lock SHA-256 {expected}",
            path.display(),
        );
    }
}
