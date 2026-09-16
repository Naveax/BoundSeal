use std::{fs, path::PathBuf};

const REGISTRY_SOURCE_PATH: &str = "scripts/nxb-153-registry-source.py";

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source() -> String {
    let path = repository_root().join(REGISTRY_SOURCE_PATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

#[test]
fn registry_reads_compare_path_and_handle_metadata_with_matching_apis() {
    let source = source();

    for marker in [
        "def metadata_changed(before: os.stat_result, after: os.stat_result) -> bool:",
        "path_before = path.lstat()",
        "handle_before = os.fstat(handle.fileno())",
        "handle_after = os.fstat(handle.fileno())",
        "path_after = path.lstat()",
        "metadata_changed(handle_before, handle_after)",
        "metadata_changed(path_before, path_after)",
    ] {
        assert!(
            source.contains(marker),
            "{REGISTRY_SOURCE_PATH}: missing same-API stability marker: {marker}"
        );
    }

    for marker in [
        "handle_before = os.fstat(handle.fileno())",
        "handle_after = os.fstat(handle.fileno())",
        "path_after = path.lstat()",
        "metadata_changed(handle_before, handle_after)",
        "metadata_changed(path_before, path_after)",
    ] {
        assert!(
            source.matches(marker).count() >= 2,
            "{REGISTRY_SOURCE_PATH}: read and hash paths must both retain marker: {marker}"
        );
    }

    for forbidden in [
        "\n        before = path.lstat()",
        "\n            after = os.fstat(handle.fileno())",
        "len(value) != before.st_size",
        "total != before.st_size",
    ] {
        assert!(
            !source.contains(forbidden),
            "{REGISTRY_SOURCE_PATH}: stale cross-API metadata comparison returned: {forbidden}"
        );
    }
}
