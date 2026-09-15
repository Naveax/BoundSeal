use std::{
    fs,
    path::{Path, PathBuf},
};

const BROKER_PATH: &str = "scripts/nxb-153-windows-h2-destination-broker.py";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source() -> String {
    let path = repository_root().join(BROKER_PATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source
        .find(start)
        .unwrap_or_else(|| panic!("{BROKER_PATH}: missing section start: {start}"));
    let tail = &source[start..];
    let end = tail
        .find(end)
        .unwrap_or_else(|| panic!("{BROKER_PATH}: missing section end: {end}"));
    &tail[..end]
}

#[test]
fn broker_cleanup_attempts_every_retained_authority_before_failing() {
    let text = source();
    let close = section(
        &text,
        "    def close(self) -> None:",
        "\n\ndef read_command()",
    );

    for marker in [
        "errors: list[str] = []",
        "self.stopping.set()",
        "watcher cancellation failed:",
        "watcher handle close failed:",
        "watcher thread did not stop within cleanup timeout",
        "change notification close failed:",
        "transition notification close failed:",
        "writer handle close failed:",
        "file handle close failed:",
        "directory handle close failed:",
        "validation handle close failed:",
        "fail(\"broker cleanup failed: \" + \" | \".join(errors))",
    ] {
        assert!(
            close.contains(marker),
            "{BROKER_PATH}: cleanup arbitration marker is missing: {marker}"
        );
    }

    let errors = close
        .find("errors: list[str] = []")
        .expect("cleanup error collector must exist");
    let watcher = close
        .find("if self.watcher_handle is not None:")
        .expect("watcher cleanup must exist");
    let writers = close
        .find("for handle, _, _, _ in reversed(self.writer_records):")
        .expect("writer cleanup must exist");
    let final_arbitration = close
        .rfind("if errors:")
        .expect("cleanup final arbitration must exist");
    assert!(
        errors < watcher && watcher < writers && writers < final_arbitration,
        "{BROKER_PATH}: one shared cleanup error collector must cover watcher and retained object cleanup"
    );
}

#[test]
fn broker_cleanup_does_not_swallow_watcher_or_sentinel_close_failures() {
    let text = source();
    let close = section(
        &text,
        "    def close(self) -> None:",
        "\n\ndef read_command()",
    );

    for forbidden in [
        "except OSError:\n                pass",
        "self.watcher_thread.join(timeout=5)\n            self.watcher_thread = None",
    ] {
        assert!(
            !close.contains(forbidden),
            "{BROKER_PATH}: broker cleanup still swallows authority-release failure: {forbidden}"
        );
    }

    for marker in [
        "self.native.cancel_io(self.watcher_handle)",
        "self.watcher_thread.join(timeout=5)",
        "if self.watcher_thread.is_alive():",
        "self.native.close_change_notification(self.change_notification_handle)",
        "self.native.close_change_notification(self.transition_notification_handle)",
    ] {
        assert!(
            close.contains(marker),
            "{BROKER_PATH}: fail-closed watcher cleanup marker is missing: {marker}"
        );
    }
}

#[test]
fn cancel_io_only_tolerates_the_documented_no_pending_request_case() {
    let text = source();
    let cancel = section(
        &text,
        "    def cancel_io(self, handle: int) -> None:",
        "\n    def information(",
    );

    for marker in [
        "if self.CancelIoEx(wintypes.HANDLE(handle), None):",
        "error = ctypes.get_last_error()",
        "if error != ERROR_NOT_FOUND:",
        "raise OSError(error, \"CancelIoEx failed\", None, error)",
    ] {
        assert!(
            cancel.contains(marker),
            "{BROKER_PATH}: CancelIoEx cleanup contract marker is missing: {marker}"
        );
    }
}
