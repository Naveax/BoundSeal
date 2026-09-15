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

fn required_offset(source: &str, marker: &str) -> usize {
    source
        .find(marker)
        .unwrap_or_else(|| panic!("{BROKER_PATH}: missing source marker: {marker}"))
}

#[test]
fn creator_handles_suppress_their_own_delayed_file_time_notifications() {
    let text = source();

    for marker in [
        "self.SetFileTime = self.kernel32.SetFileTime",
        "self.SetFileTime.argtypes = [",
        "def suppress_automatic_file_times(self, handle: int) -> None:",
        "preserve = FILETIME(0xFFFFFFFF, 0xFFFFFFFF)",
        "if not self.SetFileTime(",
        "self.winerror(\"SetFileTime suppress automatic file times\")",
        "if not directory:\n            self.suppress_automatic_file_times(handle)",
    ] {
        assert!(
            text.contains(marker),
            "{BROKER_PATH}: creator-handle time suppression marker is missing: {marker}"
        );
    }

    let create = required_offset(&text, "def create_relative(");
    let suppress = required_offset(
        &text[create..],
        "self.suppress_automatic_file_times(handle)",
    ) + create;
    let returned = required_offset(&text[suppress..], "return handle") + suppress;
    assert!(
        create < suppress && suppress < returned,
        "{BROKER_PATH}: automatic file-time suppression must occur before a newly created file handle escapes create_relative"
    );
}

#[test]
fn transitioned_read_guards_withhold_write_and_delete_sharing() {
    let text = source();
    let start = required_offset(&text, "def open_guard_file(self, path: str) -> int:");
    let end = required_offset(&text[start..], "\n    def create_relative(") + start;
    let body = &text[start..end];

    assert!(
        body.contains("FILE_SHARE_READ,\n            None,"),
        "{BROKER_PATH}: final read guard must share reads only"
    );
    assert!(
        !body.contains("FILE_SHARE_READ | FILE_SHARE_WRITE"),
        "{BROKER_PATH}: final read guard must not admit external write sharing"
    );
}

#[test]
fn synchronous_change_sentinel_closes_the_watcher_thread_startup_gap() {
    let text = source();
    for marker in [
        "self.FindFirstChangeNotificationW = self.kernel32.FindFirstChangeNotificationW",
        "self.FindCloseChangeNotification = self.kernel32.FindCloseChangeNotification",
        "self.WaitForSingleObject = self.kernel32.WaitForSingleObject",
        "def begin_change_notification(self, path: str, notify_filter: int) -> int:",
        "def change_notification_signaled(self, handle: int) -> bool:",
        "self.change_notification_handle = self.native.begin_change_notification(",
        "str(self.destination), WATCH_FILTER",
        "self._refresh_change_notification_violation()",
        "snapshot subtree change notification signaled after broker freeze",
    ] {
        assert!(
            text.contains(marker),
            "{BROKER_PATH}: synchronous watcher sentinel marker is missing: {marker}"
        );
    }

    let arm_start = required_offset(&text, "def _arm_watcher(self) -> None:");
    let arm_end = required_offset(
        &text[arm_start..],
        "\n    def _transition_writers_to_read_guards",
    ) + arm_start;
    let arm_body = &text[arm_start..arm_end];
    let sentinel = required_offset(arm_body, "self.native.begin_change_notification(");
    let directory_watch = required_offset(
        arm_body,
        "self.native.open_directory(str(self.destination), watch=True)",
    );
    let thread_start = required_offset(arm_body, "self.watcher_thread.start()");
    assert!(
        sentinel < directory_watch && directory_watch < thread_start,
        "{BROKER_PATH}: synchronous full-change sentinel must arm before the asynchronous ReadDirectoryChangesW watcher starts"
    );
}

#[test]
fn writer_transition_uses_namespace_sentinel_and_exact_byte_guards_before_full_watch() {
    let text = source();

    for marker in [
        "NAMESPACE_FILTER = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME",
        "self.transition_notification_handle = self.native.begin_change_notification(",
        "str(self.destination), NAMESPACE_FILTER",
        "expected_sha256 = self.native.copy_file(",
        "actual_sha256 = self.native.sha256_file(guard, expected_identity[2])",
        "if actual_sha256 != expected_sha256:",
        "self._verify_destination_namespace()",
        "self._retire_transition_sentinel()",
    ] {
        assert!(
            text.contains(marker),
            "{BROKER_PATH}: settled writer-transition authority marker is missing: {marker}"
        );
    }

    let transition_start = required_offset(
        &text,
        "def _transition_writers_to_read_guards(self) -> None:",
    );
    let transition_end = required_offset(
        &text[transition_start..],
        "\n    def _verify_destination_namespace",
    ) + transition_start;
    let body = &text[transition_start..transition_end];
    for marker in [
        "self.native.close(writer)",
        "guard = self.native.open_guard_file(str(path))",
        "self.file_handles.append(guard)",
        "if actual_identity != expected_identity:",
        "actual_sha256 = self.native.sha256_file(guard, expected_identity[2])",
        "self._refresh_transition_notification_violation()",
        "if self.violated.is_set():",
    ] {
        assert!(
            body.contains(marker),
            "{BROKER_PATH}: fail-closed writer-to-guard transition marker is missing: {marker}"
        );
    }

    let copy = required_offset(&text, "def copy_and_freeze(self) -> None:");
    let copy_body = &text[copy..];
    let namespace_arm = required_offset(copy_body, "self._arm_transition_sentinel()");
    let transition = required_offset(copy_body, "self._transition_writers_to_read_guards()");
    let full_watch = required_offset(copy_body, "self._arm_watcher()");
    let verify_namespace = required_offset(copy_body, "self._verify_destination_namespace()");
    let retire_transition = required_offset(copy_body, "self._retire_transition_sentinel()");
    assert!(
        namespace_arm < transition
            && transition < full_watch
            && full_watch < verify_namespace
            && verify_namespace < retire_transition,
        "{BROKER_PATH}: namespace-only sentinel must cover writer close/reopen, then full watch must cover final namespace verification before transition sentinel retirement"
    );
}

#[test]
fn self_test_proves_read_guard_rejects_post_freeze_file_writes() {
    let text = source();
    for marker in [
        "write_succeeded = False",
        "with copied.open(\"r+b\") as stream:",
        "fail(\"self-test retained destination read guard allowed write\")",
    ] {
        assert!(
            text.contains(marker),
            "{BROKER_PATH}: post-freeze write-sharing self-test marker is missing: {marker}"
        );
    }
}
