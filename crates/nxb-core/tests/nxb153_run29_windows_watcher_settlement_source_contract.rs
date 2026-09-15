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

fn required_offset(source: &str, marker: &str) -> usize {
    source
        .find(marker)
        .unwrap_or_else(|| panic!("{BROKER_PATH}: missing source marker: {marker}"))
}

#[test]
fn full_watcher_requires_a_bounded_clean_settlement_generation() {
    let text = source();
    for marker in [
        "WATCH_SETTLEMENT_TIMEOUT_MS = 250",
        "MAX_WATCH_SETTLEMENT_GENERATIONS = 8",
        "def change_notification_signaled(self, handle: int, timeout_ms: int = 0) -> bool:",
        "self.WaitForSingleObject(wintypes.HANDLE(handle), timeout_ms)",
        "self.guard_records: list[tuple[Path, tuple[int, int, int, int], str]] = []",
        "def _verify_guard_records(self) -> None:",
        "def _stabilize_change_notification(self) -> None:",
        "for _generation in range(1, MAX_WATCH_SETTLEMENT_GENERATIONS + 1):",
        "WATCH_SETTLEMENT_TIMEOUT_MS",
        "full snapshot change watcher did not reach a clean bounded settlement generation",
    ] {
        assert!(
            text.contains(marker),
            "{BROKER_PATH}: bounded full-watcher settlement marker is missing: {marker}"
        );
    }
}

#[test]
fn a_signaled_settlement_generation_is_revalidated_before_it_is_discarded() {
    let text = source();
    let settle = section(
        &text,
        "    def _stabilize_change_notification(self) -> None:",
        "\n    def _arm_watcher(",
    );

    for marker in [
        "self._verify_guard_records()",
        "self._verify_destination_namespace()",
        "self._refresh_transition_notification_violation()",
        "signaled = self.native.change_notification_signaled(",
        "WATCH_SETTLEMENT_TIMEOUT_MS",
        "self.native.close_change_notification(handle)",
        "self.change_notification_handle = None",
    ] {
        assert!(
            settle.contains(marker),
            "{BROKER_PATH}: settlement revalidation marker is missing: {marker}"
        );
    }

    assert!(
        !settle.contains("time.sleep("),
        "{BROKER_PATH}: full-watcher settlement must not use an unguarded sleep"
    );

    let wait = required_offset(settle, "signaled = self.native.change_notification_signaled(");
    let post_wait_guards = required_offset(&settle[wait..], "self._verify_guard_records()") + wait;
    let post_wait_namespace =
        required_offset(&settle[post_wait_guards..], "self._verify_destination_namespace()")
            + post_wait_guards;
    let close = required_offset(
        &settle[post_wait_namespace..],
        "self.native.close_change_notification(handle)",
    ) + post_wait_namespace;
    assert!(
        wait < post_wait_guards && post_wait_guards < post_wait_namespace && post_wait_namespace < close,
        "{BROKER_PATH}: a signaled generation must prove exact file and namespace state before its notification handle is discarded"
    );
}

#[test]
fn persistent_watcher_reuses_the_clean_full_sentinel_and_overlaps_transition_authority() {
    let text = source();
    let arm = section(
        &text,
        "    def _arm_watcher(self) -> None:",
        "\n    def _transition_writers_to_read_guards",
    );
    assert!(
        arm.contains("if self.change_notification_handle is None:"),
        "{BROKER_PATH}: persistent watcher must reuse an already clean full-change sentinel"
    );

    let copy = section(
        &text,
        "    def copy_and_freeze(self) -> None:",
        "\n    def health_record(",
    );
    let transition_arm = required_offset(copy, "self._arm_transition_sentinel()");
    let transition = required_offset(copy, "self._transition_writers_to_read_guards()");
    let settle = required_offset(copy, "self._stabilize_change_notification()");
    let full_watch = required_offset(copy, "self._arm_watcher()");
    let guard_verify = required_offset(&copy[full_watch..], "self._verify_guard_records()") + full_watch;
    let namespace_verify =
        required_offset(&copy[guard_verify..], "self._verify_destination_namespace()") + guard_verify;
    let retire = required_offset(copy, "self._retire_transition_sentinel()");
    assert!(
        transition_arm < transition
            && transition < settle
            && settle < full_watch
            && full_watch < guard_verify
            && guard_verify < namespace_verify
            && namespace_verify < retire,
        "{BROKER_PATH}: transition authority must overlap clean full-watcher establishment and exact-state revalidation before retirement"
    );
}
