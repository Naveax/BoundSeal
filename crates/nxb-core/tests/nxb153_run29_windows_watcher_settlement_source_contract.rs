use std::{
    fs,
    path::{Path, PathBuf},
};

const LAUNCHER_PATH: &str = "scripts/nxb-153-windows-h2-destination-broker.py";
const CORE_PATH: &str = "scripts/nxb-153-windows-h2-destination-broker-core.py";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(relative_path: &str) -> String {
    let path = repository_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn section<'a>(source: &'a str, start: &str, end: &str, path: &str) -> &'a str {
    let start = source
        .find(start)
        .unwrap_or_else(|| panic!("{path}: missing section start: {start}"));
    let tail = &source[start..];
    let end = tail
        .find(end)
        .unwrap_or_else(|| panic!("{path}: missing section end: {end}"));
    &tail[..end]
}

fn required_offset(source: &str, marker: &str, path: &str) -> usize {
    source
        .find(marker)
        .unwrap_or_else(|| panic!("{path}: missing source marker: {marker}"))
}

#[test]
fn launcher_pins_and_executes_only_the_verified_immutable_core_bytes() {
    let text = source(LAUNCHER_PATH);
    for marker in [
        "CORE_NAME = \"nxb-153-windows-h2-destination-broker-core.py\"",
        "CORE_GIT_BLOB_SHA1 = \"2cd3f9bd6ee36892a0adeb9cb40d940c8e3a73f6\"",
        "git_object = f\"blob {len(raw)}\\0\".encode(\"ascii\") + raw",
        "digest != CORE_GIT_BLOB_SHA1",
        "module = types.ModuleType(\"nxb153_h2_destination_broker_core\")",
        "code = compile(raw, str(core_path), \"exec\")",
        "exec(code, module.__dict__)",
    ] {
        assert!(
            text.contains(marker),
            "{LAUNCHER_PATH}: immutable core authority marker is missing: {marker}"
        );
    }

    for forbidden in [
        "importlib.util.spec_from_file_location",
        "spec.loader.exec_module(module)",
    ] {
        assert!(
            !text.contains(forbidden),
            "{LAUNCHER_PATH}: verified core bytes must not be discarded before a pathname-based reload: {forbidden}"
        );
    }
}

#[test]
fn full_watcher_requires_a_bounded_clean_settlement_generation() {
    let text = source(LAUNCHER_PATH);
    for marker in [
        "WATCH_SETTLEMENT_TIMEOUT_MS = 250",
        "MAX_WATCH_SETTLEMENT_GENERATIONS = 8",
        "def change_notification_signaled(self, handle: int, timeout_ms: int = 0) -> bool:",
        "self.WaitForSingleObject(wintypes.HANDLE(handle), timeout_ms)",
        "self.guard_records: list[tuple[Path, tuple[int, int, int, int], str, int]] = []",
        "def verify_guard_records(self) -> None:",
        "def stabilize_change_notification(self) -> None:",
        "for _generation in range(1, MAX_WATCH_SETTLEMENT_GENERATIONS + 1):",
        "WATCH_SETTLEMENT_TIMEOUT_MS",
        "full snapshot change watcher did not reach a clean bounded settlement generation",
    ] {
        assert!(
            text.contains(marker),
            "{LAUNCHER_PATH}: bounded full-watcher settlement marker is missing: {marker}"
        );
    }
}

#[test]
fn a_signaled_settlement_generation_is_revalidated_before_it_is_discarded() {
    let text = source(LAUNCHER_PATH);
    let settle = section(
        &text,
        "def stabilize_change_notification(self) -> None:",
        "\n\ndef arm_watcher(",
        LAUNCHER_PATH,
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
            "{LAUNCHER_PATH}: settlement revalidation marker is missing: {marker}"
        );
    }

    assert!(
        !settle.contains("time.sleep("),
        "{LAUNCHER_PATH}: full-watcher settlement must not use an unguarded sleep"
    );

    let wait = required_offset(
        settle,
        "signaled = self.native.change_notification_signaled(",
        LAUNCHER_PATH,
    );
    let post_wait_guards = required_offset(
        &settle[wait..],
        "self._verify_guard_records()",
        LAUNCHER_PATH,
    ) + wait;
    let post_wait_namespace = required_offset(
        &settle[post_wait_guards..],
        "self._verify_destination_namespace()",
        LAUNCHER_PATH,
    ) + post_wait_guards;
    let close = required_offset(
        &settle[post_wait_namespace..],
        "self.native.close_change_notification(handle)",
        LAUNCHER_PATH,
    ) + post_wait_namespace;
    assert!(
        wait < post_wait_guards
            && post_wait_guards < post_wait_namespace
            && post_wait_namespace < close,
        "{LAUNCHER_PATH}: a signaled generation must prove exact file and namespace state before its notification handle is discarded"
    );
}

#[test]
fn persistent_watcher_reuses_clean_sentinel_inside_the_core_transition_overlap() {
    let launcher = source(LAUNCHER_PATH);
    let core = source(CORE_PATH);

    let arm = section(
        &launcher,
        "def arm_watcher(self) -> None:",
        "\n\ncore.Authority.__init__",
        LAUNCHER_PATH,
    );
    assert!(
        arm.contains("if self.change_notification_handle is None:"),
        "{LAUNCHER_PATH}: persistent watcher must reuse an already clean full-change sentinel"
    );

    let settled = section(
        &launcher,
        "def settled_arm_watcher(self) -> None:",
        "\n\ncore.Authority._arm_watcher = settled_arm_watcher",
        LAUNCHER_PATH,
    );
    let settle = required_offset(
        settled,
        "self._stabilize_change_notification()",
        LAUNCHER_PATH,
    );
    let full_watch = required_offset(settled, "_original_arm_watcher(self)", LAUNCHER_PATH);
    let guard_verify = required_offset(
        &settled[full_watch..],
        "self._verify_guard_records()",
        LAUNCHER_PATH,
    ) + full_watch;
    let namespace_verify = required_offset(
        &settled[guard_verify..],
        "self._verify_destination_namespace()",
        LAUNCHER_PATH,
    ) + guard_verify;
    assert!(
        settle < full_watch && full_watch < guard_verify && guard_verify < namespace_verify,
        "{LAUNCHER_PATH}: clean sentinel establishment must precede persistent watcher startup and exact-state revalidation"
    );

    let copy = section(
        &core,
        "    def copy_and_freeze(self) -> None:",
        "\n    def health_record(",
        CORE_PATH,
    );
    let transition_arm = required_offset(copy, "self._arm_transition_sentinel()", CORE_PATH);
    let transition = required_offset(copy, "self._transition_writers_to_read_guards()", CORE_PATH);
    let patched_arm = required_offset(copy, "self._arm_watcher()", CORE_PATH);
    let retire = required_offset(copy, "self._retire_transition_sentinel()", CORE_PATH);
    assert!(
        transition_arm < transition && transition < patched_arm && patched_arm < retire,
        "{CORE_PATH}: transition sentinel must remain live while the patched full-watcher arm establishes a clean generation"
    );
}
