#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing lint-fix anchor: {label}")
    file.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def main() -> None:
    replace_once(
        "crates/nxb-core/src/target/activation.rs",
        """use super::{\n    build_guided_setup, canonical_json, workspace, AuthorizationBasis, AuthorizationBinding,\n    ProgramMetadata, SetupAuthorization, SetupAutomation, SetupPolicyBinding, SetupPreview,\n    SetupPreviewIdentity, SetupProgram, TargetProfile, PROFILE_SCHEMA_VERSION,\n};\n""",
        """use super::{\n    build_guided_setup, canonical_json, workspace, AuthorizationBasis, AuthorizationBinding,\n    ProgramMetadata, SetupPreview, SetupPreviewIdentity, TargetProfile, PROFILE_SCHEMA_VERSION,\n};\n#[cfg(test)]\nuse super::{SetupAuthorization, SetupAutomation, SetupPolicyBinding, SetupProgram};\n""",
        "activation test-only setup imports",
    )

    replace_once(
        "crates/nxb-core/src/prepared_file_authority.rs",
        "use std::os::unix::fs::{MetadataExt, PermissionsExt};",
        "use std::os::unix::fs::PermissionsExt;",
        "prepared-file unused MetadataExt import",
    )

    directory = "crates/nxb-core/src/directory_authority.rs"
    for marker in [
        "    #[cfg(target_os = \"linux\")]\n    pub(crate) fn sync(&self, label: &str) -> Result<()> {",
        "    #[cfg(all(unix, not(target_os = \"linux\")))]\n    pub(crate) fn sync(&self, _label: &str) -> Result<()> {",
        "    #[cfg(not(unix))]\n    pub(crate) fn sync(&self, _label: &str) -> Result<()> {",
    ]:
        replace_once(
            directory,
            marker,
            marker.replace("    pub(crate) fn sync", "    #[allow(dead_code)]\n    pub(crate) fn sync"),
            "directory sync compatibility surface",
        )

    authority = "crates/nxb-core/src/workspace_authority.rs"
    for marker in [
        "fn authority_exact_directory(path: &Path) -> bool {",
        "struct AuthorityUnpublishedCleanupError {",
        "pub(crate) fn create_document(path: &Path, bytes: &[u8]) -> Result<()> {",
        "fn create_authority_document(path: &Path, bytes: &[u8]) -> Result<()> {",
        "fn remove_authority_temporary(path: &Path) -> Result<()> {",
        "fn sync_authority_directory(path: &Path) -> Result<()> {",
    ]:
        replace_once(
            authority,
            marker,
            "#[allow(dead_code)]\n" + marker,
            f"intentional base-authority compatibility item {marker}",
        )

    workspace = "crates/nxb-core/src/workspace/mod.rs"
    for marker in [
        "struct DoctorResult {",
        "struct DoctorCheck {",
        "enum CheckStatus {",
        "pub(crate) fn doctor_value(workspace: &Path) -> Result<Value> {",
        "fn doctor_result(workspace: &Path) -> DoctorResult {",
        "pub(crate) fn replace_document(path: &Path, bytes: &[u8]) -> Result<()> {",
        "fn write_probe(workspace: &Path) -> Result<()> {",
        "fn pass_check(name: impl Into<String>, detail: impl Into<String>) -> DoctorCheck {",
        "fn fail_check(name: impl Into<String>, detail: impl Into<String>) -> DoctorCheck {",
        "pub(crate) fn remove_regular(path: &Path) -> Result<()> {",
    ]:
        replace_once(
            workspace,
            marker,
            "#[allow(dead_code)]\n" + marker,
            f"intentional legacy workspace compatibility item {marker}",
        )
    for marker in [
        "#[cfg(unix)]\nfn replace_file(source: &Path, destination: &Path) -> Result<()> {",
        "#[cfg(not(unix))]\nfn replace_file(source: &Path, destination: &Path) -> Result<()> {",
    ]:
        replace_once(
            workspace,
            marker,
            marker.replace("fn replace_file", "#[allow(dead_code)]\nfn replace_file"),
            "legacy replacement compatibility item",
        )

    live = "crates/nxb-core/src/live_orchestrator.rs"
    for marker in [
        "    pub fn code(self) -> &'static str {",
        "    pub fn parsed_url(&self) -> Result<Url> {",
        "    pub fn request_target(&self) -> Result<String> {",
        "pub struct LiveOrchestratorReceipt {",
    ]:
        prefix = "    #[allow(dead_code)]\n" if marker.startswith("    ") else "#[allow(dead_code)]\n"
        replace_once(live, marker, prefix + marker, f"dormant live API compatibility item {marker}")
    replace_once(
        live,
        "impl LiveOrchestratorReceipt {\n    pub fn verify(&self) -> Result<()> {",
        "impl LiveOrchestratorReceipt {\n    #[allow(dead_code)]\n    pub fn verify(&self) -> Result<()> {",
        "dormant orchestrator receipt verify API",
    )

    replace_once(
        "crates/nxb-core/src/workspace_doctor_probe.rs",
        """    #[cfg(target_os = \"linux\")]\n    {\n        return run_linux(directory);\n    }\n    #[cfg(windows)]\n    {\n        return run_windows(directory);\n    }\n""",
        """    #[cfg(target_os = \"linux\")]\n    {\n        run_linux(directory)\n    }\n    #[cfg(windows)]\n    {\n        run_windows(directory)\n    }\n""",
        "doctor probe needless return",
    )

    replace_once(
        "crates/nxb-evidence-key-provider-process/src/bin/nxb-windows-credential-evidence-key-helper.rs",
        'const VERSION_COMMENT_PREFIX: &str = "NXB_EVIDENCE_KEY_VERSION:";',
        '#[cfg(windows)]\nconst VERSION_COMMENT_PREFIX: &str = "NXB_EVIDENCE_KEY_VERSION:";',
        "Windows-only credential version comment prefix",
    )


if __name__ == "__main__":
    main()
