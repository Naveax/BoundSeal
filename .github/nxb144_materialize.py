from pathlib import Path
import base64
import gzip
import io
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def write_payloads() -> None:
    encoded = "".join(
        (ROOT / f".github/nxb144_payload_{index:02d}.txt").read_text(encoding="utf-8")
        for index in range(4)
    )
    archive = gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(encoded)))
    with tarfile.open(fileobj=archive, mode="r:") as bundle:
        for member in bundle.getmembers():
            target = (ROOT / member.name).resolve()
            if ROOT.resolve() not in target.parents or not member.isfile():
                raise SystemExit("unsafe NXB-144 payload member")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise SystemExit("missing NXB-144 payload content")
            target.write_bytes(source.read())


def patch_workspace() -> None:
    path = ROOT / "Cargo.toml"
    text = path.read_text(encoding="utf-8")
    member = '    "crates/nxb-resumable-runner",\n'
    if member not in text:
        anchor = '    "crates/nxb-operator-runtime",\n'
        if text.count(anchor) != 1:
            raise SystemExit("unexpected workspace member anchor")
        text = text.replace(anchor, anchor + member, 1)
    path.write_text(text, encoding="utf-8", newline="\n")


def patch_runtime() -> None:
    path = ROOT / "crates/nxb-operator-runtime/src/lib.rs"
    text = path.read_text(encoding="utf-8")

    if "pub fn from_live(" not in text:
        anchor = "    fn from_live(\n"
        if text.count(anchor) != 1:
            raise SystemExit("runtime receipt constructor anchor missing")
        text = text.replace(anchor, "    pub fn from_live(\n", 1)

    committed_struct = '''#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCommittedRequest {
    pub request_index: u64,
    pub method: RuntimeMethod,
    pub request_target_sha256: String,
    pub depth: u16,
    pub execution_receipt_sha256: String,
    pub checkpoint_sequence: u64,
    pub checkpoint_sha256: String,
}

'''
    if "pub struct RuntimeCommittedRequest" not in text:
        anchor = "#[derive(Debug, Clone)]\npub struct RuntimeRecovery {\n"
        if text.count(anchor) != 1:
            raise SystemExit("runtime recovery anchor missing")
        text = text.replace(anchor, committed_struct + anchor, 1)

    recovery_anchor = "    pub committed_requests: u64,\n    pub unresolved_request:"
    if "pub last_committed_request: Option<RuntimeCommittedRequest>" not in text:
        if text.count(recovery_anchor) != 1:
            raise SystemExit("runtime recovery field anchor missing")
        text = text.replace(
            recovery_anchor,
            "    pub committed_requests: u64,\n"
            "    pub last_committed_request: Option<RuntimeCommittedRequest>,\n"
            "    pub unresolved_request:",
            1,
        )

    journal_anchor = "    committed_requests: u64,\n    next_request_index:"
    if "last_committed_request: Option<RuntimeCommittedRequest>,\n    next_request_index" not in text:
        if text.count(journal_anchor) != 1:
            raise SystemExit("journal scan field anchor missing")
        text = text.replace(
            journal_anchor,
            "    committed_requests: u64,\n"
            "    last_committed_request: Option<RuntimeCommittedRequest>,\n"
            "    next_request_index:",
            1,
        )

    initial_anchor = "            committed_requests: 0,\n            unresolved_request: None,"
    if initial_anchor in text:
        text = text.replace(
            initial_anchor,
            "            committed_requests: 0,\n"
            "            last_committed_request: None,\n"
            "            unresolved_request: None,",
            1,
        )

    recovery_scan_anchor = (
        "            committed_requests: scan.committed_requests,\n"
        "            unresolved_request: scan.unresolved_request,"
    )
    replacement = (
        "            committed_requests: scan.committed_requests,\n"
        "            last_committed_request: scan.last_committed_request.clone(),\n"
        "            unresolved_request: scan.unresolved_request,"
    )
    occurrences = text.count(recovery_scan_anchor)
    if occurrences not in (0, 2):
        raise SystemExit(f"unexpected runtime recovery constructor count: {occurrences}")
    if occurrences == 2:
        text = text.replace(recovery_scan_anchor, replacement)

    if "let mut last_committed_request = None;" not in text:
        anchor = "    let mut last_committed = None;\n"
        if text.count(anchor) != 1:
            raise SystemExit("last committed timestamp anchor missing")
        text = text.replace(
            anchor, anchor + "    let mut last_committed_request = None;\n", 1
        )

    summary_assignment = '''                last_committed_request = Some(RuntimeCommittedRequest {
                    request_index: index,
                    method: prepared.method,
                    request_target_sha256: prepared.request_target_sha256.clone(),
                    depth: prepared.depth,
                    execution_receipt_sha256: outcome.execution.receipt_sha256.clone(),
                    checkpoint_sequence: commit.checkpoint_sequence,
                    checkpoint_sha256: commit.checkpoint_sha256.clone(),
                });
'''
    if "execution_receipt_sha256: outcome.execution.receipt_sha256.clone()" not in text:
        anchor = (
            "                committed_requests += 1;\n"
            "                last_committed = Some(commit.committed_at_epoch_milliseconds);\n"
        )
        if text.count(anchor) != 1:
            raise SystemExit("committed request branch anchor missing")
        text = text.replace(anchor, anchor + summary_assignment, 1)

    return_anchor = (
        "        journal_bytes,\n"
        "        committed_requests,\n"
        "        next_request_index,"
    )
    if "        last_committed_request,\n        next_request_index," not in text:
        if text.count(return_anchor) != 1:
            raise SystemExit("journal scan return anchor missing")
        text = text.replace(
            return_anchor,
            "        journal_bytes,\n"
            "        committed_requests,\n"
            "        last_committed_request,\n"
            "        next_request_index,",
            1,
        )

    if "pub fn execute_with_reserved_workspace" not in text:
        start = text.find("    pub fn execute_with<F>(")
        body = text.find("        let clock = clock.validate()?;", start)
        if start < 0 or body < 0:
            raise SystemExit("execute_with signature anchor missing")
        signatures = '''    pub fn execute_with<F>(
        &mut self,
        spec: RuntimeRequestSpec,
        clock: RuntimeClock,
        executor: F,
    ) -> Result<(RuntimeExecutionReceipt, RecoveredOperatorState), RuntimeError>
    where
        F: FnOnce(&RuntimeRequestSpec) -> Result<RuntimeExecutionReceipt, RuntimeError>,
    {
        self.execute_with_reserved_workspace(spec, clock, 0, executor)
    }

    pub fn execute_with_reserved_workspace<F>(
        &mut self,
        spec: RuntimeRequestSpec,
        clock: RuntimeClock,
        external_reserved_bytes: u64,
        executor: F,
    ) -> Result<(RuntimeExecutionReceipt, RecoveredOperatorState), RuntimeError>
    where
        F: FnOnce(&RuntimeRequestSpec) -> Result<RuntimeExecutionReceipt, RuntimeError>,
    {
'''
        text = text[:start] + signatures + text[body:]

    prospective_anchor = (
        "            .and_then(|value| value.checked_add(RUNTIME_COMMIT_RESERVATION_BYTES))\n"
        "            .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;"
    )
    if "checked_add(external_reserved_bytes)" not in text:
        if text.count(prospective_anchor) < 1:
            raise SystemExit("runtime prospective workspace anchor missing")
        text = text.replace(
            prospective_anchor,
            "            .and_then(|value| value.checked_add(RUNTIME_COMMIT_RESERVATION_BYTES))\n"
            "            .and_then(|value| value.checked_add(external_reserved_bytes))\n"
            "            .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;",
            1,
        )

    old_evidence = '''            let calculated = recovered
                .latest
                .counters
                .evidence_bytes
                .checked_add(prepared_bytes.len() as u64)
                .and_then(|value| value.checked_add(outcome_bytes.len() as u64))
                .and_then(|value| value.checked_add(RUNTIME_COMMIT_RESERVATION_BYTES))
                .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;
'''
    new_evidence = '''            let exact_evidence = self
                .journal_bytes
                .checked_add(outcome_bytes.len() as u64)
                .and_then(|value| value.checked_add(RUNTIME_COMMIT_RESERVATION_BYTES))
                .and_then(|value| value.checked_add(external_reserved_bytes))
                .ok_or(RuntimeError::WorkspaceBudgetExceeded)?;
            let calculated = recovered
                .latest
                .counters
                .evidence_bytes
                .max(exact_evidence);
'''
    if old_evidence in text:
        text = text.replace(old_evidence, new_evidence, 1)
    elif "let exact_evidence = self" not in text:
        raise SystemExit("runtime evidence accounting anchor missing")

    path.write_text(text, encoding="utf-8", newline="\n")


write_payloads()
patch_workspace()
patch_runtime()
