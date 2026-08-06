# NXB-150 Dual-Platform Evidence Closure

## Purpose

NXB-150 cannot leave draft state merely because Linux and Windows validation files exist. Both files must describe the same unchanged Git head, the same canonical lockfile and the same pinned toolchain, and every required gate must report success.

The closure scripts perform that final networkless review and publish one deterministic local closure document.

## Required inputs

The evidence directory must contain exactly named schema-v2 platform documents for the current checkout head:

```text
target/nxb-validation/nxb-150-linux-<HEAD>.json
target/nxb-validation/nxb-150-windows-<HEAD>.json
```

The checkout must have:

- one clean 40-character Git head;
- the committed candidate `Cargo.lock`;
- `Cargo.lock` SHA-256 `f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff`;
- no source or untracked working-tree change.

The evidence directory and every existing parent component must be a normal directory path. Symbolic links, junctions and Windows reparse points are rejected rather than resolved.

## Windows review

```text
pwsh -NoProfile -File .\scripts\review-nxb-150-evidence.ps1
```

An alternate evidence directory may be supplied:

```text
pwsh -NoProfile -File .\scripts\review-nxb-150-evidence.ps1 \
  -EvidenceDirectory D:\NXB-Evidence
```

## Linux review

The Linux wrapper uses only Bash, Git, `sha256sum` and the Python 3 standard library:

```text
bash scripts/review-nxb-150-evidence-linux.sh
```

An alternate evidence directory may be supplied as the second positional argument:

```text
bash scripts/review-nxb-150-evidence-linux.sh \
  /path/to/repository \
  /path/to/evidence
```

## Fail-closed evidence checks

Each platform document must:

- be a regular non-symlink file of 1–65,536 bytes;
- have no symbolic-link, junction or reparse-point parent component;
- be strict UTF-8 JSON;
- contain exactly the schema-v2 field set, with no unknown or missing field;
- use the required JSON types rather than truthy or string-coerced values;
- identify milestone `NXB-150` and gate `pinned_process_evidence_key_provider`;
- identify the expected platform and current exact Git head;
- report Rust `1.97.1`;
- report `cargo-audit 0.22.2` and `cargo-deny 0.20.2`;
- bind lowercase SHA-256 values for both security-tool executables;
- bind the expected `Cargo.lock` SHA-256;
- report lockfile reproduction without diff;
- report package fmt/check/Clippy/tests as passed;
- report vault-provider regressions as passed;
- report full workspace check/Clippy/tests as passed;
- report RustSec and cargo-deny as passed;
- report the serial process fixture as passed;
- use canonical UTC `validated_at` not more than five minutes in the future.

The Linux and Windows documents must agree exactly on:

- Git head;
- Rust version;
- Cargo version;
- cargo-audit version;
- cargo-deny version;
- `Cargo.lock` SHA-256.

Platform executable hashes are retained separately because Windows and Linux binaries are expected to differ.

## Closure output

A successful review creates:

```text
target/nxb-validation/nxb-150-closure-<HEAD>.json
```

The closure binds:

- exact final head;
- canonical lockfile SHA-256;
- pinned Rust/Cargo/security-tool versions;
- Linux and Windows evidence file names and SHA-256 values;
- each platform security-tool executable SHA-256;
- both validation timestamps;
- all required gate summaries;
- status `ready_for_manual_pr_review`;
- network activity `none`.

The closure is published through a create-new pending file and atomic rename. Linux flushes the pending file and parent directory before success. A pre-existing pending file is never deleted automatically; it blocks closure and requires manual recovery.

A pre-existing closure must be a bounded regular non-symlink file and semantically identical to the deterministic review result. Formatting differences are permitted; content differences are never overwritten.

## Closure source self-test

The Linux verifier has a permanent networkless adversarial self-test:

```text
bash scripts/test-nxb-150-evidence-closure-linux.sh
```

The self-test builds an isolated temporary Git repository from the current verifier and candidate lockfile, then covers:

- valid dual-platform closure;
- idempotent repeat;
- mixed-head rejection;
- unknown-field rejection;
- wrong-type rejection;
- future-timestamp rejection;
- failed-gate rejection;
- evidence-file symlink rejection;
- evidence-directory symlink rejection;
- existing closure symlink rejection;
- tampered closure rejection;
- orphan pending-file rejection;
- pending symlink rejection.

This is verifier-source testing only. It does not replace Rust compilation, package/workspace validation or real Linux/Windows evidence.

## Manual PR transition

`ready_for_manual_pr_review` is not an automatic merge authorization. Before changing PR #68 from draft:

1. inspect both platform evidence files;
2. inspect the closure document;
3. confirm the closure head equals the current PR head;
4. confirm no review thread remains unresolved;
5. confirm the PR diff contains no workflow enablement or unexpected file;
6. only then mark the exact-head PR ready for review.

A missing platform, stale head, mixed toolchain, unknown JSON field, hash mismatch, path indirection, orphan pending file or failed gate blocks closure.

## Validation status

The closure sources and Linux adversarial self-test are present on the NXB-150 draft branch. Their existence and source-level success are not evidence that Rust, Linux package validation or Windows validation has run. PR #68 remains draft until actual platform evidence and a successful closure document are produced on one final unchanged head.
