# NXB-151 acceptance matrix

This matrix defines the minimum evidence required before NXB-151 can be marked complete.

| Gate | Linux | Windows | Required evidence |
|---|---:|---:|---|
| Pinned Rust toolchain | Required | Required | exact `rustc`, Cargo, rustfmt and Clippy versions |
| Formatting | Required | Required | `cargo fmt --all -- --check` |
| Package check | Required | Required | `cargo check -p nxb-core --all-targets --all-features --locked` |
| Clippy | Required | Required | all targets, all features, warnings denied |
| Unit and acceptance tests | Required | Required | serial `nxb-core` test result |
| Full workspace regression | Required | Required | workspace check, Clippy and tests |
| Single binary target | Required | Required | Cargo metadata exposes exactly `nxb` |
| Single executable build | Required | Required | `cargo build -p nxb-core --bin nxb --all-features --locked` |
| No helper executable dependency | Required | Required | workspace, migration and target commands succeed with only `nxb` |
| Init absent path | Required | Required | canonical tree and manifest created |
| Init empty path | Required | Required | canonical tree and manifest created |
| Init non-empty path | Required | Required | fail closed, pre-existing content unchanged |
| Partial-init recovery | Required | Required | no manifest or child directories remain |
| Symlink/reparse-point root | Required | Required | fail closed |
| Manifest size bound | Required | Required | files over 64 KiB rejected |
| Unknown manifest fields | Required | Required | rejected |
| Unsupported schema | Required | Required | rejected |
| Doctor write probe | Required | Required | create-new, flush and cleanup |
| Unix permissions | Required | N/A | root/directories `0700`, documents `0600` |
| Windows ACL | N/A | Required | protected DACL with approved principals only |
| Status redaction | Required | Required | no file contents, secrets or provider handles |
| Stable workspace exit codes | Required | Required | init `10`, doctor `20`, status `30` |
| Stable migration exit codes | Required | Required | apply `40`, recover `41`, status `42` |
| Schema 0 → 1 migration | Required | Required | target manifest and one immutable receipt |
| Orphan-backup recovery | Required | Required | deterministic recovery and cleanup |
| Pending migration doctor | Required | Required | unhealthy result and exit `20` |
| Pending migration status | Required | Required | `recovery_required` and exit `30` |
| Target create and validate | Required | Required | policy and authorization source digests verified |
| Target immutable identity | Required | Required | active profile identity SHA-256 verified |
| Target source non-persistence | Required | Required | no raw policy/auth bytes or local source paths stored |
| Target origin and path boundary | Required | Required | unsafe origin, path and reference rejected |
| Target source drift | Required | Required | `target validate` rejects digest drift with exit `54` |
| Target disable receipt | Required | Required | create-only receipt binds canonical profile SHA-256 |
| Target profile tamper | Required | Required | show/list fail closed with exit `52` |
| Target receipt tamper | Required | Required | show/list fail closed with exit `52` |
| Target private file mode | Required | N/A | profile and receipt mode `0600` |
| Target broad ACL rejection | N/A | Required | injected Everyone ACE rejected |
| Stable target exit codes | Required | Required | create `50`, list `51`, show `52`, disable `53`, validate `54` |
| Diagnostic JSON schema | Required | Required | exact schema/code/domain/operation/exit mapping |
| Diagnostic message bound | Required | Required | single line, no CR/LF/NUL, maximum 2,048 characters |
| Synthetic authorization binding | Required | Required | canonical fixture source hashes validate |
| Synthetic policy validation | Required | Required | policy compiles at fixed acceptance time |
| Networkless scan plan | Required | Required | dry-run plan has zero issued requests |
| Manual report bundle | Required | Required | JSON, Markdown, HackerOne draft and manifest generated |
| Automatic submission disabled | Required | Required | report and draft explicitly preserve manual review |
| Demo receipt | Required | Required | deterministic receipt generated and verified |
| Final doctor/status | Required | Required | workspace remains healthy and ready |
| Exact-head evidence | Required | Required | JSON evidence, `nxb` SHA-256 and artifact SHA-256 values |
| No workflow re-enable | Required | Required | no GitHub Actions workflow added or enabled |
| No NXB-151 lock drift | Required | Required | no `Cargo.lock` modification from this stacked PR |

NXB-151 remains draft until every required cell has immutable evidence tied to one exact commit. Source implementation or static inspection does not satisfy a required evidence cell.
