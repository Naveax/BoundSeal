# NXB-151 acceptance matrix

This matrix defines the minimum evidence required before NXB-151 can be marked complete.

| Gate | Linux | Windows | Required evidence |
|---|---:|---:|---|
| Pinned Rust toolchain | Required | Required | exact `rustc`, Cargo, rustfmt and Clippy versions |
| Formatting | Required | Required | `cargo fmt --all -- --check` |
| Package check | Required | Required | `cargo check -p nxb-core --all-targets --all-features --locked` |
| Clippy | Required | Required | all targets, all features, warnings denied |
| Unit and acceptance tests | Required | Required | serial `nxb-core` test result |
| Single binary target | Required | Required | Cargo metadata exposes exactly `nxb` |
| Single executable build | Required | Required | `cargo build -p nxb-core --bin nxb --all-features --locked` |
| No helper executable dependency | Required | Required | workspace and migration commands succeed with only `nxb` |
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
| Synthetic product flow | Required | Required | init → doctor → status → migration status succeeds |
| Exact-head evidence | Required | Required | JSON evidence and `nxb` SHA-256 |

NXB-151 remains draft until every required cell has immutable evidence tied to an exact commit.
