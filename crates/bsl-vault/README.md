# bsl-vault

`bsl-vault` is the in-memory secret boundary for authenticated testing.

It stores cookie, bearer-token, API-key and CSRF values behind opaque handles. Raw values are deliberately excluded from `Debug`, serde, errors and audit events. Access requires an exact run, worker, account, tenant, role, host and scheme binding.

Secret access is issued as a short-lived lease. HTTP materialization produces a second single-use header lease bound to one session, authority and scheme. Materialized buffers are zeroized on drop.

This crate intentionally provides no disk persistence, environment import, browser import, keychain integration, network access or report export.
