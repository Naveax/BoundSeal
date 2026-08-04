# v0.1.0-contract-complete release checkpoint

## Meaning

This release candidate records completion of the NXB-0 through NXB-147 contract architecture. It is a bounded security-automation contract checkpoint, not a claim of unrestricted autonomous scanning.

## Included chain

1. Signed authorization, scope, DNS, transport, TLS and HTTP contracts.
2. Vault-backed authenticated request injection and external provider lifecycle.
3. Signed unified operator plan and one-use activation.
4. Durable checkpoint-bound authenticated runtime.
5. Resumable bounded GET/HEAD runner and signed live-run host.
6. Ordered teardown and signed terminal closure.
7. Operator-approved signed manual-submission handoff.

## Required release evidence

- Tag `v0.1.0-contract-complete` points to the merged release commit.
- Every workspace package resolves to version `0.1.0` and remains `publish = false`.
- Canonical committed `Cargo.lock` matches a regenerated lockfile.
- Full format, all-target Clippy, workspace tests and synthetic demo pass.
- Ubuntu and Windows contract regressions pass.
- RustSec and cargo-deny policy checks pass.
- Release binary, deterministic CycloneDX SBOM and source-tree manifest are produced.
- SHA-256 checksums cover the binary, SBOM, source manifest, release contract and lockfile.
- Secret-pattern scanning passes before immutable evidence upload.

## Explicit exclusions

- Automatic HackerOne or platform submission.
- Browser/proxy automation and browser credential access.
- Password-manager or operating-system credential-store adapters.
- Credential discovery, destructive methods or unrestricted exploitation.
- Production encrypted evidence sealing.

The release remains private and non-publishable. It is intended as a verifiable source and artifact checkpoint for continued controlled development.
