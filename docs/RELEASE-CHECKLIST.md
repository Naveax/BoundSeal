# Release checklist

## Source and dependency closure

- [ ] `rust-toolchain.toml` matches the approved Rust release.
- [ ] `Cargo.lock` is committed and unchanged after `cargo check --locked`.
- [ ] `cargo fmt --all --check` passes.
- [ ] Clippy passes with warnings denied.
- [ ] All workspace tests pass with all features.
- [ ] The synthetic demo receipt generates and verifies.
- [ ] RustSec audit passes.
- [ ] cargo-deny advisories, licenses, bans and source checks pass.

## Documentation

- [ ] README status is current.
- [ ] Architecture and threat model are current.
- [ ] `CHANGELOG.md` contains the release.
- [ ] `SECURITY.md` is present.
- [ ] Known live-product limitations are explicit.

## Safety

- [ ] No socket, resolver, browser, scanner or process adapter entered the release.
- [ ] No credential attack or destructive capability exists.
- [ ] No raw secret or body is emitted in fixtures, logs, audit records or artifacts.
- [ ] Temporary materializer workflows and payloads are absent.

## Release

- [ ] Main CI is green.
- [ ] Create annotated tag `v0.1.0-contract-complete`.
- [ ] Record the main commit and CI run in the release notes.
