# NXB-120 Repository Stabilization

This maintenance batch turns the NXB-0 through NXB-119 contract program into a reproducible, understandable and executable networkless checkpoint.

## Scope

- current root documentation and crate map;
- explicit contract-complete versus live-product status;
- pinned Rust toolchain;
- committed Cargo lockfile;
- RustSec and cargo-deny dependency policy;
- deterministic CLI system-status command;
- deterministic twelve-stage synthetic smoke receipt;
- receipt verification and tamper tests;
- release and security documentation;
- first contract-complete release checklist.

## Verification sequence

1. Generate the Cargo lockfile with the pinned toolchain.
2. Check the complete workspace with `--locked`.
3. Restore the permanent read-only CI workflow.
4. Run formatting, Clippy, tests and the synthetic demo.
5. Run RustSec and cargo-deny dependency-policy gates.
6. Merge only after the permanent branch head is green.

## Excluded

- resolver, socket, TLS negotiation or public-network traffic;
- browser, proxy or scanner automation;
- credential attacks or destructive testing;
- raw secrets or HTTP message bodies;
- shell, process, plugin or deployment execution.
