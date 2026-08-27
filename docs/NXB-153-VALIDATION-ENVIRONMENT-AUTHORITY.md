# NXB-153 Validation Environment Authority

## Status

This document records the ambient-process environment boundary for NXB-153 validation.

The controls described here are **source-staged, not admitted**. Real exact-head Linux and supported Windows execution is still required before any platform PASS or NXB-153 admission claim.

The purpose of this contract is to prevent an exact-head validation from consuming immutable workspace/dependency bytes while the operator process silently changes compiler, Cargo, Python, target, runner or native-build behavior through ambient environment variables.

## Threat model

The contract addresses avoidable ambient authority such as:

- `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `RUSTFLAGS` and related Rust compiler/documentation overrides;
- `RUSTUP_*` toolchain/distribution overrides;
- `CARGO_HOME`, `CARGO_TARGET_DIR`, encoded Rust flags and Cargo build/profile/source/registry/target/runner configuration families;
- `PYTHONPATH`, `PYTHONHOME` and startup/import-path injection into the Python authority helpers;
- native compiler/archive/linker overrides used by build scripts, including `CC`, `CXX`, `AR`, `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LD`, `LDFLAGS`, `RANLIB`, MSVC `CL`/`_CL_`, `CRATE_CC_NO_DEFAULTS` and target-specific variants;
- `BINDGEN_EXTRA_CLANG_ARGS` and target-specific variants.

This is not a claim that the complete host operating system or Rust installation is adversarially reproducible. A compromised kernel, administrator, hypervisor, trusted Rust distribution, platform SDK or every host tool simultaneously remains outside this contract. Host-toolchain executable identity remains an explicit admission consideration rather than being disguised as an environment-variable property.

## Canonical policy

Canonical cross-platform policy implementation:

`scripts/nxb-153-validation-environment.py`

The helper uses case-insensitive variable-name matching so Windows spelling/casing does not create a different security contract.

The helper never prints blocked variable **values**. Only names may be reported, avoiding accidental disclosure of registry credentials, tokens or other process secrets.

Policy identifier:

`nxb-153-compiler-cargo-python-authority-v2`

The Python helper includes a networkless self-test covering accepted host variables, Rust/Cargo/Python overrides, native `cc`-style overrides and case-variant rejection.

## Allowed host discovery

The policy intentionally does not reject every environment variable.

For example, `PATH`, proxy/TLS variables and the Visual Studio/Windows SDK discovery variables `INCLUDE`, `LIB` and `LIBPATH` are not currently rejected merely for existing. Those are part of the supported-host/toolchain boundary rather than operator-selectable exact-source overrides in this contract.

This distinction is deliberate. Blindly deleting or rejecting the complete environment would make supported Windows toolchain discovery unreliable without actually proving toolchain identity.

## Linux preparation

Canonical entrypoint:

`scripts/prepare-and-validate-nxb-153-linux.sh`

Before `rustup toolchain install` or either `cargo install` begins, Linux preparation:

1. resolves `scripts/nxb-153-validation-environment.py` from the exact-head committed Git object;
2. executes its self-test with `python3 -I`;
3. executes its ambient-environment audit with `python3 -I`;
4. fails before tool mutation/receipt publication if the policy is violated.

Thus a tooling receipt cannot be intentionally prepared under one of the rejected compiler/Cargo/Python/native-build override variables.

## Linux validation

Canonical immutable runner:

`scripts/nxb-153-linux-immutable-source.sh`

The exact-head immutable snapshot must contain the environment and registry authority helpers as regular tracked files. Before dependency acquisition or heavy Cargo gates, the child validation flow runs the environment self-test/audit and the registry verifier self-test.

Python security/registry helpers are executed with `python3 -I` isolated mode so `PYTHONPATH`/user-site import state is not trusted as helper-code authority.

After the audit, NXB-153 itself creates the controlled Cargo environment required by the validation lifecycle, including private target/fetch/vendor/gate roots and offline gate state. Those controlled variables are implementation state, not inherited ambient authority.

## Windows preparation

Canonical entrypoint:

`scripts/prepare-and-validate-nxb-153-windows.ps1`

Windows preparation performs the same case-insensitive v2 forbidden-name audit before repository/tool preparation reaches any `rustup` or Cargo installation step.

The PowerShell implementation intentionally duplicates the small name policy rather than invoking Python before Python authority has itself been constrained. Values are not printed.

## Windows validation/dependency gates

Canonical dependency runner:

`scripts/nxb-153-windows-dependency-source.ps1`

The dependency runner performs the same ambient audit at entry, before it stages controlled `CARGO_HOME`, target or offline variables and before any Cargo gate executes.

Python 3.11+ discovery is tested with `-I`, every direct registry-verifier invocation uses `python -I`, and the metadata verifier subprocess places `-I` before the helper pathname.

The parent immutable-source runner keeps exact-head workspace handles alive while this dependency/environment-bounded gate sequence executes.

## Current native-build reason

The exact NXB-153 lockfile contains `ring 0.17.14`, which depends on the `cc` crate. Therefore native compiler/archive environment overrides are not hypothetical for this dependency graph. They can affect a build even when Cargo.lock and vendored source bytes are stable.

The v2 environment policy consequently rejects the relevant `cc`/compiler flag families rather than limiting the policy to Rust-only variables.

## Remaining acceptance

The environment policy is not final admission by itself. Exact final-head platform evidence must still prove:

- Linux environment self-test/audit runs before preparation and heavy validation under the real canonical flow;
- Windows PowerShell environment guard parses and rejects representative exact/prefix/case-variant variables on supported Windows;
- Windows Python 3.11+ isolated-mode invocations work in the canonical dependency flow;
- supported host SDK/toolchain discovery still works with the allowed host variables;
- no rejected ambient compiler/Cargo/Python/native-build variable is silently reintroduced before a heavy gate;
- immutable workspace/dependency source, exact-head security-tool authority, serialization, create-only evidence and object-anchored review all continue to pass on the same exact head.

Host Rust/rustup/cargo/rustc/rustfmt/clippy executable identity is a separate trust boundary. This document does not claim to make a malicious or replaced trusted Rust distribution safe merely by sanitizing environment variables.

PR #89 remains draft/not admitted. Issues #90–#98 remain open. NXB-154 must not use NXB-153 as an admitted implementation base until the exact-head Linux + Windows closure and blocker review complete.
