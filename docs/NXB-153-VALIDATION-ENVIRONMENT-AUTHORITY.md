# NXB-153 Validation Environment Authority

## Status

This document records the ambient-process environment boundary for NXB-153 validation.

The controls described here are **source-staged, not admitted**. Real exact-head Linux and supported Windows execution is still required before any platform PASS or NXB-153 admission claim.

The purpose of this contract is to prevent an exact-head validation from consuming immutable workspace/dependency bytes while the operator process silently changes compiler, Cargo, Python, Bash startup, target, runner or native-build behavior through ambient environment variables.

## Threat model

The contract addresses avoidable ambient authority such as:

- `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `RUSTFLAGS` and related Rust compiler/documentation overrides;
- `RUSTUP_*` toolchain/distribution overrides;
- `CARGO_HOME`, `CARGO_TARGET_DIR`, encoded Rust flags and Cargo build/profile/source/registry/target/runner configuration families;
- `PYTHONPATH`, `PYTHONHOME` and startup/import-path injection into Python authority helpers;
- native compiler/archive/linker overrides used by build scripts, including `CC`, `CXX`, `AR`, `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LD`, `LDFLAGS`, `RANLIB`, MSVC `CL`/`_CL_`, `CRATE_CC_NO_DEFAULTS` and target-specific variants;
- `BINDGEN_EXTRA_CLANG_ARGS` and target-specific variants;
- Bash startup/behavior controls `BASH_ENV`, `BASHOPTS`, `BASH_COMPAT`, `SHELLOPTS`, `POSIXLY_CORRECT` and exported shell-function environment entries matching `BASH_FUNC_*`.

This is not a claim that the complete host operating system or Rust installation is adversarially reproducible. A compromised kernel, administrator, hypervisor, trusted Rust distribution, platform SDK or every host tool simultaneously remains outside this contract. Host-toolchain executable identity remains an explicit admission consideration rather than being disguised as an environment-variable property.

## Canonical policy

Canonical cross-platform policy implementation:

`scripts/nxb-153-validation-environment.py`

Current helper blob:

`8b1766915b6ad3a2350a3368fb666b8dbff240b5`

The helper uses case-insensitive variable-name matching so Windows spelling/casing does not create a different security contract.

The helper never prints blocked variable **values**. Only names may be reported, avoiding accidental disclosure of registry credentials, tokens or other process secrets.

Policy identifier remains:

`nxb-153-compiler-cargo-python-authority-v2`

The identifier is retained because no NXB-153 evidence using this policy has been admitted. The current source-staged v2 implementation now also covers the Bash startup/function variables listed above; final exact-head evidence must bind to the actual committed helper object and runtime behavior rather than infer semantics from the label alone.

The Python helper includes a networkless self-test covering accepted host variables, Rust/Cargo/Python/native-build overrides, Bash startup/function overrides and case-variant rejection.

## Privileged Bash boundary on Linux

An environment audit that executes after Bash startup cannot undo startup code that has already run. NXB-153 therefore does **not** rely on the Python audit alone for Linux shell entry authority.

Canonical Linux preparation, validation and evidence-review wrappers require privileged Bash mode (`-p`). Their direct-exec shebangs request privileged Bash, and each wrapper verifies the `p` shell option before accepting the shell as canonical authority.

The preparation/validation wrappers also resolve the Bash executable and force Bash children launched by the preserved inner implementations through `-p`. The exact-head entry-blob adversarial probe is executed by the canonical validator through a `pipefail`-protected `<resolved-bash> -p -s` pipeline before inner validation.

Privileged Bash prevents `BASH_ENV` startup processing and exported-function import before the script's later environment audit. The environment audit then independently rejects those ambient variables so their presence is visible as an admission failure rather than silently ignored.

Canonical Linux blob/startup authority is documented in:

`docs/NXB-153-LINUX-ENTRY-BLOB-AUTHORITY.md`

## Allowed host discovery

The policy intentionally does not reject every environment variable.

For example, `PATH`, proxy/TLS variables and Visual Studio/Windows SDK discovery variables `INCLUDE`, `LIB` and `LIBPATH` are not currently rejected merely for existing. Those are part of the supported-host/toolchain boundary rather than operator-selectable exact-source overrides in this contract.

This distinction is deliberate. Blindly deleting or rejecting the complete environment would make supported Windows toolchain discovery unreliable without actually proving toolchain identity.

## Linux preparation

Canonical entrypoint:

`scripts/prepare-and-validate-nxb-153-linux.sh`

Before `rustup toolchain install` or either `cargo install` begins, Linux preparation:

1. begins under privileged Bash authority;
2. resolves `scripts/nxb-153-validation-environment.py` from the exact-head committed Git object;
3. executes its self-test with `python3 -I`;
4. executes its ambient-environment audit with `python3 -I`;
5. fails before tool mutation/receipt publication if the policy is violated.

Thus a tooling receipt cannot be intentionally prepared under one of the rejected compiler/Cargo/Python/native-build/Bash authority variables.

## Linux validation

Canonical outer entrypoint:

`scripts/validate-nxb-153-linux.sh`

Canonical immutable runner:

`scripts/nxb-153-linux-immutable-source.sh`

The outer validator starts under privileged Bash, executes the exact-head entry-blob probe under privileged Bash, then evaluates only captured/OID-verified preserved validator bytes. The preserved validator runs the exact-head environment helper before dependency acquisition or heavy Cargo gates.

The exact-head immutable snapshot must contain the environment and registry authority helpers as regular tracked files. Before dependency acquisition or heavy Cargo gates, the child validation flow runs the environment self-test/audit and the registry verifier self-test.

Python security/registry helpers are executed with `python3 -I` isolated mode so `PYTHONPATH`/user-site import state is not trusted as helper-code authority.

After the audit, NXB-153 itself creates the controlled Cargo environment required by the validation lifecycle, including private target/fetch/vendor/gate roots and offline gate state. Those controlled variables are implementation state, not inherited ambient authority.

## Windows preparation

Canonical entrypoint:

`scripts/prepare-and-validate-nxb-153-windows.ps1`

Windows preparation performs the existing case-insensitive forbidden compiler/Cargo/Python/native-build audit before repository/tool preparation reaches any `rustup` or Cargo installation step.

Bash-specific startup/function variables do not grant shell startup authority in the PowerShell-only Windows path. They are rejected by the canonical Python helper when that helper's cross-platform audit is used, while the PowerShell-native pre-Python guard retains the variables relevant to the Windows execution model.

The PowerShell implementation intentionally duplicates the small pre-Python name policy rather than invoking Python before Python authority has itself been constrained. Values are not printed.

## Windows validation/dependency gates

Canonical dependency runner:

`scripts/nxb-153-windows-dependency-source.ps1`

The dependency runner performs the ambient audit at entry, before it stages controlled `CARGO_HOME`, target or offline variables and before any Cargo gate executes.

Python 3.11+ discovery is tested with `-I`, every direct registry-verifier invocation uses `python -I`, and the metadata verifier subprocess places `-I` before the helper pathname.

The parent immutable-source runner keeps exact-head workspace handles alive while this dependency/environment-bounded gate sequence executes.

## Current native-build reason

The exact NXB-153 lockfile contains `ring 0.17.14`, which depends on the `cc` crate. Therefore native compiler/archive environment overrides are not hypothetical for this dependency graph. They can affect a build even when Cargo.lock and vendored source bytes are stable.

The v2 environment policy consequently rejects the relevant `cc`/compiler flag families rather than limiting the policy to Rust-only variables.

## Remaining acceptance

The environment policy is not final admission by itself. Exact final-head platform evidence must still prove:

- Linux canonical entry wrappers actually start in privileged Bash mode;
- direct invocation without privileged Bash fails closed;
- representative `BASH_ENV` and exported-function injection cannot influence canonical Linux preparation/validation/review before the audit;
- Linux environment self-test/audit runs before preparation and heavy validation under the real canonical flow;
- nested H1/H2 Bash children remain compatible with the privileged-Bash child authority;
- Windows PowerShell environment guard parses and rejects representative exact/prefix/case-variant variables on supported Windows;
- Windows Python 3.11+ isolated-mode invocations work in the canonical dependency flow;
- supported host SDK/toolchain discovery still works with allowed host variables;
- no rejected ambient compiler/Cargo/Python/native-build/Bash variable is silently reintroduced before a heavy gate;
- immutable workspace/dependency source, exact-head security-tool authority, serialization, create-only evidence and object-anchored review all continue to pass on the same exact head.

Host Rust/rustup/cargo/rustc/rustfmt/clippy executable identity is a separate trust boundary. This document does not claim to make a malicious or replaced trusted Rust distribution safe merely by sanitizing environment variables.

PR #89 remains draft/not admitted. Issues #90–#98 remain open. NXB-154 must not use NXB-153 as an admitted implementation base until the exact-head Linux + Windows closure and blocker review complete.
