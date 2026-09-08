# NXB-153 Validation Environment Authority

## Status

This document records the ambient-process environment boundary for NXB-153 validation.

The controls described here are **source-staged, not admitted**. Real exact-head Linux and supported Windows execution is still required before any platform PASS or NXB-153 admission claim.

The purpose of this contract is to prevent exact-head validation from consuming immutable workspace/dependency bytes while the operator process silently changes Git repository/object/config authority, compiler, Cargo, Python, Bash startup, target, runner or native-build behavior through ambient environment variables.

## Threat model

The contract addresses avoidable ambient authority such as:

- `GIT_*` repository/object/config/process overrides, including `GIT_DIR`, `GIT_WORK_TREE`, `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_CONFIG_*` and `GIT_EXEC_PATH`;
- `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `RUSTFLAGS` and related Rust compiler/documentation overrides;
- `RUSTUP_*` toolchain/distribution overrides;
- `CARGO_HOME`, `CARGO_TARGET_DIR`, encoded Rust flags and Cargo build/profile/source/registry/target/runner configuration families;
- `PYTHONPATH`, `PYTHONHOME` and startup/import-path injection into Python authority helpers;
- native compiler/archive/linker overrides used by build scripts, including `CC`, `CXX`, `AR`, `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LD`, `LDFLAGS`, `RANLIB`, MSVC `CL`/`_CL_`, `CRATE_CC_NO_DEFAULTS` and target-specific variants;
- `BINDGEN_EXTRA_CLANG_ARGS` and target-specific variants;
- Bash startup/behavior controls `BASH_ENV`, `BASHOPTS`, `BASH_COMPAT`, `SHELLOPTS`, `POSIXLY_CORRECT` and exported shell-function environment entries matching `BASH_FUNC_*`.

This is not a claim that the complete host operating system, Git installation or Rust installation is adversarially reproducible. A compromised kernel, administrator, hypervisor, trusted Git/Rust distribution, platform SDK or every host tool simultaneously remains outside this contract. Host-tool executable identity remains an explicit admission consideration rather than being disguised as an environment-variable property.

## Canonical policy

Canonical cross-platform policy implementation:

`scripts/nxb-153-validation-environment.py`

Current helper blob:

`d3c4a27064468bba6d6247cb1c7767eead4abfe8`

The helper uses case-insensitive variable-name matching so Windows spelling/casing does not create a different security contract.

The helper never prints blocked variable **values**. Only names may be reported, avoiding accidental disclosure of registry credentials, tokens or other process secrets.

Policy identifier remains:

`nxb-153-compiler-cargo-python-authority-v2`

The result schema identifier is retained for compatibility. The exact committed helper object, not the label alone, is the authority. The current source strengthens the forbidden-name set by rejecting the complete `GIT_*` family and extends the self-test with representative Git repository/object/config variables and a case-variant control.

## Pre-Git authority boundary on Linux

The Python audit cannot protect a Git operation that already happened. Canonical Linux entrypoints therefore reject ambient `GIT_*` variables **before their first exact-head Git resolution**.

The following direct canonical entrypoints perform that pre-Git gate immediately after confirming privileged Bash mode:

- `scripts/prepare-and-validate-nxb-153-linux.sh`;
- `scripts/validate-nxb-153-linux.sh`;
- `scripts/review-nxb-153-evidence-linux.sh`;
- `scripts/nxb-153-linux-immutable-source.sh`;
- `scripts/nxb-153-linux-entry-blob-probe.sh`.

This matters because Git itself treats environment variables such as `GIT_DIR`, `GIT_WORK_TREE`, object-directory/alternate-object settings, configuration injection and executable-path settings as authority. In particular, an ambient `GIT_DIR` can redirect `git rev-parse HEAD` away from the repository selected by the caller even after `cd` into the intended working tree.

The pre-Git gate rejects names, not values. It therefore fails before `rev-parse`, `cat-file`, `hash-object`, `ls-tree` or `archive` can consume attacker-selected Git repository/object/config authority. The later exact-head Python environment audit repeats the broader `GIT_*` rejection before deeper children and heavy validation.

The exact-head entry-blob probe also requires the three outer wrappers and immutable-source runner to contain this pre-Git guard, making its presence part of the source-staged canonical contract rather than a convention.

## Linux Bash startup runtime primitive

On Linux, the helper's mandatory `self-test` performs bounded host-Bash startup tests in addition to the name-policy checks.

The runtime primitive is Linux-only. Windows behavior of the helper remains the policy self-test/audit path.

The Linux primitive:

- resolves the selected `bash` application from the supported-host `PATH` boundary;
- runs every child with stdin/stdout/stderr detached to bounded null streams and a **5 second timeout**;
- creates a private temporary `BASH_ENV` fixture that writes a marker and exports a synthetic variable;
- proves a non-privileged Bash control consumes that `BASH_ENV` fixture, so the negative test is not vacuous;
- proves `bash -p` does **not** consume the same `BASH_ENV` fixture and does not create its marker;
- injects a synthetic `BASH_FUNC_nxb153_hostile%%` environment entry;
- proves a non-privileged Bash control imports the synthetic exported function;
- proves `bash -p` rejects that same exported-function authority;
- injects a synthetic trusted `BASH_FUNC_cp%%` control and proves an ordinary non-privileged Bash child imports it, matching the host primitive intentionally used by the immutable-source H2 handoff;
- uses a minimal synthetic environment for those controls rather than inheriting arbitrary ambient Bash authority into the test fixture;
- removes all temporary files through `TemporaryDirectory` before the self-test can report success.

The synthetic controls do **not** modify the repository, installed Bash or installed Git.

This runtime primitive is mandatory on all current Linux admission paths that need to trust Bash startup/function semantics:

- preparation resolves the exact-head environment helper and runs `self-test` before tool installation/receipt publication;
- outer validation resolves the same helper and runs `self-test` before lock-owned heavy validation;
- the immutable-source runner independently repeats the exact-head helper `self-test` immediately before its ambient audit and trusted-function transition;
- standalone evidence review independently resolves the exact-head helper, validates its blob/type/size authority, runs `python3 -I - self-test` before semantic review, and re-resolves the helper object before returning success.

A self-test PASS is still not final Linux admission. It proves the selected supported-host Bash primitive at runtime; the complete exact-head preparation/validation/review/H1/H2 chain must still execute successfully on the final head.

## Privileged Bash boundary on Linux

An environment audit that executes after Bash startup cannot undo startup code that has already run. NXB-153 therefore does **not** rely on the Python audit alone for Linux shell entry authority.

Canonical Linux preparation, validation and evidence-review wrappers require privileged Bash mode (`-p`). Their direct-exec shebangs request privileged Bash, and each wrapper verifies the `p` shell option before accepting the shell as canonical authority.

The preparation/validation wrappers also resolve the Bash executable and force Bash children launched by the preserved inner implementations through `-p`. The exact-head entry-blob adversarial probe is executed by the canonical validator through a `pipefail`-protected `<resolved-bash> -p -s` pipeline before inner validation.

Privileged Bash prevents `BASH_ENV` startup processing and exported-function import before the script's later environment audit. The strengthened environment helper self-test dynamically verifies those two selected-host Bash primitives on Linux rather than leaving them as documentation-only assumptions.

The environment audit then independently rejects those ambient variables, together with the `GIT_*` family, so their presence is visible as an admission failure rather than silently ignored.

Canonical Linux blob/startup authority is documented in:

`docs/NXB-153-LINUX-ENTRY-BLOB-AUTHORITY.md`

## Allowed host discovery

The policy intentionally does not reject every environment variable.

For example, `PATH`, proxy/TLS variables and Visual Studio/Windows SDK discovery variables `INCLUDE`, `LIB` and `LIBPATH` are not currently rejected merely for existing. Those are part of the supported-host/toolchain boundary rather than operator-selectable exact-source overrides in this contract.

This distinction is deliberate. Blindly deleting or rejecting the complete environment would make supported Windows toolchain discovery unreliable without actually proving toolchain identity.

## Linux preparation

Canonical entrypoint:

`scripts/prepare-and-validate-nxb-153-linux.sh`

Before the first exact-head Git resolution, Linux preparation rejects every ambient `GIT_*` variable. After exact-head helper resolution and before `rustup toolchain install` or either `cargo install` begins, Linux preparation:

1. begins under privileged Bash authority;
2. passes the pre-Git `GIT_*` authority gate;
3. resolves `scripts/nxb-153-validation-environment.py` from the exact-head committed Git object;
4. executes its self-test with `python3 -I`, including the Linux Bash startup runtime primitive and representative Git-variable rejection controls;
5. executes its ambient-environment audit with `python3 -I`;
6. fails before tool mutation/receipt publication if the policy or startup primitive is violated.

Thus a tooling receipt cannot be intentionally prepared under one of the rejected Git/compiler/Cargo/Python/native-build/Bash authority variables, and the selected Linux Bash must satisfy the staged privileged/non-privileged startup semantics before preparation proceeds.

## Linux validation

Canonical outer entrypoint:

`scripts/validate-nxb-153-linux.sh`

Canonical immutable runner:

`scripts/nxb-153-linux-immutable-source.sh`

Both canonical entries reject ambient `GIT_*` before their first Git authority operation. The outer validator then executes the exact-head entry-blob probe under privileged Bash and evaluates only captured/OID-verified preserved validator bytes. The preserved validator resolves the exact-head environment helper and runs its self-test/audit before dependency acquisition or heavy Cargo gates.

The exact-head immutable snapshot must contain the environment and registry authority helpers as regular tracked files. Before dependency acquisition or heavy Cargo gates, the child validation flow runs the environment self-test/audit and the registry verifier self-test.

The immutable-source runner independently resolves the same exact-head environment helper and repeats both self-test and ambient audit immediately before defining/exporting the one intended trusted `cp` function and launching its deliberately non-privileged H2 child.

Python security/registry helpers are executed with `python3 -I` isolated mode so `PYTHONPATH`/user-site import state is not trusted as helper-code authority.

After the audit, NXB-153 itself creates the controlled Cargo environment required by the validation lifecycle, including private target/fetch/vendor/gate roots and offline gate state. Those controlled variables are implementation state, not inherited ambient authority.

## Linux evidence review

Canonical entrypoint:

`scripts/review-nxb-153-evidence-linux.sh`

Evidence review is intentionally safe to invoke independently of the host/process that created Linux evidence. It therefore cannot rely on a startup primitive proved only by an earlier validation run.

The canonical review wrapper:

1. requires privileged Bash and rejects ambient `GIT_*` before its first Git operation;
2. resolves the exact-head environment helper as a canonical blob within the 1 MiB implementation envelope;
3. runs that exact helper through the already-resolved `python3 -I - self-test` path before semantic review;
4. evaluates only the existing captured/OID-verified semantic-review inner source; and
5. re-resolves both the review inner object and environment-helper object before returning success.

Thus the review host must itself satisfy the selected-host Bash startup/function primitive before object-anchored evidence review can succeed.

## Pre-Git authority boundary on Windows

The same ordering rule applies on Windows: pinning the selected `git.exe` cannot make an earlier Git invocation safe if the child inherits ambient repository/object/config authority.

Current source-staged Windows authority surfaces reject every environment-variable name beginning with `GIT_`, case-insensitively, before their first exact-head Git operation:

- `scripts/prepare-and-validate-nxb-153-windows.ps1`;
- `scripts/validate-nxb-153-windows.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`;
- `scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1`;
- `scripts/review-nxb-153-windows-admission.ps1`;
- `scripts/review-nxb-153-windows-admission-complete.ps1`;
- `scripts/nxb-153-windows-host-git-lifetime-probe.ps1`.

These early PowerShell gates report names only, never values. They exist before `rev-parse HEAD`, exact-head object lookup or working-tree hashing. The shared Python environment helper later repeats the complete `GIT_*` family rejection before deeper validation work.

Canonical Windows Git-output/lifetime details and current exact blobs are documented in:

`docs/NXB-153-WINDOWS-ENTRY-GIT-OUTPUT-AUTHORITY.md`

## Windows preparation

Canonical entrypoint:

`scripts/prepare-and-validate-nxb-153-windows.ps1`

Windows preparation now performs two distinct source-staged environment boundaries:

1. the canonical outer PowerShell entry rejects ambient `GIT_*`, case-insensitively, before its first exact-head Git operation;
2. after exact-head authority is established, the existing pre-Python/compiler/Cargo/Python/native-build policy and exact-head shared helper audit continue to reject later ambient authority before `rustup` or Cargo preparation reaches heavy tool mutation.

The Bash startup subprocess controls are Linux-only and therefore do not add a Bash dependency to the PowerShell-only Windows path. Bash-specific variable names remain part of the cross-platform forbidden-name policy.

The early Windows `GIT_*` gate is now source-aligned across the canonical outer entry, process-evidence writer, subordinate/complete admission and host-Git lifetime probe. Runtime admission must still prove those controls on supported Windows rather than infer correctness from source text.

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

The environment policy and source guards are not final admission by themselves. Exact final-head platform evidence must still prove:

- all canonical Linux privileged entrypoints parse and execute correctly under the supported Bash host;
- direct invocation without privileged Bash fails closed for every canonical privileged entrypoint;
- representative `GIT_DIR`, object-directory/alternate-object and config-injection variables are rejected before the first exact-head Git operation on every canonical Linux entrypoint;
- clean exact-head Git resolution/object lookup remains unchanged after the Linux pre-Git gate;
- the exact-final-head environment helper self-test actually executes successfully in preparation, outer validation, immutable-source entry and standalone evidence review;
- representative real canonical-flow `BASH_ENV` and exported-function injection cannot influence preparation/validation/review before the audit;
- the intended self-removing trusted `cp` shim is the only function authority admitted across the immutable-source non-privileged H2 transition;
- nested H1/H2 Bash children remain compatible with the privileged-Bash child authority;
- representative `GIT_DIR`, `GIT_WORK_TREE`, object-directory/alternate-object and `GIT_CONFIG_*` variables are rejected before the first exact-head Git operation on every canonical Windows authority surface listed above;
- clean supported-Windows execution still resolves the intended exact HEAD/object database after the pre-Git gate;
- Windows PowerShell environment guard parses and rejects representative exact/prefix/case-variant compiler/Cargo/Python/native-build variables after exact-head authority is established;
- Windows Python 3.11+ isolated-mode invocations work in the canonical dependency flow;
- supported host SDK/toolchain discovery still works with allowed host variables;
- no rejected ambient Git/compiler/Cargo/Python/native-build/Bash variable is silently reintroduced before a heavy gate;
- immutable workspace/dependency source, exact-head security-tool authority, serialization, create-only evidence and object-anchored review all continue to pass on the same exact head.

Host Git/Rust/rustup/cargo/rustc/rustfmt/clippy executable identity is a separate trust boundary. This document does not claim to make a malicious or replaced trusted distribution safe merely by sanitizing environment variables.

PR #89 remains draft/not admitted. Issues #90–#98 remain open. NXB-154 must not use NXB-153 as an admitted implementation base until the exact-head Linux + Windows closure and blocker review complete.
