# NXB-153 Linux Entry Blob Execution Authority

## Status

This document records a **source-staged, not admitted** NXB-153 Linux entrypoint authority rule.

Canonical Linux preparation, validation, evidence-review and immutable-source entrypoints must not accept implementation bytes through an authority boundary weaker than the exact-head Git object and supported shell-startup contract.

The rule addresses three related boundaries:

1. producer/representation integrity for exact-head Git blob bytes;
2. ambient Bash startup/function authority before later environment audits can run; and
3. the deliberate transition from privileged shell authority into the one non-privileged H2 child that must import the exact runner-created `cp` shim.

Source staging is not runtime PASS.

## Current source-staged contract

The three outer canonical wrappers resolve and size-check their exact-head inner Git blob, capture it through a sentinel-checked command substitution, independently recompute the Git blob identity of the captured in-memory bytes, and execute only that same verified string through Bash builtin `eval`.

Current source blobs:

- `scripts/prepare-and-validate-nxb-153-linux.sh` -> `e78a4d7626977fd511d9acae562519da56c49f27`;
- `scripts/validate-nxb-153-linux.sh` -> `6b343e0cd2cc42888db4276c4e2cb6b035c5ccea`;
- `scripts/review-nxb-153-evidence-linux.sh` -> `77e62d7c79791eb7678c1a81b7272af15eaa5ebf`;
- `scripts/nxb-153-linux-immutable-source.sh` -> `57e99472b09a291479f84c8e73fd1c56b1309837`;
- `scripts/nxb-153-linux-entry-blob-probe.sh` -> `511e7160a0221b4889f3b46b8267894a6b4e195d`;
- `scripts/nxb-153-validation-environment.py` -> `c294c69c72b100efade6e106aa75e36eb97d4c95`.

Each outer wrapper requires its selected inner implementation to be a Git blob whose reported size is greater than zero and no larger than **1 MiB** before capture.

The capture appends a non-newline sentinel only after `git cat-file blob` succeeds. After the sentinel is removed, the wrapper passes the exact captured value to `git hash-object --stdin` and requires the returned object ID to equal the originally selected exact-head inner blob.

The wrapper therefore fails if:

- `git cat-file` returns nonzero;
- the sentinel is absent;
- the captured source is empty;
- command-substitution representation changes the selected blob bytes, including loss of an embedded NUL byte;
- the recomputed captured-byte Git object ID differs from the selected exact-head object;
- the committed inner object cannot be re-resolved consistently after successful delegation.

After this check there is **no second process-substitution source producer**. The exact verified in-memory string is executed directly through `builtin eval`, preserving the intended same-shell sourced-script behavior while removing the earlier asynchronous delegation boundary.

## Privileged Bash startup authority

The preparation, validation and evidence-review wrappers, the immutable-source runner and the entry-blob probe request privileged Bash in their direct-exec shebang and fail unless `$-` contains `p`.

Canonical invocations use Bash `-p`. In privileged mode Bash must not consume `BASH_ENV` startup code or import exported shell functions before the script's own authority checks can run.

Preparation and validation wrappers resolve the Bash executable and install a same-shell `bash()` shim that invokes that exact executable with `-p`. This covers first-level Bash children launched by the preserved inner implementation without rewriting the historical inner scripts merely to change their handoff spelling.

The canonical validator also executes the exact-head entry-blob probe through a `set -o pipefail` protected:

`git cat-file blob <probe-object> | <resolved-bash> -p -s ...`

pipeline before evaluating the preserved validator inner bytes.

The ambient environment guard rejects Bash startup/function authority variables together with the compiler/Cargo/Python/native-build authority set. Privileged Bash remains required because an audit that runs after shell startup cannot retroactively undo startup code that already executed.

## Mandatory selected-host Bash runtime self-test

The exact-head environment helper now turns the central Bash startup assumption into a Linux runtime primitive inside its existing mandatory `self-test`.

Current helper:

`scripts/nxb-153-validation-environment.py`

Current helper blob:

`c294c69c72b100efade6e106aa75e36eb97d4c95`

On Linux the helper self-test:

- resolves the selected Bash executable from the supported-host `PATH` boundary;
- launches only bounded subprocesses with stdin/stdout/stderr detached and a **5 second timeout**;
- creates a private synthetic `BASH_ENV` startup file;
- proves a non-privileged Bash control consumes the synthetic startup file and creates its marker;
- proves `bash -p` does not consume the same startup file and does not create the marker;
- injects a synthetic exported `BASH_FUNC_nxb153_hostile%%` function;
- proves the non-privileged control imports it;
- proves `bash -p` rejects it;
- injects a synthetic exported `BASH_FUNC_cp%%` control;
- proves an ordinary non-privileged Bash child imports the intended trusted-function primitive used by the later H2 handoff;
- uses a minimal synthetic subprocess environment instead of inheriting arbitrary ambient authority into the control fixtures;
- cleans all temporary startup artifacts before self-test success.

This runtime self-test is mandatory through existing exact-head control flow rather than through a new optional wrapper:

- Linux preparation resolves the exact-head environment helper and runs `self-test` before tool installation/receipt publication;
- outer Linux validation resolves the same helper and runs `self-test` before lock-owned heavy validation;
- the immutable-source runner independently resolves the same helper and repeats `self-test` immediately before its ambient audit and trusted-function transition.

The audit policy/result schema remains `nxb-153-compiler-cargo-python-authority-v2`; only the source-staged runtime self-test became stronger.

## Immutable-source entry and trusted-function transition

`scripts/nxb-153-linux-immutable-source.sh` is a canonical entrypoint, not merely an implementation detail reachable only from the outer validator.

The runner independently:

- requires privileged Bash mode at entry;
- resolves the exact-head validation environment helper;
- runs that helper's isolated self-test and ambient audit before constructing any exported function authority;
- resolves the exact-head source-envelope helper;
- captures that Python helper through the producer-success sentinel shape;
- recomputes `git hash-object --stdin` over the captured Bash representation and requires equality with the selected exact-head source-envelope blob before `python3 -I -c` consumes it.

After the audit, the runner deliberately creates and exports one trusted `cp` function. That shim delegates copying to the exact-head bounded Rust snapshot-copy helper and removes itself with `unset -f cp` after its admitted copy invocation. The final H2 inner Bash child is intentionally **non-privileged** so it can import this exact runner-created function.

This non-privileged child is not an ambient-authority exception. Ambient `BASH_ENV` and pre-existing exported-function authority must already have been rejected before the trusted shim is defined or exported. The new Linux runtime self-test proves the selected supported-host Bash distinguishes the privileged rejection behavior from the intended ordinary-child exported-function import primitive.

Runtime acceptance must still demonstrate that the real exact runner-created `cp` shim is the only function authority admitted across that exact-head transition.

## Authority precedence

This document is the canonical authority for Linux outer-entry, preparation-to-validator and immutable-source shell handoff semantics.

Older NXB-153 documentation may describe the historical preparation handoff as streaming the exact validator blob into `bash -s -- '.'`. That wording is superseded for the current source-staged contract. The preserved preparation implementation still spells a bare `bash -s -- '.'` command, but it executes inside the canonical preparation wrapper's trusted `bash()` shim; the actual child process is the already-resolved Bash executable invoked with `-p`.

Therefore the current effective preparation-to-validator handoff is privileged Bash (`<resolved-bash> -p -s -- '.'`). The later immutable-source-to-H2-inner handoff is different by design: it is a resolved ordinary Bash child only after the immutable runner has independently re-audited ambient authority and created its exact trusted `cp` export.

## Mandatory entry-blob adversarial probe

`scripts/nxb-153-linux-entry-blob-probe.sh` remains the concrete exact-blob/source-order probe for the three outer wrappers and canonical immutable-source runner.

Its primitive self-test creates a temporary Git repository and requires:

- an ordinary synthetic shell blob to survive exact capture with unchanged Git object identity;
- a producer that emits a prefix and exits nonzero to be rejected;
- a producer that exits zero after emitting only a truncated prefix to be rejected by captured-byte Git object mismatch;
- a NUL-bearing Git blob to be rejected after Bash command-substitution representation rather than executed as altered bytes.

The repository-aware probe additionally requires for the three outer wrappers:

- working file bytes to equal their exact-head Git blob;
- privileged `bash -p -n` syntax validation;
- privileged direct-entry shebang and runtime requirement;
- no retained `source <(` delegation;
- captured-byte `hash-object --stdin` verification;
- exactly one `builtin eval` in-memory delegation per wrapper.

For the canonical immutable-source runner, the probe additionally requires:

- working bytes equal the exact-head runner blob;
- privileged syntax/direct-entry/runtime requirements;
- captured-byte Git object verification;
- exact-head validation environment helper resolution;
- exactly one canonical environment-audit handoff;
- exactly one trusted `cp()` definition;
- exactly one `unset -f cp` self-removal;
- exactly one `export -f cp`;
- exactly one canonical resolved-Bash non-privileged H2 child handoff;
- exact source-line ordering `environment audit < cp definition < cp self-removal < cp export < child handoff`.

Those source-order checks use exact line signatures and occurrence counts rather than loose substring existence.

The entry-blob probe and the environment-helper Bash runtime self-test are complementary. The former binds source/object/order semantics; the latter proves the selected Linux Bash startup/function primitive at runtime.

## Required runtime proof

Exact-final-head Linux validation must still prove:

- all three outer wrappers and the immutable-source runner parse and execute correctly under the supported Bash host in privileged mode;
- direct invocation without privileged mode fails closed for every canonical privileged entrypoint;
- the new exact-head environment-helper Bash startup self-test executes successfully through preparation, outer validation and immutable-source entry;
- representative real canonical-flow `BASH_ENV` and hostile exported-function injection cannot influence preparation/validation/review before the audit;
- the mandatory exact-head entry-blob probe executes successfully through the canonical validator;
- clean and dirty Git-status semantics remain unchanged;
- Python isolated mode remains effective where applicable;
- exact captured-byte Git-object equality succeeds on normal outer-wrapper and source-envelope execution;
- deliberate producer-failure/truncation and NUL-bearing synthetic controls fail closed;
- `builtin eval` preserves the intended positional-argument/same-shell semantics of the preserved outer inner implementations;
- the immutable runner's post-audit non-privileged H2 child imports the **real intended self-removing trusted `cp` shim** while hostile startup/function authority remains absent;
- the exact audit/function/self-removal/export/handoff order matches supported-host execution;
- exact inner/probe/runner/helper object authority remains stable through normal delegation;
- the complete nested H1/H2 Bash chain preserves the intended authority boundaries;
- full Rust 1.97.1 H2 validation and schema-v2 evidence review remain green on the same exact head.

No GitHub Actions workflow is required or implied by this document. PR #89 remains draft/not admitted until the real Linux + Windows same-head closure completes.
