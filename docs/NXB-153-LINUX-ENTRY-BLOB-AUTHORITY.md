# NXB-153 Linux Entry Blob Execution Authority

## Status

This document records a **source-staged, not admitted** NXB-153 Linux entrypoint authority rule.

Canonical Linux preparation, validation and evidence-review entry wrappers must not execute an exact-head inner shell implementation through a pathname-reopened script or an asynchronous `source <(...)` producer after object authority has been established.

The rule addresses two distinct shell boundaries:

1. producer/representation integrity for exact-head Git blob bytes; and
2. ambient Bash startup/function authority before the later environment audit runs.

Source staging is not runtime PASS.

## Current source-staged contract

The three canonical wrappers resolve and size-check their exact-head inner Git blob, capture it through a sentinel-checked command substitution, independently recompute the Git blob identity of the captured in-memory bytes, and execute only that same verified string through Bash builtin `eval`.

Current wrapper/probe blobs:

- `scripts/prepare-and-validate-nxb-153-linux.sh` -> `e78a4d7626977fd511d9acae562519da56c49f27`;
- `scripts/validate-nxb-153-linux.sh` -> `6b343e0cd2cc42888db4276c4e2cb6b035c5ccea`;
- `scripts/review-nxb-153-evidence-linux.sh` -> `77e62d7c79791eb7678c1a81b7272af15eaa5ebf`;
- `scripts/nxb-153-linux-entry-blob-probe.sh` -> `3128cceb3b6892368660620b6c0dd4d9e3b023d4`.

Each wrapper requires its selected inner implementation to be a Git blob whose reported size is greater than zero and no larger than **1 MiB** before capture.

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

All three canonical wrappers and the adversarial probe request privileged Bash in their direct-exec shebang and fail unless `$-` contains `p`.

Canonical invocations are expected to use Bash `-p`. In privileged mode Bash does not consume `BASH_ENV` startup code and does not import exported shell functions from the environment before the script's own authority checks can run.

Preparation and validation wrappers resolve the Bash executable and install a same-shell `bash()` shim that invokes that exact executable with `-p`. This covers Bash children launched by the preserved inner implementation without rewriting the historical inner scripts merely to change their handoff spelling.

The canonical validator also executes the exact-head entry-blob probe through a `set -o pipefail` protected:

`git cat-file blob <probe-object> | <resolved-bash> -p -s ...`

pipeline **before** evaluating the preserved validator inner bytes.

The committed ambient environment guard separately rejects Bash startup/function authority variables together with the existing compiler/Cargo/Python/native-build authority set. Privileged Bash is still required because an environment audit that runs after shell startup cannot retroactively undo startup code that already executed.

## Mandatory adversarial probe

`scripts/nxb-153-linux-entry-blob-probe.sh` stages a concrete adversarial contract for the capture primitive and the three canonical wrappers.

Its primitive self-test creates a temporary Git repository and requires:

- an ordinary synthetic shell blob to survive exact capture with unchanged Git object identity;
- a producer that emits a prefix and exits nonzero to be rejected;
- a producer that exits zero after emitting only a truncated prefix to be rejected by captured-byte Git object mismatch;
- a NUL-bearing Git blob to be rejected after Bash command-substitution representation rather than executed as altered bytes.

The repository-aware probe additionally requires:

- the probe itself and each canonical wrapper working file to equal their exact-head Git blob;
- each wrapper to parse under privileged `bash -p -n`;
- each wrapper to request and require privileged Bash mode;
- no wrapper to retain `source <(` delegation;
- captured-byte `hash-object --stdin` verification to remain present;
- exactly one `builtin eval` in-memory delegation per wrapper.

The validator re-resolves the probe object after validation alongside the preserved inner validator object. The probe is therefore a mandatory exact-head gate rather than an optional diagnostic script.

## Other exact-blob execution paths

The Linux immutable-source/H1/H2 paths that intentionally stream exact Git blobs into `bash` or `python3` use pipelines under `set -euo pipefail`, so producer failure participates in pipeline failure.

Bash child creation from the canonical validator/preparation shell is forced through the privileged-Bash shim. The supported-host runtime proof must still demonstrate that the complete H1/H2 nested Bash chain preserves the intended behavior under this authority.

`scripts/nxb-153-linux-immutable-source.sh` also uses a sentinel-checked bounded blob capture for source text that must be held in a shell variable. Its separately constrained source-envelope helper remains part of the H2 validation chain.

## Why this matters

Exact object identity before execution is not sufficient if the bytes actually consumed by the shell can be a successful prefix of a failed producer stream, can be transformed by Bash representation, or can be affected by startup/function authority before validation begins.

NXB-153 therefore binds the actual in-memory implementation bytes back to the selected Git object, removes the second process-substitution delegation, and establishes privileged Bash before any nested shell authority is accepted.

## Required runtime proof

Exact-final-head Linux validation must still prove:

- all three wrappers parse and execute correctly under the supported Bash host in privileged mode;
- invocation without privileged mode fails closed;
- ambient `BASH_ENV` and exported-function injection cannot influence the canonical wrapper/probe flow;
- the mandatory exact-head entry-blob probe executes successfully through the canonical validator;
- clean and dirty Git-status semantics remain unchanged;
- the Python isolated-mode shim remains effective where applicable;
- exact captured-byte Git-object equality succeeds on normal execution;
- deliberate producer-failure/truncation and NUL-bearing synthetic controls fail closed;
- `builtin eval` preserves the intended positional-argument/same-shell semantics of the preserved inner implementations;
- exact inner/probe object re-verification succeeds after normal delegation;
- nested H1/H2 Bash execution remains compatible with the privileged-child authority;
- full Rust 1.97.1 H2 validation and schema-v2 evidence review remain green on the same exact head.

No GitHub Actions workflow is required or implied by this document. PR #89 remains draft/not admitted until the real Linux + Windows same-head closure completes.
