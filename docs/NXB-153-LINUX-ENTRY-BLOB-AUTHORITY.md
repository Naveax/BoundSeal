# NXB-153 Linux Entry Blob Execution Authority

## Status

This document records a **source-staged, not admitted** NXB-153 Linux entrypoint authority rule.

Canonical Linux preparation, validation and evidence-review entry wrappers must not execute an exact-head inner shell implementation through `source <(git cat-file blob ...)` directly.

Bash process substitution does not make the producer's exit status the `source` command's exit status. A failing producer can therefore be a weaker authority boundary than a pipeline protected by `set -o pipefail`.

## Source-staged contract

The three canonical wrappers now resolve and size-check their exact-head inner Git blob, capture the blob through a sentinel-checked command substitution, independently recompute the Git blob identity of the captured in-memory bytes, and only then source that complete bounded value through shell-builtin `printf`.

Current wrapper blobs:

- `scripts/prepare-and-validate-nxb-153-linux.sh` -> `a6f9aa7caf90e89ae369808eedf67c093535adfd`;
- `scripts/validate-nxb-153-linux.sh` -> `95483dfff5fa848acce0d3d7b8d542053f15a97e`;
- `scripts/review-nxb-153-evidence-linux.sh` -> `1fb240ba83b487cee0847f2a5aadb9b634c5d132`.

Each wrapper requires its selected inner implementation to be a Git blob whose reported size is greater than zero and no larger than **1 MiB** before capture.

The capture appends a non-newline sentinel only after `git cat-file blob` succeeds. After the sentinel is removed, the wrapper passes the exact captured value to `git hash-object --stdin` and requires the returned object ID to equal the originally selected exact-head inner blob.

The wrapper therefore fails if:

- `git cat-file` returns nonzero;
- the sentinel is absent;
- the captured source is empty;
- command-substitution representation changes the selected blob bytes, including loss of an embedded NUL byte;
- the recomputed captured-byte Git object ID differs from the selected exact-head object;
- the committed inner object cannot be re-resolved consistently after successful delegation.

The final process substitution is therefore no longer a Git producer. It is shell-builtin `printf` over an already captured value whose Git object identity has been re-established after Bash representation.

## Other exact-blob execution paths

The Linux immutable-source/H1/H2 paths that stream an exact Git blob directly into `bash` or `python3` use pipelines under `set -euo pipefail`. Their producer failure therefore participates in the pipeline status and is a separate, already fail-closed execution shape.

`scripts/nxb-153-linux-immutable-source.sh` also uses a sentinel-checked bounded blob capture for source text that must be held in a shell variable. Its separately constrained source-envelope helper remains part of the H2 validation chain.

## Why this matters

Exact object identity before execution is not sufficient if the bytes actually consumed by the shell can be a successful prefix of a failed producer stream or can be transformed by the shell's in-memory representation. NXB-153 treats the executed implementation bytes, not merely the earlier object lookup, as part of validation authority.

The captured-byte `hash-object` check adds an explicit representation-integrity gate on top of producer-success/sentinel checks. This hardening removes the known canonical Linux direct-Git process-substitution gap without changing the preserved inner preparation, validator or evidence-review implementations.

## Required runtime proof

Source staging is not Linux PASS. Exact-final-head Linux validation must still prove:

- all three wrappers parse and execute correctly under the supported Bash host;
- clean and dirty Git-status semantics remain unchanged;
- the Python isolated-mode shim remains effective where applicable;
- exact captured-byte Git-object equality succeeds on normal execution;
- a deliberately failing/truncated blob producer cannot become a successful partial inner execution;
- a representation-changing/NUL-bearing synthetic blob is rejected rather than executed as transformed bytes;
- exact inner-object re-verification succeeds after normal delegation;
- full Rust 1.97.1 H2 validation and schema-v2 evidence review remain green on the same exact head.

No GitHub Actions workflow is required or implied by this document. PR #89 remains draft/not admitted until the real Linux + Windows same-head closure completes.