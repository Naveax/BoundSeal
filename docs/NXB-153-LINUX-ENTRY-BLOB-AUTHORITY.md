# NXB-153 Linux Entry Blob Execution Authority

## Status

This document records a **source-staged, not admitted** NXB-153 Linux entrypoint authority rule.

Canonical Linux preparation, validation and evidence-review entry wrappers must not execute an exact-head inner shell implementation through `source <(git cat-file blob ...)` directly.

Bash process substitution does not make the producer's exit status the `source` command's exit status. A failing producer can therefore be a weaker authority boundary than a pipeline protected by `set -o pipefail`.

## Source-staged contract

The three canonical wrappers now resolve and size-check their exact-head inner Git blob, capture the blob through a sentinel-checked command substitution, and only then source the complete bounded in-memory value through shell-builtin `printf`.

Current wrapper blobs:

- `scripts/prepare-and-validate-nxb-153-linux.sh` -> `4e8900c636137a7ee654b69721c1ea83b66867eb`;
- `scripts/validate-nxb-153-linux.sh` -> `dc17bc72a734fc218497213a6447a96bcf3db170`;
- `scripts/review-nxb-153-evidence-linux.sh` -> `67af47ce190ea84208d73276c4dc7a709b8c40f2`.

Each wrapper requires its selected inner implementation to be a Git blob whose reported size is greater than zero and no larger than **1 MiB** before capture.

The capture appends a non-newline sentinel only after `git cat-file blob` succeeds. The wrapper fails if:

- `git cat-file` returns nonzero;
- the sentinel is absent;
- the captured source is empty;
- the committed inner object cannot be re-resolved consistently after successful delegation.

The final process substitution is therefore no longer a Git producer. It is shell-builtin `printf` over the already captured bounded value.

## Other exact-blob execution paths

The Linux immutable-source/H1/H2 paths that stream an exact Git blob directly into `bash` or `python3` use pipelines under `set -euo pipefail`. Their producer failure therefore participates in the pipeline status and is a separate, already fail-closed execution shape.

`scripts/nxb-153-linux-immutable-source.sh` also uses a sentinel-checked bounded blob capture for source text that must be held in a shell variable.

## Why this matters

Exact object identity before execution is not sufficient if the bytes actually consumed by the shell can be a successful prefix of a failed producer stream. NXB-153 treats the executed implementation bytes, not merely the earlier object lookup, as part of validation authority.

This hardening removes the known canonical Linux `source <(git cat-file ...)` producer-status gap without changing the preserved inner preparation, validator or evidence-review implementations.

## Required runtime proof

Source staging is not Linux PASS. Exact-final-head Linux validation must still prove:

- all three wrappers parse and execute correctly under the supported Bash host;
- clean and dirty Git-status semantics remain unchanged;
- the Python isolated-mode shim remains effective where applicable;
- exact inner-object re-verification succeeds on normal execution;
- a deliberately failing/truncated blob producer in the wrapper primitive cannot become a successful partial inner execution;
- full Rust 1.97.1 H2 validation and schema-v2 evidence review remain green on the same exact head.

No GitHub Actions workflow is required or implied by this document. PR #89 remains draft/not admitted until the real Linux + Windows same-head closure completes.