# NXB-153 Windows Entry Git-Output Authority

## Status

This document records the current **source-staged, not admitted** Windows process-output availability contract for NXB-153.

The canonical Windows entry Git-output guard was introduced at commit:

`b3762f604191c024e3cd55a4b9055a03f1845f03`

The deeper direct-child pipe/lifecycle hardening was source-staged by:

- `836b7e82d93157b2da1ba4d61d89b4ae31d343c5` for isolated registry-verifier stdin/exit supervision;
- `f9193e251ad3fe39ae42f831c15b26de0ca935e3` for Git-archive stdout and tar-extraction stdin/exit supervision.

No supported Windows/NTFS/PowerShell runtime PASS is claimed by this source staging.

## Canonical Windows entry Git-output authority

The three canonical Windows entry surfaces previously invoked `git status --porcelain=v1 --untracked-files=all` directly and allowed PowerShell to retain the complete stdout sequence before cleanliness rejection:

- `scripts/prepare-and-validate-nxb-153-windows.ps1`;
- `scripts/validate-nxb-153-windows.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`.

The canonical entrypoints now share one bounded outer implementation with exact Git blob:

`ab8383d4281ebc147dfe8305a926dd862699cef4`

The historical/full implementations are preserved byte-for-byte at:

- `scripts/prepare-and-validate-nxb-153-windows-inner.ps1` -> `b8874331a06496a7c77e6d6bd8ce99c7762b7c35`;
- `scripts/validate-nxb-153-windows-inner.ps1` -> `835e7b77dccbec99aa1f3b32600e18ee09730a43`;
- `scripts/review-nxb-153-evidence-windows-inner.ps1` -> `65b4538186cc449608d1362367902bce0ee84bed`.

The outer wrapper resolves the real Git application before proxy installation, exact-head resolves and pins the selected preserved inner implementation, installs a temporary bounded global `git` function, delegates to the preserved implementation and re-verifies both HEAD and the pinned inner Git object before success.

Nested canonical Windows entrypoints preserve and restore the prior global Git function, so preparation can delegate to the validator without discarding the outer authority chain.

### Bounded entry Git process contract

For Git invocations passing through the canonical Windows entry wrapper:

- stdout is streamed from `Diagnostics.Process` rather than retained without a bound;
- maximum stdout bytes: **64 MiB**;
- maximum decoded stdout records: **4,096**;
- stdout decoding is strict UTF-8;
- stderr is inherited rather than retained by the proxy;
- stdout must make progress within **300,000 ms / 5 minutes** for each asynchronous read;
- after stdout closes, the child must exit within **30,000 ms / 30 seconds**;
- byte-limit, record-limit or timeout failure attempts recursive process termination and fails closed;
- child exit status is copied to `$LASTEXITCODE` so existing caller checks remain effective.

The wrapper self-test proves normal Git version delegation and deliberately forces both one-record and four-byte rejection before running the preserved inner implementation.

## H2 Git-output layer

The nested Windows H2 Git-output guard exact Git blob is:

`scripts/nxb-153-windows-immutable-source-git-output-inner.ps1` -> `c92a612c2e7921191beb64d1c60a0798fe3fb7ae`

This supersedes the earlier `7ffbaadb69ecffec8fcc9961c585fcb3644df422` Git-output guard blob wherever older authority notes still list that blob as current.

The H2 guard retains the **64 MiB / 4,096-record** stdout envelope and applies the same **5 minute read-inactivity** and **30 second post-stdout exit** timeouts. It resolves the real Git application before defining its local H2 proxy, so an outer canonical entry wrapper can remain installed while the H2 layer safely narrows authority inside its own scope.

The H2 guard still exact-object verifies the next enumeration layer and removes its local Git proxy during cleanup.

## Direct-child pipe / exit authority

The three deeper `Diagnostics.Process` paths no longer retain the previously identified `.NET ReadToEndAsync()` parent-memory captures, and their complete child pipe/exit lifecycle is now source-bounded.

Current exact blobs:

- `scripts/nxb-153-windows-dependency-source.ps1` -> `76734e3f5ab9adbf2c9e509ff4be08427da57aa3`;
- `scripts/nxb-153-windows-immutable-source-inner.ps1` -> `664930b3b62f54b57345ff387fabce7a8171f45f`.

### Registry metadata verifier

The isolated registry verifier still redirects stdin only and inherits stdout/stderr. The parent now:

- performs `StandardInput.WriteAsync(...)` instead of synchronous `Write(...)`;
- requires the write to complete within **300,000 ms / 5 minutes**;
- performs bounded `FlushAsync()` under the same inactivity limit;
- closes stdin only after the bounded write/flush completes;
- requires child exit within **30,000 ms / 30 seconds** after stdin closes;
- on failure/timeout, `finally` attempts recursive `Kill(true)` and bounded reap before process disposal.

The parent still retains no verifier stdout/stderr string.

### Exact-head Git archive

Git archive still redirects only binary stdout and inherits stderr. The parent now:

- performs chunked `ReadAsync(...)` from Git stdout;
- requires each read to make progress within **300,000 ms / 5 minutes**;
- preserves the existing **1 GiB** archive byte ceiling;
- writes admitted bytes into the pinned create-new archive stream;
- requires Git exit within **30,000 ms / 30 seconds** after stdout closes;
- attempts recursive kill plus bounded reap in cleanup if the child remains live.

### Tar extraction

Tar extraction still redirects only stdin from the already bounded pinned archive and inherits stdout/stderr. The parent now:

- reads the local pinned archive in bounded chunks;
- writes each chunk with `WriteAsync(...)` to tar stdin;
- requires each child-pipe write to complete within **300,000 ms / 5 minutes**;
- applies the same bound to `FlushAsync()`;
- closes stdin only after all admitted archive bytes are delivered;
- requires tar exit within **30,000 ms / 30 seconds** after stdin closes;
- attempts recursive kill plus bounded reap on failure/timeout before cleanup completes.

Static exact-head review confirms the former synchronous `StandardInput.Write(...)`, child-pipe `CopyTo(...)` and parameterless `WaitForExit()` forms are absent from these source-staged paths. Local file-stream reads/writes remain ordinary bounded-object filesystem operations and are not redirected child-pipe retention surfaces.

## What this does not prove

Source staging does not prove PowerShell/.NET process timing, cancellation or process-tree behavior on the supported Windows host. Real exact-head Windows validation must still demonstrate at least:

- outer global Git proxy installation/restoration across prepare -> validate nesting;
- local H2 Git proxy shadowing and cleanup while the outer wrapper remains installed;
- 64 MiB and 4,096-record fail-closed behavior;
- read-inactivity timeout and post-stdout exit timeout behavior;
- inherited stderr behavior;
- recursive child termination on timeout/limit failure;
- clean/dirty repository semantics and `$LASTEXITCODE` compatibility;
- exact-head inner-object pinning and final HEAD/object re-verification;
- registry-verifier stalled-stdin, nonzero-exit and cleanup behavior;
- Git-archive stalled-stdout, byte-limit, nonzero-exit and cleanup behavior;
- tar stalled-stdin, nonzero-exit and cleanup behavior;
- failure/cancellation cleanup without weakening the existing destination-broker, source, dependency or evidence authority chains.

## Admission boundary

Current schema-v2 evidence intentionally remains:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

The known direct-child source blocker is now source-hardened, but PR #89 remains draft/not admitted. Issues #90-#98 remain open until the exact final head completes real supported Linux + Windows execution, schema-v2 evidence review and guarded dual-platform closure. NXB-154 must not use NXB-153 as an admitted implementation base before that closure.