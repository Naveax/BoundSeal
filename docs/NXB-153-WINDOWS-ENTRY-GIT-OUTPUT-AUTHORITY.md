# NXB-153 Windows Entry Git-Output Authority

## Status

This document records the current **source-staged, not admitted** Windows entrypoint Git-output availability contract for NXB-153.

The source implementation was introduced at commit:

`b3762f604191c024e3cd55a4b9055a03f1845f03`

No supported Windows/NTFS/PowerShell runtime PASS is claimed by this source staging.

## Finding closed at source level

The three canonical Windows entry surfaces previously invoked `git status --porcelain=v1 --untracked-files=all` directly and allowed PowerShell to retain the complete stdout sequence before cleanliness rejection:

- `scripts/prepare-and-validate-nxb-153-windows.ps1`;
- `scripts/validate-nxb-153-windows.ps1`;
- `scripts/review-nxb-153-evidence-windows.ps1`.

That meant the H2-internal bounded Git proxy did not protect independent preparation, validation and evidence-review cleanliness captures.

The canonical entrypoints now share one bounded outer implementation with exact Git blob:

`ab8383d4281ebc147dfe8305a926dd862699cef4`

The historical/full implementations are preserved byte-for-byte at:

- `scripts/prepare-and-validate-nxb-153-windows-inner.ps1` -> `b8874331a06496a7c77e6d6bd8ce99c7762b7c35`;
- `scripts/validate-nxb-153-windows-inner.ps1` -> `835e7b77dccbec99aa1f3b32600e18ee09730a43`;
- `scripts/review-nxb-153-evidence-windows-inner.ps1` -> `65b4538186cc449608d1362367902bce0ee84bed`.

The outer wrapper resolves the real Git application before proxy installation, exact-head resolves and pins the selected preserved inner implementation, installs a temporary bounded global `git` function, delegates to the preserved implementation and re-verifies both HEAD and the pinned inner Git object before success.

Nested canonical Windows entrypoints preserve and restore the prior global Git function, so preparation can delegate to the validator without discarding the outer authority chain.

## Bounded Git process contract

For Git invocations passing through the canonical Windows entry wrapper:

- stdout is streamed from `Diagnostics.Process` rather than retained without a bound;
- maximum stdout bytes: **64 MiB**;
- maximum decoded stdout records: **4,096**;
- stdout decoding is strict UTF-8;
- stderr is inherited rather than retained by the proxy;
- stdout must make progress within **300,000 ms / 5 minutes** for each asynchronous read;
- after stdout closes, the child must exit within **30,000 ms / 30 seconds**;
- byte-limit, record-limit or timeout failure attempts recursive process termination and fails closed;
- the child exit code is copied to `$LASTEXITCODE` so existing caller checks remain effective.

The wrapper self-test proves normal Git version delegation and deliberately forces both one-record and four-byte rejection before running the preserved inner implementation.

These limits cover the independent preparation/validation/review cleanliness paths as well as the other bare Git invocations in those preserved scripts.

## H2 Git-output layer update

The nested Windows H2 Git-output guard was updated in the same source commit. Its current exact Git blob is:

`scripts/nxb-153-windows-immutable-source-git-output-inner.ps1` -> `c92a612c2e7921191beb64d1c60a0798fe3fb7ae`

This supersedes the earlier `7ffbaadb69ecffec8fcc9961c585fcb3644df422` Git-output guard blob wherever older authority notes still list that blob as current.

The H2 guard retains the **64 MiB / 4,096 record** stdout envelope and now additionally applies the same **5 minute read-inactivity** and **30 second post-stdout exit** timeouts. It resolves the real Git application before defining its local H2 proxy, so an outer canonical entry wrapper can remain installed while the H2 layer safely narrows authority inside its own scope.

The H2 guard still exact-object verifies the next enumeration layer and removes its local Git proxy during cleanup.

## Separate direct-child I/O / exit blocker

The entry/H2 Git hardening above does **not** cover three direct `Diagnostics.Process` paths deeper in the Windows source/dependency chain. Their former `ReadToEndAsync()` parent-memory retention has been removed, but static review shows that their complete child lifecycle is not yet availability-bounded:

1. the isolated registry verifier performs synchronous `StandardInput.Write($InputText)` and then unbounded `WaitForExit()`;
2. exact-head `git archive` performs synchronous stdout `Read(...)` in the archive loop and then unbounded `WaitForExit()`;
3. tar extraction performs synchronous archive `CopyTo(...)` into child stdin and then unbounded `WaitForExit()`.

Therefore merely changing `WaitForExit()` to a timed overload would be incomplete. Source closure must bound **pipe progress and exit**.

The intended follow-on contract is aligned with the already staged entry/H2 process policy:

- each child pipe operation must make progress within **300,000 ms / 5 minutes**;
- after pipe completion/closure, the child must exit within **30,000 ms / 30 seconds**;
- existing byte/count envelopes remain independently enforced;
- timeout or limit failure attempts recursive process-tree termination;
- cleanup/disposal follows bounded termination handling and remains fail-closed;
- inherited stdout/stderr behavior remains unchanged for the paths already hardened against parent retention.

This section records a **remaining source blocker**, not a completed implementation. Registry verifier, Git archive and tar extraction require code hardening before NXB-153 can be admitted.

## What this does not prove

Source staging does not prove PowerShell scoping, process-tree termination or timing behavior on the supported Windows host. Real exact-head Windows validation must still demonstrate at least:

- outer global Git proxy installation/restoration across prepare -> validate nesting;
- local H2 Git proxy shadowing and cleanup while the outer wrapper remains installed;
- 64 MiB and 4,096-record fail-closed behavior;
- read-inactivity timeout and post-stdout exit timeout behavior;
- inherited stderr behavior;
- recursive child termination on timeout/limit failure;
- clean/dirty repository semantics and `$LASTEXITCODE` compatibility;
- exact-head inner-object pinning and final HEAD/object re-verification;
- bounded registry-verifier / Git-archive / tar pipe-I/O and exit behavior after that source patch lands;
- failure/cancellation cleanup without weakening the existing destination-broker, source, dependency or evidence authority chains.

## Admission boundary

Current schema-v2 evidence intentionally remains:

`host_rust_toolchain_identity = version_pinned_object_identity_pending`

PR #89 remains draft/not admitted. Issues #90-#98 remain open until the direct-child source blocker is closed, real exact-final-head Linux + Windows execution completes, schema-v2 evidence is reviewed and guarded dual-platform closure succeeds. NXB-154 must not use NXB-153 as an admitted implementation base before that closure.