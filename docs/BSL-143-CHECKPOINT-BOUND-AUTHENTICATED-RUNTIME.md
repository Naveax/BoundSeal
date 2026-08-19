# NXB-143 — Checkpoint-bound authenticated runtime

NXB-143 connects the signed NXB-141 operator contract, the NXB-142 checkpoint store and the existing authenticated live-adapter boundary without introducing automatic broad crawling or destructive methods.

## Execution boundary

The runtime accepts only `GET` and `HEAD` requests already covered by the signed unified operator plan. Before any executor callback is invoked it verifies:

- plan validity and consumed activation continuity;
- exact allowed path-prefix membership;
- discovery depth;
- request-count and response-byte budgets;
- minimum request interval;
- sequential execution;
- dedicated runtime-journal ownership.

The production bridge additionally binds the live connection attempt to HTTPS port 443, the exact plan authority, exact SNI and the declared redirect depth. Secret values remain inside the existing session broker and in-memory vault path.

## Runtime ownership

One runtime process owns a journal through an operating-system file lock. Concurrent owners fail closed before state recovery or request preparation.

The lock file remains at one stable path and inode between runs. Only the operating-system lock is released when the runtime is dropped. A process crash therefore releases ownership without requiring lock-file deletion, and stale diagnostic text in the file does not prevent recovery. Keeping the inode stable also prevents a second process from creating and locking a replacement file while an earlier owner still holds the original inode.

## Write-ahead request journal

Each request uses three immutable files:

1. `prepared` binds the next request index, previous checkpoint hash, method, target hash, depth and clock;
2. `outcome` stores only sanitized execution metadata, body length, response status, audit tails and receipt hashes;
3. `commit` binds the outcome to the exact checkpoint sequence, checkpoint hash and counters.

Files are published with create-new temporary files, explicit synchronization and no-clobber hard links. Canonical JSON bytes are required when reopening the journal.

A crash after `prepared` but before a durable outcome is treated as indeterminate. The request is never retried automatically. Continuation is blocked and only teardown or abort is allowed.

A crash after the outcome and checkpoint but before the commit marker is recoverable: the runtime compares the exact checkpoint counters and writes the missing commit marker. An outcome without a matching checkpoint remains indeterminate.

## Checkpoint accounting

Successful requests increment:

- completed requests;
- total response bytes;
- last response-body bytes;
- maximum observed depth;
- conservatively reserved journal/evidence bytes.

No raw response body, cookie, bearer token, API key or CSRF value is written to the runtime journal.

## Teardown

Completion requires `teardown_pending`. Direct `running -> completed` transitions are rejected by the state engine. The runtime can deprovision an existing external session through the established session/vault lifecycle, verify the teardown receipt and only then append `completed`.

If external-session teardown fails, the runtime attempts an emergency vault purge and records an aborted terminal state. It does not report successful completion.

## Explicit limitations

NXB-143 does not mint scope decisions or transport tickets and does not broaden the signed plan. It does not automatically follow redirects, submit reports, retry indeterminate requests, execute JavaScript or enable destructive HTTP methods.
