# BSL-6 — Bounded Byte-Stream Fixture

## Purpose

BSL-6 introduces a deterministic byte-stream boundary without enabling operating-system sockets or public network access.

A stream cannot be opened from a URL, hostname, IP address, proxy configuration or arbitrary executor receipt. Opening requires all of the following:

1. a `TransportPermit` produced by the pinned transport contract;
2. a completed `ExecutionReceipt`;
3. the verified `ExecutorAuditChain` containing that exact execution;
4. bounded stream limits;
5. a backend implementing `ByteStreamBackend`.

The permit, receipt and matching executor audit record must agree on ticket, decision, DNS context, binding hash, endpoint fingerprint, transport audit anchor, remote IP, port, scheme, SNI, HTTP Host, redirect depth, outcome and byte counters.

## Security invariants

- Stream handles have no URL or DNS API.
- Backend operations cannot select or replace the destination.
- The stream audit genesis value is the exact executor audit record hash.
- Read and write operations are bounded by per-operation, per-direction, operation-count and total-time limits.
- Cancellation and emergency stop are checked before invoking the backend.
- Read and write deadlines are deterministic values supplied to the backend.
- Late read bytes are discarded rather than returned after a deadline violation.
- Backend over-reporting is converted to an audited terminal backend failure.
- EOF closes only the read half; writes may continue until the write side closes.
- Reset, truncation, timeout, budget exhaustion and backend failure are terminal.
- Raw read or write payloads are never stored in stream receipts or audit records.
- Audit records contain only direction, requested length, transferred length, elapsed time and SHA-256 payload digest.
- `StreamReadResult` intentionally does not implement serialization.

## State model

```text
Open
 ├─ EOF ────────────────> ReadClosed
 ├─ peer write close ───> WriteClosed
 ├─ explicit close ─────> Closed
 ├─ cancellation ───────> Cancelled
 ├─ emergency stop ─────> EmergencyStopped
 ├─ deadline ───────────> TimedOut
 ├─ byte/op budget ─────> BudgetExceeded
 ├─ reset ──────────────> Reset
 ├─ truncated read ─────> Truncated
 └─ backend failure ────> BackendFailed

ReadClosed + peer write close -> Closed
WriteClosed + EOF             -> Closed
```

## Limits

Hard ceilings:

- 64 MiB read per stream;
- 64 MiB written per stream;
- 4 MiB per operation;
- 120 seconds per read, write or total deterministic deadline;
- 100,000 audit-visible stream operations.

Conservative defaults:

- 2 MiB read;
- 256 KiB written;
- 64 KiB per operation;
- 5-second read and write deadlines;
- 30-second total deadline;
- 4,096 operations including the opening audit record.

## Fixture backend

`bsl-stream-fixture` provides `InMemoryDuplex`. It has no socket, resolver, TLS or HTTP implementation. It can deterministically model:

- fragmented reads;
- partial writes;
- read/write backpressure;
- EOF;
- reset;
- timeout;
- truncated streams;
- bounded backend failures;
- explicit close.

The fixture records requested sizes and deadlines. Captured write payloads exist only in fixture memory for regression assertions and are not copied into the audit chain.

## Explicitly excluded

BSL-6 does not add:

- TCP, UDP or QUIC sockets;
- TLS handshakes or certificate validation;
- HTTP framing;
- redirects;
- DNS resolution;
- proxies;
- cookies or sessions;
- scanner adapters;
- real-target execution.

The next layer may build bounded protocol framing on this stream contract, but it must not gain an alternate network path.
