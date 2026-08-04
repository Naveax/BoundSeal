# NXB-145 — Signed live-run launch host

NXB-145 binds the verified NXB-139 external session, NXB-141 unified operator, NXB-143 request transaction runtime and NXB-144 resumable queue into one supervised live-run launch boundary.

## Signed launch graph

The `LiveRunLaunchBundle` records and re-verifies the exact hashes and identities for:

- the unified operator plan and component binding;
- the NXB-144 runner manifest;
- the external-vault plan and bootstrap receipt;
- the session-injection manifest and external session;
- the policy snapshot, passive operator configuration and live-adapter limits;
- the discovery plan, HTTPS origin, provider identity and account partition;
- the secret-handle root/count and bounded DNS resolver contract.

The bundle is self-hashed and activated by an Ed25519 certificate. Launch activation is consumed through a durable no-replay marker before runtime, runner or network ownership is created.

## Lifecycle ownership

NXB-145 adopts an already provisioned `ProvisionedExternalSession` from NXB-139. It does not silently fetch a replacement session because the NXB-141 plan binds the exact bootstrap receipt, session ID and secret-handle root.

The host owns the provisioned session, broker and in-memory vault until ordered teardown. Normal drop attempts emergency deprovisioning. A process restart cannot fabricate an equivalent authenticated session; without explicit reattachment of the exact in-memory lifecycle state, execution remains fail-closed.

## Per-request authorization

For each exact NXB-144 queue head:

1. a bounded resolver returns one context, address set, selected address and TTL;
2. the result is checked against the signed resolver ID, address-count and TTL limits;
3. `ScopeGateway` validates policy, public destination, DNS pin/rebinding and request budgets;
4. `PinnedTransportCoordinator` issues a one-use ticket bound to the selected IP, SNI, Host and DNS context;
5. NXB-144 invokes the NXB-143 authenticated request transaction;
6. passive response discovery occurs only in memory;
7. the DNS/ticket context is released on every terminal path.

A DNS failure, gateway denial, missing ticket or indeterminate execution never removes the queue head as a successful request. The host moves runner and runtime into teardown instead.

## Completion and failure

Successful terminal state requires:

- runner `teardown_pending`;
- runtime `teardown_pending`;
- external session and every vault secret deprovisioned;
- a verified external teardown receipt;
- runtime completion bound to the teardown receipt hash;
- runner terminal checkpoint bound to the completed runtime checkpoint.

If external teardown fails, the runtime is aborted and the runner records an aborted terminal checkpoint. No successful completion receipt is produced.

## Control plane

The `nxb-live-run-host` binary is networkless. It can build and verify launch bundles, create activation payload templates, verify signed activation certificates and consume launch activations. Actual live execution uses the library API and an explicitly supplied `LiveDnsResolver` implementation.

## Explicit limitations

NXB-145 does not discover credentials, import browser cookies, broaden scope, execute active probes, follow redirects, issue destructive methods, persist response bodies, retry indeterminate requests or submit reports. It does not reconstruct authenticated provider/session state after process loss.
