# NXB-129 — End-to-End Orchestrator and CLI

NXB-129 binds the NXB-128 live passive adapter to a CLI workflow without enabling network access by default.

## Default-build commands

- `live-plan`: creates a deterministic, networkless plan bound to policy bytes, exact HTTPS URL, selected/resolved public IP set, GET/HEAD, DNS observation metadata, one request and an Ed25519 public-key identity.
- `verify-live-plan`: verifies plan integrity and validity.
- `live-activation-template`: emits canonical activation signing bytes for an external Ed25519 signer.
- `verify-live-activation`: verifies the signed certificate against the exact plan.

These commands never open a network connection.

## Live command

`live-run` exists only when `nxb-core` is compiled with `--features live-network`. It additionally requires:

- explicit `--enable-live`;
- an unexpired signed activation certificate;
- exact policy, plan and activation digest agreement;
- an exact public IP set and selected IP;
- a one-use activation ledger marker;
- scope gateway approval and a one-use connection ticket;
- HTTPS/443 and GET/HEAD only.

The command does not follow redirects, send credentials, send cookies, send request bodies, crawl, mutate inputs or execute exploit payloads.

## Output

The live output includes:

- the NXB-128 metadata-only receipt;
- header, cookie and cache-policy findings;
- finding IDs and orchestrator receipt hashes;
- no response body, cookie value, authorization value or other secret.

Full TLS analyzer integration remains blocked until the controlled integration lab exports certificate validity and trusted-root metadata. That is assigned to NXB-130.

## Release limitation

A controlled live smoke transcript has not yet been produced. NXB-129 must remain a draft until that transcript and the NXB-130 adversarial lab pass.
