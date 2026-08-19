# BSL-136 — Signed live operator bridge

BSL-136 connects the exact one-request live orchestrator to the bounded operator and reporting pipeline without broadening the live authorization model.

## Command

The bridge is a separate feature-gated binary:

```text
cargo run -p bsl-core --bin bsl-live-scan --features live-network -- \
  --policy program.toml \
  --plan live-plan.json \
  --activation activation.json \
  --public-key activation-public-key.hex \
  --state-directory .bsl/live-state \
  --output-directory target/bsl-live-scan \
  --enable-live
```

## Security boundary

The command performs exactly the request already bound by the canonical live plan and one-use Ed25519 activation certificate.

It does not:

- create or broaden a live plan;
- follow redirects;
- execute a discovered endpoint;
- inject cookies, bearer tokens, API keys, CSRF tokens, or other session material;
- run active reflection, rate-limit, or authorization-differential probes;
- submit a report automatically;
- persist the raw response body.

The verified response body is retained only in process memory. Its byte length and SHA-256 digest must match the HTTP receipt before passive discovery is allowed.

## Operator integration

For a signed `GET` response with a non-empty body, the bridge:

1. converts passive header, cookie, and cache findings into validated operator findings;
2. parses the verified body through the bounded same-origin discovery pipeline;
3. schedules eligible `GET` or `HEAD` follow-up candidates;
4. stops at the signed request budget of one;
5. emits deterministic JSON, Markdown, and HackerOne manual-review artifacts;
6. emits `live-scan-receipt.json`, binding the activation, live receipt, scheduler, coverage, report, and export manifest hashes.

Every follow-up candidate requires a new exact live plan and a new one-use activation. BSL-136 never turns one activation into a crawl authorization.

## Remaining boundaries

Later milestones may add separately signed multi-request discovery sessions and explicit vault-backed session injection. Those capabilities are not part of BSL-136 and must not be inferred from its report or scheduler output.
