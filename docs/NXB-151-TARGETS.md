# NXB-151 Fail-Closed Target Profiles

## Purpose

The `nxb target` command group turns one operator-approved HTTPS origin and a bounded set of path prefixes into an immutable local target profile. Target management is networkless: it performs no DNS lookup, socket creation, HTTP request, browser discovery, proxy import or credential access.

This layer does not grant authorization. It records a narrow local description that later planning stages must intersect with a separately validated program policy and operator authorization.

## Supported commands

```text
nxb target create \
  --workspace <absolute-workspace> \
  --id <lowercase-slug> \
  --name <display-name> \
  --origin <https-origin> \
  [--include-path <absolute-prefix>]... \
  [--exclude-path <absolute-prefix>]... \
  [--json]

nxb target list \
  --workspace <absolute-workspace> \
  [--include-disabled] \
  [--json]

nxb target show \
  --workspace <absolute-workspace> \
  --id <lowercase-slug> \
  [--json]

nxb target disable \
  --workspace <absolute-workspace> \
  --id <lowercase-slug> \
  --reason <operator-hold|program-ended|scope-removed|authorization-expired> \
  [--json]
```

## Exit-code contract

| Operation | Failure code |
|---|---:|
| Target create | 50 |
| Target list | 51 |
| Target show | 52 |
| Target disable | 53 |

Errors are emitted using the stable prefix `NXB-TARGET-<code>`.

## Immutable storage model

Profiles and disable receipts are stored under the protected workspace `targets` directory:

```text
targets/<target-id>.json
targets/<target-id>.disabled.json
```

The profile is create-only and is never overwritten by target management. Disabling a target publishes a separate create-only receipt containing:

- receipt schema version;
- exact target ID;
- SHA-256 of the canonical immutable profile;
- bounded disable reason;
- UTC disable timestamp.

A repeated disable operation is idempotent only when the existing receipt validates against the exact profile. A receipt without its profile, an identity/file-name mismatch, a digest mismatch, an unexpected file, a non-file entry, a symlink or a Windows reparse point causes fail-closed rejection.

## Origin boundary

A target origin must be one canonical HTTPS origin:

```text
https://example.org
https://example.org:8443
```

The following are rejected:

- HTTP or any non-HTTPS scheme;
- username or password components;
- paths, queries or fragments;
- wildcard or backslash syntax;
- IPv4 or IPv6 literals;
- missing or malformed DNS labels;
- localhost and reserved/local suffixes including `.local`, `.internal`, `.invalid`, `.test`, `.example` and `.home.arpa`.

Port 443 is omitted from canonical storage. A non-default HTTPS port remains explicit. Target creation does not resolve the host and does not claim that it is public or authorized.

## Path-prefix boundary

A target contains at most 64 include prefixes and 64 exclude prefixes. Each prefix is at most 512 bytes and must:

- begin with exactly one `/`;
- contain no backslash, wildcard, percent encoding, query, fragment, whitespace or control character;
- contain no `.` or `..` segment;
- omit a trailing slash unless the path is `/`.

If no include prefix is supplied, `/` is used. Duplicate rules are rejected. An excluded prefix must be strictly inside at least one included prefix and cannot remove the complete included prefix. Excluding `/` is prohibited.

## Read-only method boundary

The target profile fixes the only methods available to later product planning:

```text
GET
HEAD
OPTIONS
```

Target management cannot add write methods. Later policy, authorization, activation, gateway and runtime layers may further reduce this set but cannot expand it without a separate reviewed contract.

## Workspace and migration prerequisites

Every target operation requires:

- an absolute canonical workspace path;
- valid private workspace permissions or protected Windows ACLs;
- an existing protected `targets` directory;
- a stable migration state with no pending journal, backup or applied marker.

Pending migration blocks target operations before any profile read or write.

## Bounded directory contract

The target directory supports at most 1,024 profiles and their matching disable receipts. Every entry must be a private regular file with one supported canonical name. Unknown files and nested directories are rejected rather than ignored.

## Validation sources

Unit and CLI integration tests cover:

- create, list, show and disable lifecycle;
- active-only and include-disabled views;
- unsafe origin rejection;
- ambiguous and out-of-scope path rejection;
- pending migration rejection;
- profile tamper rejection;
- disable-receipt tamper rejection.

Platform acceptance harnesses:

```text
bash scripts/validate-nxb-151-target-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-target-windows.ps1
```

The Linux harness additionally checks private file modes. The Windows harness additionally injects a broad Everyone allow ACE and requires fail-closed rejection. Successful harnesses bind their result to the exact Git head and the single `nxb` executable SHA-256 under `target/nxb-validation/`.

## Explicit non-goals

This layer does not:

- import HackerOne or other platform scopes;
- prove ownership or authorization;
- resolve DNS or validate destination IPs;
- import cookies, tokens, browser state or proxy captures;
- start scanning or live execution;
- submit reports;
- reactivate a disabled target.

Those capabilities require later bounded contracts. A disabled target remains disabled because the immutable receipt is never deleted or overwritten by this command group.

## Validation status

Source, unit tests, CLI integration tests, documentation and local harnesses are present on the NXB-151 draft branch. No compiler, Clippy, Windows or Linux acceptance pass is claimed until the pinned Rust 1.97.1 and platform harnesses complete on the same exact head.
