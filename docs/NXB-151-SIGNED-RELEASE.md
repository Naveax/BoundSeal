# NXB-151 Signed Single-Binary Release Manifest

## Purpose

The signed release manifest binds one exact `nxb` executable, its CycloneDX SBOM, checksum manifest and source Git commit into one externally signed Ed25519 document.

The product never generates, imports or stores a release private key. Signing occurs in an external trusted process. `nxb` only creates the canonical signing payload and verifies a supplied signature against an operator-selected public key.

## Commands

Create an unsigned canonical template:

```text
nxb release manifest-template \
  --release-id <lowercase-release-id> \
  --source-commit <40-character-git-sha> \
  --platform <windows|linux> \
  --architecture x86-64 \
  --binary <nxb.exe|nxb> \
  --sbom <cyclonedx-json> \
  --checksums <SHA256SUMS> \
  --generated-at <UTC-RFC3339> \
  --output <release-manifest.json> \
  [--json]
```

The generated document contains:

- canonical release manifest;
- canonical signing payload as lowercase hexadecimal;
- signing-payload SHA-256;
- an empty `signature_hex` field.

The external signer signs the exact decoded `signing_payload_hex` bytes with Ed25519 and writes the lowercase 64-byte signature into `signature_hex` without changing any other field or formatting.

Verify the signed document and bound artifacts:

```text
nxb release verify-manifest \
  --document <signed-release-manifest.json> \
  --public-key <ed25519-public-key.hex> \
  --binary <nxb.exe|nxb> \
  --sbom <cyclonedx-json> \
  --checksums <SHA256SUMS> \
  [--json]
```

## Exit-code and diagnostic contract

| Operation | Failure code | Diagnostic code |
|---|---:|---|
| Manifest template | 60 | `NXB151-RELEASE-MANIFEST-TEMPLATE-FAILED` |
| Manifest verification | 61 | `NXB151-RELEASE-MANIFEST-VERIFY-FAILED` |

JSON failures are emitted only to stderr through the existing bounded diagnostic schema.

## Manifest binding

The manifest binds:

- manifest schema version;
- release ID;
- product identity `NXBounty`;
- exact Cargo package version;
- exact lowercase 40-character source commit;
- platform and architecture;
- exact single-binary file name, size and SHA-256;
- exact SBOM file name, size and SHA-256;
- exact checksum-manifest file name, size and SHA-256;
- operator-supplied UTC generation timestamp;
- self-consistent manifest SHA-256.

The Linux binary must be named exactly `nxb`. The Windows binary must be named exactly `nxb.exe`. A helper or second executable cannot be substituted.

## Artifact limits

| Artifact | Maximum size |
|---|---:|
| `nxb` / `nxb.exe` | 512 MiB |
| CycloneDX SBOM | 32 MiB |
| checksum manifest | 1 MiB |
| signed release document | 64 KiB |

All input paths are checked for symbolic links and Windows reparse points. Every artifact must be one non-empty regular file.

## SBOM boundary

The SBOM must be JSON and contain:

```text
bomFormat = CycloneDX
specVersion
components array
```

The manifest binds the exact SBOM bytes rather than a normalized representation.

## Checksum boundary

The checksum manifest is canonical LF-terminated UTF-8 text. Each line uses:

```text
<lowercase-sha256><two spaces><file-name>
```

File names cannot contain directories. Duplicate names, CRLF, NUL bytes, malformed hashes and overlong lines are rejected. The manifest must include entries matching the exact binary and SBOM SHA-256 values.

## Signature boundary

Verification requires:

- a 32-byte Ed25519 public key encoded as lowercase hexadecimal;
- a 64-byte signature encoded as lowercase hexadecimal;
- exact signing-payload hex and SHA-256 equality;
- successful Ed25519 verification over the canonical manifest bytes;
- canonical pretty JSON with one trailing LF;
- exact local artifact equality.

The public key is the external trust anchor selected by the installer, release verifier or operator. The private key never enters the NXBounty process.

## Installer requirement

The Windows installer must not install or upgrade `nxb.exe` merely because a checksum matches. It must first run the equivalent of `nxb release verify-manifest` against:

- the candidate `nxb.exe`;
- candidate CycloneDX SBOM;
- candidate checksum manifest;
- signed release document;
- pinned trusted release public key.

Installer publication, upgrade and rollback evidence must record the verified source commit, manifest SHA-256, signature SHA-256 and executable SHA-256.

## Tests

Unit tests cover:

- canonical template construction;
- externally signed Ed25519 round trip;
- binary tamper rejection;
- signature tamper rejection;
- checksum-manifest mismatch rejection.

CLI integration tests execute the real `nxb` binary and cover:

- template creation;
- external signature insertion;
- signed verification;
- single-binary filename enforcement;
- binary tamper rejection;
- wrong-public-key rejection;
- machine-readable diagnostics and exit codes 60/61.

## Non-goals

This layer does not:

- generate or persist release private keys;
- perform code signing or Authenticode signing;
- upload releases;
- create Git tags;
- publish GitHub Releases;
- install software;
- download artifacts;
- access the network.

Those operations remain external and may proceed only after this manifest verification succeeds.

## Validation status

Source, tests and documentation are present on the NXB-151 draft branch. No compiler, Clippy, Linux or Windows validation pass is claimed until the pinned Rust 1.97.1 matrix completes on one unchanged exact head.
