# NXB-148 — Production encrypted evidence sealer

## Purpose

NXB-148 adds the first concrete encrypted persistent evidence store. It accepts only previously validated and redacted `EvidenceRecord` values from `nxb-knowledge-reporting`; it is not a raw HTTP capture store and does not permit secret-bearing request or response material.

## Cryptographic boundary

- Algorithm: AES-256-GCM through the workspace's existing `ring` dependency.
- Key input: an externally supplied 256-bit `EvidenceSealingKey`.
- Key handling: the input key is non-serializable, redacted from `Debug`, and zeroized when consumed or dropped.
- Nonce: a fresh 96-bit nonce from `SystemRandom` for every sealing operation.
- Authenticated associated data binds:
  - evidence identifier;
  - evidence content SHA-256;
  - policy snapshot SHA-256;
  - provenance SHA-256;
  - knowledge-audit tail SHA-256.
- The envelope records independent SHA-256 values for canonical plaintext and authenticated ciphertext.

The key itself is never written to the evidence directory. Key acquisition and rotation remain external operator responsibilities.

## Persistent-store contract

`EncryptedEvidenceStore` owns a dedicated directory and fails closed when it encounters:

- a symlink or non-directory store root;
- a non-empty directory during initialization;
- unexpected files, directories or malformed evidence names;
- temporary files left by interrupted publication;
- duplicate evidence identifiers;
- non-canonical JSON envelopes or plaintext;
- policy, provenance, evidence-ID, content-digest or audit-tail drift;
- wrong key identifiers, wrong key material or modified ciphertext;
- per-envelope or total-store budget exhaustion.

Publication uses a create-new temporary file, full file synchronization, a create-only hard link to the final name, directory synchronization where supported, and removal of the temporary link. Existing evidence is never overwritten.

## Canonical envelope

Every `.nxbseal` file contains canonical pretty JSON with a trailing newline. The envelope includes only cryptographic metadata and hexadecimal authenticated ciphertext. Opening a record requires all of the following to agree:

1. file name and evidence identifier;
2. store policy snapshot and authenticated binding;
3. active key identifier;
4. ciphertext SHA-256;
5. AES-GCM authentication tag;
6. canonical plaintext bytes;
7. reconstructed `EvidenceInput` redaction validation;
8. original evidence content digest, serialized length and content-addressed identifier.

## Verification manifest

`verify_all` decrypts and validates every entry in sorted evidence-ID order and emits a deterministic manifest containing file hashes, key identifiers, content hashes, plaintext/ciphertext hashes, byte accounting and a manifest SHA-256.

## Explicit exclusions

NXB-148 does not implement:

- key derivation from passwords;
- storage of keys beside ciphertext;
- cloud KMS, HSM, password-manager or OS credential-store adapters;
- raw cookie, authorization header, token or response-body persistence;
- automatic report submission;
- unrestricted scanning or active exploitation.

## Validation

The permanent NXB-148 workflow runs on Ubuntu and Windows and requires canonical `Cargo.lock`, Rust formatting, package check, all-target Clippy with warnings denied, and adversarial tests for round trips, duplicate publication, wrong keys, wrong key identifiers, tampering, policy drift, non-canonical envelopes, interrupted publication and redacted key diagnostics.
