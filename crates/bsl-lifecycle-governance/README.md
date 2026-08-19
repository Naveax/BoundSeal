# bsl-lifecycle-governance

Deterministic local-only contracts for BSL-84 through BSL-101.

- P13 governs post-freeze maintenance proposals, impact analysis, bounded windows, canonical patch admission and maintenance release certification.
- P14 provides metadata-only archives, bounded retention and redaction, diverse recovery rehearsals and continuity certification.
- P15 requires independent verifier diversity, deterministic evidence sampling, exact decommission steps, zero-live-resource tombstones and lifecycle closure.

The certificate chain is explicit: final assurance and roadmap closure anchor maintenance release; maintenance release anchors continuity; final assurance, roadmap closure, maintenance release, continuity and tombstone roots jointly anchor lifecycle closure.

The crate exposes no socket, resolver, browser, scanner, process, shell, deployment, credential-discovery or destructive-testing API.
