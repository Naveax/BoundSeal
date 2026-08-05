from pathlib import Path

path = Path("crates/nxb-evidence-key-provider/src/lib.rs")
text = path.read_text(encoding="utf-8")

replacements = [
    (
        "use zeroize::{Zeroize, Zeroizing};",
        "use zeroize::Zeroizing;",
    ),
    (
        '''        if bytes.len() != EVIDENCE_SEALING_KEY_BYTES {
            return Err(EvidenceKeyProviderError::InvalidKeyMaterial);
        }''',
        '''        if bytes.len() != EVIDENCE_SEALING_KEY_BYTES {
            bytes.fill(0);
            return Err(EvidenceKeyProviderError::InvalidKeyMaterial);
        }''',
    ),
    (
        '''        activation.signature_hex.replace_range(0..2, "00");''',
        '''        let replacement = if &activation.signature_hex[..2] == "00" {
            "01"
        } else {
            "00"
        };
        activation.signature_hex.replace_range(0..2, replacement);''',
    ),
    (
        '''        assert_eq!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ProviderIdentityMismatch)
        );''',
        '''        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ProviderIdentityMismatch)
        ));''',
    ),
    (
        '''        assert_eq!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ActivationSignatureInvalid)
        );''',
        '''        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ActivationSignatureInvalid)
        ));''',
    ),
    (
        '''        assert_eq!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ProviderFetchFailure(
                "backend_failure".into()
            ))
        );''',
        '''        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ProviderFetchFailure(code))
                if code == "backend_failure"
        ));''',
    ),
    (
        '''        assert_eq!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ProviderTeardownFailure(
                "teardown_failed".into()
            ))
        );''',
        '''        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::ProviderTeardownFailure(code))
                if code == "teardown_failed"
        ));''',
    ),
    (
        '''        assert_eq!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::PlanDigestMismatch)
        );''',
        '''        assert!(matches!(
            acquire_evidence_sealer(plan, activation, &mut provider, now),
            Err(EvidenceKeyProviderError::PlanDigestMismatch)
        ));''',
    ),
    (
        '''        let mut bytes = vec![3_u8; EVIDENCE_SEALING_KEY_BYTES];
        bytes.zeroize();''',
        '''        let mut bytes = vec![3_u8; EVIDENCE_SEALING_KEY_BYTES];
        bytes.fill(0);''',
    ),
]

for old, new in replacements:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one source block, found {count}: {old[:100]!r}")
    text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")
