from pathlib import Path
import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"unexpected {label} count: {count}")
    return text.replace(old, new, 1)


provider_path = Path("crates/nxb-vault-provider/src/provider.inc.rs")
provider = provider_path.read_text(encoding="utf-8")
pattern = re.compile(
    r"impl ProviderSecretMaterial \{\n"
    r"    pub fn new\(\n.*?\n"
    r"    \}\n"
    r"\}",
    re.DOTALL,
)
replacement = """impl ProviderSecretMaterial {
    pub fn new(
        version_id: impl Into<String>,
        value: Vec<u8>,
        expires_at_epoch_seconds: i64,
    ) -> Result<Self, VaultProviderError> {
        let value = Zeroizing::new(value);
        let version_id = version_id.into();
        validate_identifier(&version_id, "provider_version_id")?;
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(VaultProviderError::SecretValueSize);
        }
        Ok(Self {
            version_id,
            value,
            expires_at_epoch_seconds,
        })
    }
}"""
provider, count = pattern.subn(replacement, provider, count=1)
if count != 1:
    raise SystemExit(f"unexpected ProviderSecretMaterial impl count: {count}")
provider_path.write_text(provider, encoding="utf-8", newline="\n")

lifecycle_path = Path("crates/nxb-vault-provider/src/lifecycle.inc.rs")
lifecycle = lifecycle_path.read_text(encoding="utf-8")
lifecycle = replace_once(
    lifecycle,
    """            let handle = vault.insert(
                SecretInput {
                    kind: spec.kind,
                    value: std::mem::take(&mut *material.value),
                    binding,
                    delivery: spec.delivery.secret_delivery()?,
                    expires_at_epoch_seconds: Some(material.expires_at_epoch_seconds),
                },
                now_epoch_seconds,
            )?;""",
    """            let delivery = spec.delivery.secret_delivery()?;
            let value = std::mem::take(&mut *material.value);
            let handle = vault.insert(
                SecretInput {
                    kind: spec.kind,
                    value,
                    binding,
                    delivery,
                    expires_at_epoch_seconds: Some(material.expires_at_epoch_seconds),
                },
                now_epoch_seconds,
            )?;""",
    "vault insert block",
)
lifecycle = replace_once(
    lifecycle,
    """    provisioned.receipt.verify()?;
    broker.revoke_session(&provisioned.session.session_id)?;
    let mut revoke_error = None;
    for handle in &provisioned.handles {
        if let Err(error) = vault.revoke_secret(handle) {
            revoke_error.get_or_insert(error);
        }
    }
    if let Some(error) = revoke_error {
        return Err(error.into());
    }
""",
    """    provisioned.receipt.verify()?;
    if let Err(error) = rollback_provisioning(
        Some(&provisioned.session),
        &provisioned.handles,
        broker,
        vault,
    ) {
        return Err(VaultProviderError::TeardownFailed(error));
    }
""",
    "teardown block",
)
lifecycle_path.write_text(lifecycle, encoding="utf-8", newline="\n")

validation_path = Path("crates/nxb-vault-provider/src/validation.inc.rs")
validation = validation_path.read_text(encoding="utf-8")
validation = replace_once(
    validation,
    """    #[error("external-vault teardown receipt is invalid")]
    InvalidTeardownReceipt,
""",
    """    #[error("external-vault teardown failed after attempting all revocations: {0}")]
    TeardownFailed(String),
    #[error("external-vault teardown receipt is invalid")]
    InvalidTeardownReceipt,
""",
    "teardown error marker",
)
validation_path.write_text(validation, encoding="utf-8", newline="\n")

tests_path = Path("crates/nxb-vault-provider/src/tests.rs")
tests = tests_path.read_text(encoding="utf-8")
tests = replace_once(
    tests,
    """    #[test]
    fn duplicate_or_broad_specs_fail_before_provider_use() {
""",
    """    #[test]
    fn teardown_still_revokes_vault_values_when_broker_is_wrong() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[19_u8; 32]).unwrap();
        let plan = plan(key_pair.public_key().as_ref());
        let certificate = certificate(&plan, &key_pair);
        let consumed = consumed(&plan, &certificate, &key_pair, "wrong-broker-teardown");
        let mut provider = provider();
        let mut vault = InMemorySecretVault::new("wrong-broker-vault").unwrap();
        let mut original_broker = SessionBroker::new("original-broker").unwrap();
        let provisioned = bootstrap_external_session(
            &plan,
            consumed,
            &mut provider,
            &mut original_broker,
            &mut vault,
            NOW + 1,
        )
        .unwrap();
        assert_eq!(vault.secret_count(), 2);

        let mut wrong_broker = SessionBroker::new("wrong-broker").unwrap();
        assert!(matches!(
            deprovision_external_session(
                provisioned,
                &mut wrong_broker,
                &mut vault,
                NOW + 2,
            ),
            Err(VaultProviderError::TeardownFailed(_))
        ));
        assert_eq!(vault.secret_count(), 0);
    }

    #[test]
    fn duplicate_or_broad_specs_fail_before_provider_use() {
""",
    "final test marker",
)
tests_path.write_text(tests, encoding="utf-8", newline="\n")
