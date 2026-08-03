#[cfg(test)]
mod tests {
    use super::*;
    use nxb_vault::SameSitePolicy;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::{
        collections::{BTreeMap, VecDeque},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const NOW: i64 = 1_900_000_000;

    struct MockSession;

    struct MockProvider {
        identity: ProviderIdentity,
        values: BTreeMap<String, VecDeque<ProviderSecretMaterial>>,
        begin_count: u64,
        fetch_count: u64,
        finish_outcomes: Vec<ProviderSessionOutcome>,
        fail_fetch: Option<String>,
        fail_finish: bool,
    }

    impl ExternalVaultProvider for MockProvider {
        type Session = MockSession;

        fn identity(&self) -> ProviderIdentity {
            self.identity.clone()
        }

        fn begin(
            &mut self,
            _request: &ProviderSessionRequest,
        ) -> Result<Self::Session, ProviderFailure> {
            self.begin_count += 1;
            Ok(MockSession)
        }

        fn fetch(
            &mut self,
            _session: &mut Self::Session,
            request: &ProviderSecretRequest,
        ) -> Result<ProviderSecretMaterial, ProviderFailure> {
            self.fetch_count += 1;
            if self.fail_fetch.as_deref() == Some(request.provider_handle.as_str()) {
                return Err(ProviderFailure::new("mock_fetch_denied").unwrap());
            }
            self.values
                .get_mut(&request.provider_handle)
                .and_then(VecDeque::pop_front)
                .ok_or_else(|| ProviderFailure::new("mock_secret_missing").unwrap())
        }

        fn finish(
            &mut self,
            _session: Self::Session,
            outcome: ProviderSessionOutcome,
        ) -> Result<(), ProviderFailure> {
            self.finish_outcomes.push(outcome);
            if self.fail_finish {
                return Err(ProviderFailure::new("mock_finish_failed").unwrap());
            }
            Ok(())
        }
    }

    fn provider_identity() -> ProviderIdentity {
        ProviderIdentity {
            provider_id: "mock-provider".into(),
            provider_instance_sha256: sha256_bytes(b"mock-provider-instance"),
            capability_sha256: sha256_bytes(b"read-only-exact-handles"),
        }
    }

    fn specs() -> Vec<ProviderSecretSpec> {
        vec![
            ProviderSecretSpec {
                logical_id: "authorization".into(),
                provider_handle: "apps/example/authorization".into(),
                kind: SecretKind::BearerToken,
                delivery: ProviderDeliverySpec::Header {
                    name: "authorization".into(),
                    prefix_hex: lower_hex(b"Bearer "),
                },
                maximum_value_bytes: 4096,
                required_version_sha256: Some(sha256_bytes(b"version-1")),
            },
            ProviderSecretSpec {
                logical_id: "session-cookie".into(),
                provider_handle: "apps/example/session-cookie".into(),
                kind: SecretKind::Cookie,
                delivery: ProviderDeliverySpec::Cookie {
                    cookie: CookieMetadata {
                        name: "sid".into(),
                        domain: "app.example.com".into(),
                        path: "/app".into(),
                        expires_at_epoch_seconds: Some(NOW + 3_600),
                        secure: true,
                        http_only: true,
                        same_site: SameSitePolicy::Lax,
                    },
                },
                maximum_value_bytes: 4096,
                required_version_sha256: Some(sha256_bytes(b"version-2")),
            },
        ]
    }

    fn plan(public_key: &[u8]) -> ExternalVaultSessionPlan {
        build_plan(public_key, "bootstrap-1", specs()).unwrap()
    }

    fn build_plan(
        public_key: &[u8],
        bootstrap_id: &str,
        secrets: Vec<ProviderSecretSpec>,
    ) -> Result<ExternalVaultSessionPlan, VaultProviderError> {
        ExternalVaultSessionPlan::build(ExternalVaultPlanParameters {
            bootstrap_id: bootstrap_id.into(),
            discovery_plan_sha256: sha256_bytes(b"discovery-plan"),
            target_origin_sha256: sha256_bytes(b"https://app.example.com:443"),
            authority: "app.example.com".into(),
            run_id: "run-1".into(),
            worker_id: "worker-1".into(),
            account_id: "account-1".into(),
            tenant_id: "tenant-1".into(),
            role_id: "role-1".into(),
            provider: provider_identity(),
            secrets,
            created_at_epoch_seconds: NOW,
            expires_at_epoch_seconds: NOW + 300,
            session_expires_at_epoch_seconds: NOW + 1_800,
            activation_public_key: public_key.to_vec(),
        })
    }

    fn certificate(
        plan: &ExternalVaultSessionPlan,
        key_pair: &Ed25519KeyPair,
    ) -> ExternalVaultActivationCertificate {
        let payload = ExternalVaultActivationPayload::template(
            "activation-1",
            plan,
            NOW,
            NOW + 240,
        )
        .unwrap();
        let signature = key_pair.sign(&payload.signing_bytes().unwrap());
        ExternalVaultActivationCertificate {
            payload,
            signature_hex: lower_hex(signature.as_ref()),
        }
    }

    fn provider() -> MockProvider {
        MockProvider {
            identity: provider_identity(),
            values: BTreeMap::from([
                (
                    "apps/example/authorization".into(),
                    VecDeque::from([ProviderSecretMaterial::new(
                        "version-1",
                        b"top-secret-bearer".to_vec(),
                        NOW + 3_600,
                    )
                    .unwrap()]),
                ),
                (
                    "apps/example/session-cookie".into(),
                    VecDeque::from([ProviderSecretMaterial::new(
                        "version-2",
                        b"top-secret-cookie".to_vec(),
                        NOW + 3_600,
                    )
                    .unwrap()]),
                ),
            ]),
            begin_count: 0,
            fetch_count: 0,
            finish_outcomes: Vec::new(),
            fail_fetch: None,
            fail_finish: false,
        }
    }

    fn unique_state_directory(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "nxb-vault-provider-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn consumed(
        plan: &ExternalVaultSessionPlan,
        certificate: &ExternalVaultActivationCertificate,
        key_pair: &Ed25519KeyPair,
        label: &str,
    ) -> ConsumedExternalVaultActivation {
        let directory = unique_state_directory(label);
        let proof = consume_activation_once(
            &directory,
            plan,
            certificate,
            key_pair.public_key().as_ref(),
            NOW + 1,
        )
        .unwrap();
        fs::remove_dir_all(directory).unwrap();
        proof
    }

    #[test]
    fn exact_provider_bootstrap_and_teardown_are_receipted() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[11_u8; 32]).unwrap();
        let plan = plan(key_pair.public_key().as_ref());
        let certificate = certificate(&plan, &key_pair);
        let consumed = consumed(&plan, &certificate, &key_pair, "success");
        let mut provider = provider();
        let mut vault = InMemorySecretVault::new("external-vault").unwrap();
        let mut broker = SessionBroker::new("external-broker").unwrap();

        let provisioned = bootstrap_external_session(
            &plan,
            consumed,
            &mut provider,
            &mut broker,
            &mut vault,
            NOW + 1,
        )
        .unwrap();
        provisioned.receipt().verify().unwrap();
        assert_eq!(provider.begin_count, 1);
        assert_eq!(provider.fetch_count, 2);
        assert_eq!(
            provider.finish_outcomes,
            vec![ProviderSessionOutcome::Committed]
        );
        assert_eq!(vault.secret_count(), 2);
        assert_eq!(provisioned.session().profile.secret_handles.len(), 2);

        let teardown = deprovision_external_session(
            provisioned,
            &mut broker,
            &mut vault,
            NOW + 2,
        )
        .unwrap();
        teardown.verify().unwrap();
        assert_eq!(vault.secret_count(), 0);
    }

    #[test]
    fn provider_identity_mismatch_fetches_nothing() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[12_u8; 32]).unwrap();
        let plan = plan(key_pair.public_key().as_ref());
        let certificate = certificate(&plan, &key_pair);
        let consumed = consumed(&plan, &certificate, &key_pair, "identity");
        let mut provider = provider();
        provider.identity.provider_instance_sha256 = sha256_bytes(b"wrong-instance");
        let mut vault = InMemorySecretVault::new("identity-vault").unwrap();
        let mut broker = SessionBroker::new("identity-broker").unwrap();
        assert!(matches!(
            bootstrap_external_session(
                &plan,
                consumed,
                &mut provider,
                &mut broker,
                &mut vault,
                NOW + 1,
            ),
            Err(VaultProviderError::ProviderIdentityMismatch)
        ));
        assert_eq!(provider.begin_count, 0);
        assert_eq!(provider.fetch_count, 0);
        assert_eq!(vault.secret_count(), 0);
    }

    #[test]
    fn partial_fetch_failure_rolls_back_inserted_values() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[13_u8; 32]).unwrap();
        let plan = plan(key_pair.public_key().as_ref());
        let certificate = certificate(&plan, &key_pair);
        let consumed = consumed(&plan, &certificate, &key_pair, "rollback");
        let mut provider = provider();
        provider.fail_fetch = Some("apps/example/session-cookie".into());
        let mut vault = InMemorySecretVault::new("rollback-vault").unwrap();
        let mut broker = SessionBroker::new("rollback-broker").unwrap();
        assert!(matches!(
            bootstrap_external_session(
                &plan,
                consumed,
                &mut provider,
                &mut broker,
                &mut vault,
                NOW + 1,
            ),
            Err(VaultProviderError::ProviderFetch { .. })
        ));
        assert_eq!(vault.secret_count(), 0);
        assert_eq!(
            provider.finish_outcomes,
            vec![ProviderSessionOutcome::Aborted]
        );
    }

    #[test]
    fn provider_commit_failure_revokes_session_and_secrets() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[14_u8; 32]).unwrap();
        let plan = plan(key_pair.public_key().as_ref());
        let certificate = certificate(&plan, &key_pair);
        let consumed = consumed(&plan, &certificate, &key_pair, "commit-failure");
        let mut provider = provider();
        provider.fail_finish = true;
        let mut vault = InMemorySecretVault::new("commit-vault").unwrap();
        let mut broker = SessionBroker::new("commit-broker").unwrap();
        assert!(matches!(
            bootstrap_external_session(
                &plan,
                consumed,
                &mut provider,
                &mut broker,
                &mut vault,
                NOW + 1,
            ),
            Err(VaultProviderError::ProviderCommit(_))
        ));
        assert_eq!(vault.secret_count(), 0);
        assert_eq!(
            provider.finish_outcomes,
            vec![ProviderSessionOutcome::Committed]
        );
    }

    #[test]
    fn short_lived_or_wrong_version_material_is_denied() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[15_u8; 32]).unwrap();
        let plan = plan(key_pair.public_key().as_ref());
        let certificate = certificate(&plan, &key_pair);
        let consumed = consumed(&plan, &certificate, &key_pair, "expiry");
        let mut provider = provider();
        provider.values.insert(
            "apps/example/authorization".into(),
            VecDeque::from([ProviderSecretMaterial::new(
                "wrong-version",
                b"secret".to_vec(),
                NOW + 10,
            )
            .unwrap()]),
        );
        let mut vault = InMemorySecretVault::new("expiry-vault").unwrap();
        let mut broker = SessionBroker::new("expiry-broker").unwrap();
        assert!(matches!(
            bootstrap_external_session(
                &plan,
                consumed,
                &mut provider,
                &mut broker,
                &mut vault,
                NOW + 1,
            ),
            Err(VaultProviderError::SecretVersionMismatch)
        ));
        assert_eq!(vault.secret_count(), 0);
    }

    #[test]
    fn activation_is_exact_and_single_use() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[16_u8; 32]).unwrap();
        let plan = plan(key_pair.public_key().as_ref());
        let certificate = certificate(&plan, &key_pair);
        let directory = unique_state_directory("single-use");
        consume_activation_once(
            &directory,
            &plan,
            &certificate,
            key_pair.public_key().as_ref(),
            NOW + 1,
        )
        .unwrap();
        assert!(consume_activation_once(
            &directory,
            &plan,
            &certificate,
            key_pair.public_key().as_ref(),
            NOW + 1,
        )
        .is_err());
        let mut tampered = plan.clone();
        tampered.session_expires_at_epoch_seconds += 1;
        tampered.plan_sha256 = tampered.calculate_sha256().unwrap();
        assert!(certificate
            .verify(&tampered, key_pair.public_key().as_ref(), NOW + 1)
            .is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn secret_values_never_enter_requests_receipts_or_debug() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[17_u8; 32]).unwrap();
        let plan = plan(key_pair.public_key().as_ref());
        let certificate = certificate(&plan, &key_pair);
        let consumed = consumed(&plan, &certificate, &key_pair, "redaction");
        let mut provider = provider();
        let mut vault = InMemorySecretVault::new("redaction-vault").unwrap();
        let mut broker = SessionBroker::new("redaction-broker").unwrap();
        let provisioned = bootstrap_external_session(
            &plan,
            consumed,
            &mut provider,
            &mut broker,
            &mut vault,
            NOW + 1,
        )
        .unwrap();
        let material = format!(
            "{:?}{}{}",
            provisioned,
            serde_json::to_string(&plan).unwrap(),
            serde_json::to_string(provisioned.receipt()).unwrap()
        );
        assert!(!material.contains("top-secret-bearer"));
        assert!(!material.contains("top-secret-cookie"));
    }

    #[test]
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
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[18_u8; 32]).unwrap();
        let mut duplicate = specs();
        duplicate.push(duplicate[0].clone());
        assert!(matches!(
            build_plan(
                key_pair.public_key().as_ref(),
                "bootstrap-duplicate",
                duplicate,
            ),
            Err(VaultProviderError::DuplicateSecretSpec)
        ));

        let mut broad = specs();
        let ProviderDeliverySpec::Cookie { cookie } = &mut broad[1].delivery else {
            panic!("expected cookie fixture");
        };
        cookie.domain = "example.com".into();
        assert!(matches!(
            build_plan(
                key_pair.public_key().as_ref(),
                "bootstrap-broad",
                broad,
            ),
            Err(VaultProviderError::InvalidDeliverySpec)
        ));
    }
}
