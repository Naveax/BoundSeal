#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvisionedSecretReceipt {
    pub logical_id_sha256: String,
    pub provider_handle_sha256: String,
    pub provider_version_sha256: String,
    pub vault_handle_sha256: String,
    pub kind: SecretKind,
    pub delivery_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalVaultBootstrapReceipt {
    pub version: u32,
    pub plan_sha256: String,
    pub activation_certificate_sha256: String,
    pub discovery_plan_sha256: String,
    pub target_origin_sha256: String,
    pub provider_id: String,
    pub provider_instance_sha256: String,
    pub capability_sha256: String,
    pub session_id_sha256: String,
    pub secret_count: u64,
    pub provisioned_secrets: Vec<ProvisionedSecretReceipt>,
    pub secret_binding_root_sha256: String,
    pub session_audit_tail: String,
    pub vault_audit_tail: String,
    pub completed_at_epoch_seconds: i64,
    pub receipt_sha256: String,
}

impl ExternalVaultBootstrapReceipt {
    pub fn verify(&self) -> Result<(), VaultProviderError> {
        if self.version != EXTERNAL_VAULT_RECEIPT_VERSION
            || self.secret_count == 0
            || self.secret_count as usize != self.provisioned_secrets.len()
            || self.completed_at_epoch_seconds <= 0
        {
            return Err(VaultProviderError::InvalidReceipt);
        }
        validate_identifier(&self.provider_id, "provider_id")?;
        for (value, field) in [
            (&self.plan_sha256, "plan_sha256"),
            (
                &self.activation_certificate_sha256,
                "activation_certificate_sha256",
            ),
            (&self.discovery_plan_sha256, "discovery_plan_sha256"),
            (&self.target_origin_sha256, "target_origin_sha256"),
            (
                &self.provider_instance_sha256,
                "provider_instance_sha256",
            ),
            (&self.capability_sha256, "capability_sha256"),
            (&self.session_id_sha256, "session_id_sha256"),
            (
                &self.secret_binding_root_sha256,
                "secret_binding_root_sha256",
            ),
            (&self.session_audit_tail, "session_audit_tail"),
            (&self.vault_audit_tail, "vault_audit_tail"),
            (&self.receipt_sha256, "receipt_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        for secret in &self.provisioned_secrets {
            for (value, field) in [
                (&secret.logical_id_sha256, "logical_id_sha256"),
                (&secret.provider_handle_sha256, "provider_handle_sha256"),
                (&secret.provider_version_sha256, "provider_version_sha256"),
                (&secret.vault_handle_sha256, "vault_handle_sha256"),
                (&secret.delivery_sha256, "delivery_sha256"),
            ] {
                validate_sha256(value, field)?;
            }
        }
        if self.secret_binding_root_sha256 != hash_serializable(&self.provisioned_secrets)? {
            return Err(VaultProviderError::ReceiptBindingMismatch);
        }
        let mut material = self.clone();
        material.receipt_sha256.clear();
        if self.receipt_sha256 != hash_serializable(&material)? {
            return Err(VaultProviderError::ReceiptDigestMismatch);
        }
        Ok(())
    }
}

pub struct ProvisionedExternalSession {
    session: SessionMetadata,
    handles: Vec<SecretHandle>,
    receipt: ExternalVaultBootstrapReceipt,
}

impl ProvisionedExternalSession {
    pub fn session(&self) -> &SessionMetadata {
        &self.session
    }

    pub fn handles(&self) -> &[SecretHandle] {
        &self.handles
    }

    pub fn receipt(&self) -> &ExternalVaultBootstrapReceipt {
        &self.receipt
    }
}

impl fmt::Debug for ProvisionedExternalSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedExternalSession")
            .field("session_id_sha256", &sha256_bytes(self.session.session_id.as_bytes()))
            .field("secret_count", &self.handles.len())
            .field("handles", &"<opaque vault handles>")
            .field("receipt", &self.receipt)
            .finish()
    }
}

pub fn bootstrap_external_session<P: ExternalVaultProvider>(
    plan: &ExternalVaultSessionPlan,
    consumed_activation: ConsumedExternalVaultActivation,
    provider: &mut P,
    broker: &mut SessionBroker,
    vault: &mut InMemorySecretVault,
    now_epoch_seconds: i64,
) -> Result<ProvisionedExternalSession, VaultProviderError> {
    plan.verify(now_epoch_seconds)?;
    validate_consumed_activation(plan, &consumed_activation, now_epoch_seconds)?;
    let provider_identity = provider.identity();
    provider_identity.validate()?;
    if provider_identity != plan.provider {
        return Err(VaultProviderError::ProviderIdentityMismatch);
    }

    let session_request = ProviderSessionRequest {
        bootstrap_id_sha256: sha256_bytes(plan.bootstrap_id.as_bytes()),
        plan_sha256: plan.plan_sha256.clone(),
        discovery_plan_sha256: plan.discovery_plan_sha256.clone(),
        target_origin_sha256: plan.target_origin_sha256.clone(),
        authority: plan.authority.clone(),
        scheme: plan.scheme.clone(),
        run_id: plan.run_id.clone(),
        worker_id: plan.worker_id.clone(),
        account_id: plan.account_id.clone(),
        tenant_id: plan.tenant_id.clone(),
        role_id: plan.role_id.clone(),
        requested_secret_count: plan.secrets.len() as u64,
        session_expires_at_epoch_seconds: plan.session_expires_at_epoch_seconds,
    };
    let mut provider_session = provider
        .begin(&session_request)
        .map_err(|failure| VaultProviderError::ProviderBegin(failure.code().into()))?;
    let mut handles = Vec::new();
    let mut provisioned = Vec::new();
    let mut created_session: Option<SessionMetadata> = None;

    let provision_result = (|| {
        for spec in &plan.secrets {
            let request = ProviderSecretRequest {
                logical_id: spec.logical_id.clone(),
                provider_handle: spec.provider_handle.clone(),
                kind: spec.kind,
                maximum_value_bytes: spec.maximum_value_bytes,
                required_version_sha256: spec.required_version_sha256.clone(),
            };
            let mut material = provider.fetch(&mut provider_session, &request).map_err(|failure| {
                VaultProviderError::ProviderFetch {
                    logical_id_sha256: sha256_bytes(spec.logical_id.as_bytes()),
                    code: failure.code().into(),
                }
            })?;
            validate_material(plan, spec, &material, now_epoch_seconds)?;
            let provider_version_sha256 = sha256_bytes(material.version_id.as_bytes());
            let binding = SecretBinding {
                run_id: plan.run_id.clone(),
                worker_id: plan.worker_id.clone(),
                account_id: plan.account_id.clone(),
                tenant_id: plan.tenant_id.clone(),
                role_id: plan.role_id.clone(),
                allowed_hosts: BTreeSet::from([plan.authority.clone()]),
                allowed_schemes: BTreeSet::from([plan.scheme.clone()]),
            };
            let delivery = spec.delivery.secret_delivery()?;
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
            )?;
            provisioned.push(ProvisionedSecretReceipt {
                logical_id_sha256: sha256_bytes(spec.logical_id.as_bytes()),
                provider_handle_sha256: sha256_bytes(spec.provider_handle.as_bytes()),
                provider_version_sha256,
                vault_handle_sha256: sha256_bytes(handle.as_str().as_bytes()),
                kind: spec.kind,
                delivery_sha256: hash_serializable(&spec.delivery)?,
            });
            handles.push(handle);
        }

        let session = broker.create_session(
            SessionProfile {
                run_id: plan.run_id.clone(),
                worker_id: plan.worker_id.clone(),
                account_id: plan.account_id.clone(),
                tenant_id: plan.tenant_id.clone(),
                role_id: plan.role_id.clone(),
                allowed_hosts: BTreeSet::from([plan.authority.clone()]),
                allowed_schemes: BTreeSet::from([plan.scheme.clone()]),
                secret_handles: handles.clone(),
                expires_at_epoch_seconds: plan.session_expires_at_epoch_seconds,
            },
            vault,
            now_epoch_seconds,
        )?;
        created_session = Some(session);
        Ok::<(), VaultProviderError>(())
    })();

    if let Err(error) = provision_result {
        let finish = provider.finish(provider_session, ProviderSessionOutcome::Aborted);
        let rollback = rollback_provisioning(created_session.as_ref(), &handles, broker, vault);
        if let Err(rollback_error) = rollback {
            return Err(VaultProviderError::RollbackFailed(rollback_error));
        }
        if let Err(failure) = finish {
            return Err(VaultProviderError::ProviderAbort(failure.code().into()));
        }
        return Err(error);
    }

    let session = match created_session.clone() {
        Some(session) => session,
        None => {
            let finish = provider.finish(provider_session, ProviderSessionOutcome::Aborted);
            let rollback =
                rollback_provisioning(created_session.as_ref(), &handles, broker, vault);
            if let Err(rollback_error) = rollback {
                return Err(VaultProviderError::RollbackFailed(rollback_error));
            }
            if let Err(failure) = finish {
                return Err(VaultProviderError::ProviderAbort(failure.code().into()));
            }
            return Err(VaultProviderError::SessionNotCreated);
        }
    };

    let receipt_result = (|| {
        let mut receipt = ExternalVaultBootstrapReceipt {
            version: EXTERNAL_VAULT_RECEIPT_VERSION,
            plan_sha256: plan.plan_sha256.clone(),
            activation_certificate_sha256: consumed_activation.activation_certificate_sha256,
            discovery_plan_sha256: plan.discovery_plan_sha256.clone(),
            target_origin_sha256: plan.target_origin_sha256.clone(),
            provider_id: plan.provider.provider_id.clone(),
            provider_instance_sha256: plan.provider.provider_instance_sha256.clone(),
            capability_sha256: plan.provider.capability_sha256.clone(),
            session_id_sha256: sha256_bytes(session.session_id.as_bytes()),
            secret_count: provisioned.len() as u64,
            secret_binding_root_sha256: hash_serializable(&provisioned)?,
            provisioned_secrets: provisioned,
            session_audit_tail: broker.audit().tail_hash().to_string(),
            vault_audit_tail: vault.audit().tail_hash().to_string(),
            completed_at_epoch_seconds: now_epoch_seconds,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = hash_serializable(&receipt)?;
        receipt.verify()?;
        Ok::<ExternalVaultBootstrapReceipt, VaultProviderError>(receipt)
    })();
    let receipt = match receipt_result {
        Ok(receipt) => receipt,
        Err(error) => {
            let finish = provider.finish(provider_session, ProviderSessionOutcome::Aborted);
            let rollback =
                rollback_provisioning(created_session.as_ref(), &handles, broker, vault);
            if let Err(rollback_error) = rollback {
                return Err(VaultProviderError::RollbackFailed(rollback_error));
            }
            if let Err(failure) = finish {
                return Err(VaultProviderError::ProviderAbort(failure.code().into()));
            }
            return Err(error);
        }
    };

    if let Err(failure) = provider.finish(provider_session, ProviderSessionOutcome::Committed) {
        let rollback = rollback_provisioning(created_session.as_ref(), &handles, broker, vault);
        if let Err(rollback_error) = rollback {
            return Err(VaultProviderError::RollbackFailed(rollback_error));
        }
        return Err(VaultProviderError::ProviderCommit(failure.code().into()));
    }

    Ok(ProvisionedExternalSession {
        session,
        handles,
        receipt,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalVaultTeardownReceipt {
    pub version: u32,
    pub bootstrap_receipt_sha256: String,
    pub session_id_sha256: String,
    pub revoked_secret_count: u64,
    pub session_audit_tail: String,
    pub vault_audit_tail: String,
    pub completed_at_epoch_seconds: i64,
    pub receipt_sha256: String,
}

impl ExternalVaultTeardownReceipt {
    pub fn verify(&self) -> Result<(), VaultProviderError> {
        if self.version != EXTERNAL_VAULT_TEARDOWN_VERSION
            || self.revoked_secret_count == 0
            || self.completed_at_epoch_seconds <= 0
        {
            return Err(VaultProviderError::InvalidTeardownReceipt);
        }
        for (value, field) in [
            (
                &self.bootstrap_receipt_sha256,
                "bootstrap_receipt_sha256",
            ),
            (&self.session_id_sha256, "session_id_sha256"),
            (&self.session_audit_tail, "session_audit_tail"),
            (&self.vault_audit_tail, "vault_audit_tail"),
            (&self.receipt_sha256, "receipt_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        let mut material = self.clone();
        material.receipt_sha256.clear();
        if self.receipt_sha256 != hash_serializable(&material)? {
            return Err(VaultProviderError::TeardownDigestMismatch);
        }
        Ok(())
    }
}

pub fn deprovision_external_session(
    provisioned: ProvisionedExternalSession,
    broker: &mut SessionBroker,
    vault: &mut InMemorySecretVault,
    now_epoch_seconds: i64,
) -> Result<ExternalVaultTeardownReceipt, VaultProviderError> {
    provisioned.receipt.verify()?;
    if let Err(error) = rollback_provisioning(
        Some(&provisioned.session),
        &provisioned.handles,
        broker,
        vault,
    ) {
        return Err(VaultProviderError::TeardownFailed(error));
    }
    let mut receipt = ExternalVaultTeardownReceipt {
        version: EXTERNAL_VAULT_TEARDOWN_VERSION,
        bootstrap_receipt_sha256: provisioned.receipt.receipt_sha256,
        session_id_sha256: sha256_bytes(provisioned.session.session_id.as_bytes()),
        revoked_secret_count: provisioned.handles.len() as u64,
        session_audit_tail: broker.audit().tail_hash().to_string(),
        vault_audit_tail: vault.audit().tail_hash().to_string(),
        completed_at_epoch_seconds: now_epoch_seconds,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = hash_serializable(&receipt)?;
    receipt.verify()?;
    Ok(receipt)
}
