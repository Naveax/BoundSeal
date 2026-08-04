use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{TimeZone, Utc};
use nxb_executor::ExecutionControl;
use nxb_live_adapter::LiveAdapterConfig;
use nxb_operator::OperatorConfig;
use nxb_operator_runtime::{RuntimeClock, RuntimeMethod};
use nxb_policy::{AuthorizationPolicy, AutomationPolicy, ProgramPolicy, ScopePolicy, TargetPolicy};
use nxb_resumable_runner::{RunnerCandidate, RunnerManifest};
use nxb_session::SessionBroker;
use nxb_session_injection::{
    CsrfBinding, SessionInjectionActivationCertificate, SessionInjectionActivationPayload,
    SessionInjectionManifest, SessionInjectionManifestParameters,
};
use nxb_stream::StreamControl;
use nxb_unified_operator::{
    UnifiedComponentBinding, UnifiedOperatorActivationCertificate,
    UnifiedOperatorActivationPayload, UnifiedOperatorPlan, UnifiedOperatorPlanParameters,
};
use nxb_vault::{InMemorySecretVault, SecretKind};
use nxb_vault_provider::{
    bootstrap_external_session, consume_activation_once as consume_external_activation,
    ExternalVaultActivationCertificate, ExternalVaultActivationPayload,
    ExternalVaultPlanParameters, ExternalVaultProvider, ExternalVaultSessionPlan,
    ProviderDeliverySpec, ProviderFailure, ProviderIdentity, ProviderSecretMaterial,
    ProviderSecretRequest, ProviderSecretSpec, ProviderSessionOutcome, ProviderSessionRequest,
    ProvisionedExternalSession,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

use crate::{
    LiveRunHost, LiveRunHostInputs, LiveRunLaunchActivationCertificate,
    LiveRunLaunchActivationPayload, LiveRunLaunchBundle, LiveRunLaunchBundleParameters,
    LiveRunStepOutcome, LiveRunTeardownOutcome, StaticDnsResolver,
};

struct MockProvider {
    identity: ProviderIdentity,
}

impl ExternalVaultProvider for MockProvider {
    type Session = ();

    fn identity(&self) -> ProviderIdentity {
        self.identity.clone()
    }

    fn begin(&mut self, _: &ProviderSessionRequest) -> Result<Self::Session, ProviderFailure> {
        Ok(())
    }

    fn fetch(
        &mut self,
        _: &mut Self::Session,
        _: &ProviderSecretRequest,
    ) -> Result<ProviderSecretMaterial, ProviderFailure> {
        ProviderSecretMaterial::new("version-1", b"fixture-secret".to_vec(), 1_700)
            .map_err(|_| ProviderFailure::new("material_failure").expect("failure"))
    }

    fn finish(
        &mut self,
        _: Self::Session,
        _: ProviderSessionOutcome,
    ) -> Result<(), ProviderFailure> {
        Ok(())
    }
}

struct Fixture {
    root: PathBuf,
    bundle: LiveRunLaunchBundle,
    launch_activation: LiveRunLaunchActivationCertificate,
    launch_public_key: Vec<u8>,
    unified_plan: UnifiedOperatorPlan,
    unified_activation: UnifiedOperatorActivationCertificate,
    unified_public_key: Vec<u8>,
    runner_manifest: RunnerManifest,
    external_plan: ExternalVaultSessionPlan,
    provisioned: ProvisionedExternalSession,
    injection_manifest: SessionInjectionManifest,
    injection_activation: SessionInjectionActivationCertificate,
    injection_public_key: Vec<u8>,
    policy: nxb_policy::CompiledPolicy,
    operator_config: OperatorConfig,
    adapter_config: LiveAdapterConfig,
    broker: SessionBroker,
    vault: InMemorySecretVault,
}

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("key")
}

fn sha(value: &str) -> String {
    lower_hex(&Sha256::digest(value.as_bytes()))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn unique_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("nxb145-{label}-{}-{nanos}", std::process::id()))
}

fn clock(seconds: i64) -> RuntimeClock {
    RuntimeClock {
        epoch_seconds: seconds,
        epoch_milliseconds: seconds as u64 * 1_000,
    }
}

fn fixture(label: &str) -> Fixture {
    let root = unique_root(label);
    let authority = "example.com".to_string();
    let discovery_plan_sha256 = sha("discovery-plan");
    let target_origin_sha256 = sha("https://example.com:443");
    let provider = ProviderIdentity {
        provider_id: "fixture-provider".into(),
        provider_instance_sha256: sha("provider-instance"),
        capability_sha256: sha("provider-capability"),
    };
    let external_key = key(11);
    let external_plan = ExternalVaultSessionPlan::build(ExternalVaultPlanParameters {
        bootstrap_id: "bootstrap-145".into(),
        discovery_plan_sha256: discovery_plan_sha256.clone(),
        target_origin_sha256: target_origin_sha256.clone(),
        authority: authority.clone(),
        run_id: "run-145".into(),
        worker_id: "worker-145".into(),
        account_id: "account-145".into(),
        tenant_id: "tenant-145".into(),
        role_id: "role-145".into(),
        provider: provider.clone(),
        secrets: vec![ProviderSecretSpec {
            logical_id: "auth-token".into(),
            provider_handle: "provider/read/auth-token".into(),
            kind: SecretKind::BearerToken,
            delivery: ProviderDeliverySpec::Header {
                name: "authorization".into(),
                prefix_hex: lower_hex(b"Bearer "),
            },
            maximum_value_bytes: 256,
            required_version_sha256: None,
        }],
        created_at_epoch_seconds: 1_000,
        expires_at_epoch_seconds: 1_600,
        session_expires_at_epoch_seconds: 1_700,
        activation_public_key: external_key.public_key().as_ref().to_vec(),
    })
    .expect("external plan");
    let external_payload = ExternalVaultActivationPayload::template(
        "external-activation-145",
        &external_plan,
        1_050,
        1_500,
    )
    .expect("external payload");
    let external_activation = ExternalVaultActivationCertificate {
        signature_hex: lower_hex(
            external_key
                .sign(&external_payload.signing_bytes().expect("external bytes"))
                .as_ref(),
        ),
        payload: external_payload,
    };
    let consumed_external = consume_external_activation(
        &root.join("external-activation"),
        &external_plan,
        &external_activation,
        external_key.public_key().as_ref(),
        1_100,
    )
    .expect("consume external");
    let mut broker = SessionBroker::new("broker-145").expect("broker");
    let mut vault = InMemorySecretVault::new("vault-145").expect("vault");
    let mut mock = MockProvider { identity: provider };
    let provisioned = bootstrap_external_session(
        &external_plan,
        consumed_external,
        &mut mock,
        &mut broker,
        &mut vault,
        1_100,
    )
    .expect("bootstrap");

    let injection_key = key(12);
    let injection_manifest = SessionInjectionManifest::build(SessionInjectionManifestParameters {
        injection_id: "injection-145".into(),
        discovery_plan_sha256: discovery_plan_sha256.clone(),
        target_origin_sha256: target_origin_sha256.clone(),
        authority: authority.clone(),
        session_id: provisioned.session().session_id.clone(),
        run_id: "run-145".into(),
        worker_id: "worker-145".into(),
        account_id: "account-145".into(),
        tenant_id: "tenant-145".into(),
        role_id: "role-145".into(),
        bootstrap_secret_handles: provisioned.handles().to_vec(),
        allowed_path_prefixes: BTreeSet::from(["/app".into()]),
        allowed_header_names: BTreeSet::from(["authorization".into()]),
        allowed_cookie_names: BTreeSet::new(),
        csrf_bindings: Vec::<CsrfBinding>::new(),
        maximum_lease_seconds: 30,
        created_at_epoch_seconds: 1_100,
        expires_at_epoch_seconds: 1_550,
        activation_public_key: injection_key.public_key().as_ref().to_vec(),
    })
    .expect("injection manifest");
    let injection_payload = SessionInjectionActivationPayload::template(
        "injection-activation-145",
        &injection_manifest,
        1_150,
        1_500,
    )
    .expect("injection payload");
    let injection_activation = SessionInjectionActivationCertificate {
        signature_hex: lower_hex(
            injection_key
                .sign(&injection_payload.signing_bytes().expect("injection bytes"))
                .as_ref(),
        ),
        payload: injection_payload,
    };

    let unified_key = key(13);
    let receipt = provisioned.receipt();
    let unified_plan = UnifiedOperatorPlan::build(UnifiedOperatorPlanParameters {
        operator_id: "operator-145".into(),
        binding: UnifiedComponentBinding {
            discovery_plan_sha256: discovery_plan_sha256.clone(),
            policy_sha256: sha("policy-snapshot"),
            target_origin_sha256: target_origin_sha256.clone(),
            discovery_session_id: "discovery-session-145".into(),
            authority: authority.clone(),
            run_id: "run-145".into(),
            worker_id: "worker-145".into(),
            account_id: "account-145".into(),
            tenant_id: "tenant-145".into(),
            role_id: "role-145".into(),
            session_injection_manifest_sha256: injection_manifest.manifest_sha256.clone(),
            external_vault_plan_sha256: external_plan.plan_sha256.clone(),
            external_vault_bootstrap_receipt_sha256: receipt.receipt_sha256.clone(),
            external_session_id_sha256: receipt.session_id_sha256.clone(),
            provider_id: receipt.provider_id.clone(),
            provider_instance_sha256: receipt.provider_instance_sha256.clone(),
            provider_capability_sha256: receipt.capability_sha256.clone(),
            secret_binding_root_sha256: receipt.secret_binding_root_sha256.clone(),
            secret_count: receipt.secret_count,
            allowed_path_prefixes: BTreeSet::from(["/app".into()]),
            maximum_requests: 4,
            maximum_depth: 2,
            maximum_response_body_bytes: 1_024,
            maximum_total_response_bytes: 4_096,
            minimum_request_interval_milliseconds: 200,
            maximum_concurrency: 1,
            component_expires_at_epoch_seconds: 1_550,
        },
        checkpoint_interval_requests: 1,
        maximum_workspace_bytes: 64 * 1024 * 1024,
        created_at_epoch_seconds: 1_150,
        expires_at_epoch_seconds: 1_500,
        activation_public_key: unified_key.public_key().as_ref().to_vec(),
    })
    .expect("unified plan");
    let unified_payload = UnifiedOperatorActivationPayload::template(
        "unified-activation-145",
        &unified_plan,
        1_200,
        1_450,
    )
    .expect("unified payload");
    let unified_activation = UnifiedOperatorActivationCertificate {
        signature_hex: lower_hex(
            unified_key
                .sign(&unified_payload.signing_bytes().expect("unified bytes"))
                .as_ref(),
        ),
        payload: unified_payload,
    };
    let runner_manifest = RunnerManifest::build(
        &unified_plan,
        RunnerCandidate::seed(RuntimeMethod::Get, "/app", 0),
        16,
        1_200,
    )
    .expect("runner manifest");

    let policy = TargetPolicy {
        schema_version: 1,
        program: ProgramPolicy {
            name: "fixture-program".into(),
            platform: "fixture".into(),
            policy_url: None,
        },
        scope: ScopePolicy {
            include_hosts: BTreeSet::from([authority]),
            exclude_hosts: BTreeSet::new(),
            allowed_schemes: BTreeSet::from(["https".into()]),
            allowed_methods: BTreeSet::from(["GET".into(), "HEAD".into()]),
            allow_subdomains: false,
        },
        automation: AutomationPolicy {
            active_testing: false,
            credential_bruteforce: false,
            destructive_testing: false,
            oob_callbacks: false,
            max_requests_per_second: 5.0,
            max_concurrency: 1,
            max_total_requests: 4,
        },
        authorization: AuthorizationPolicy {
            confirmed: true,
            researcher: "Naveax".into(),
            policy_snapshot_sha256: sha("policy-snapshot"),
            expires_at: Utc.timestamp_opt(1_800, 0).single().expect("timestamp"),
        },
    }
    .compile(Utc.timestamp_opt(1_200, 0).single().expect("timestamp"))
    .expect("policy");
    let operator_config = OperatorConfig {
        maximum_depth: 2,
        maximum_endpoints: 16,
        maximum_requests: 4,
        maximum_body_bytes: 1_024,
        ..OperatorConfig::default()
    };
    let mut adapter_config = LiveAdapterConfig::conservative("host-145").expect("adapter");
    adapter_config.limits.http.maximum_response_body_bytes = 1_024;
    adapter_config.limits.http.maximum_chunk_bytes = 1_024;
    adapter_config.validate().expect("adapter validate");

    let bundle = LiveRunLaunchBundle::build(
        LiveRunLaunchBundleParameters {
            launch_id: "launch-145".into(),
            dns_resolver_id: "resolver-145".into(),
            maximum_dns_addresses: 8,
            maximum_dns_ttl_seconds: 300,
            created_at_epoch_seconds: 1_200,
            expires_at_epoch_seconds: 1_400,
            signer_public_key: unified_key.public_key().as_ref().to_vec(),
        },
        &unified_plan,
        &runner_manifest,
        &external_plan,
        provisioned.receipt(),
        &injection_manifest,
        &policy,
        &operator_config,
        &adapter_config,
    )
    .expect("bundle");
    let launch_payload =
        LiveRunLaunchActivationPayload::template("launch-activation-145", &bundle, 1_210, 1_390)
            .expect("launch payload");
    let launch_activation = LiveRunLaunchActivationCertificate {
        signature_hex: lower_hex(
            unified_key
                .sign(&launch_payload.signing_bytes().expect("launch bytes"))
                .as_ref(),
        ),
        payload: launch_payload,
    };

    Fixture {
        root,
        bundle,
        launch_activation,
        launch_public_key: unified_key.public_key().as_ref().to_vec(),
        unified_plan,
        unified_activation,
        unified_public_key: unified_key.public_key().as_ref().to_vec(),
        runner_manifest,
        external_plan,
        provisioned,
        injection_manifest,
        injection_activation,
        injection_public_key: injection_key.public_key().as_ref().to_vec(),
        policy,
        operator_config,
        adapter_config,
        broker,
        vault,
    }
}

#[test]
fn launch_bundle_verifies_exact_artifact_graph() {
    let fixture = fixture("bundle");
    fixture
        .bundle
        .verify_artifacts(
            &fixture.unified_plan,
            &fixture.runner_manifest,
            &fixture.external_plan,
            fixture.provisioned.receipt(),
            &fixture.injection_manifest,
            &fixture.policy,
            &fixture.operator_config,
            &fixture.adapter_config,
            1_220,
        )
        .expect("verify");
    std::fs::remove_dir_all(fixture.root).expect("cleanup");
}

#[test]
fn bundle_rejects_operator_broadening() {
    let mut fixture = fixture("broadening");
    fixture.operator_config.maximum_requests = 5;
    let error = fixture
        .bundle
        .verify_artifacts(
            &fixture.unified_plan,
            &fixture.runner_manifest,
            &fixture.external_plan,
            fixture.provisioned.receipt(),
            &fixture.injection_manifest,
            &fixture.policy,
            &fixture.operator_config,
            &fixture.adapter_config,
            1_220,
        )
        .expect_err("broadening denied");
    assert!(error.to_string().contains("operator_config_sha256"));
    std::fs::remove_dir_all(fixture.root).expect("cleanup");
}

#[test]
fn private_dns_result_moves_host_to_ordered_teardown_without_network() {
    let fixture = fixture("private-dns");
    let resolver = StaticDnsResolver::new(
        "resolver-145",
        BTreeSet::from([IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        30,
    )
    .expect("resolver");
    let (mut host, _) = LiveRunHost::initialize(LiveRunHostInputs {
        workspace: fixture.root.join("host"),
        bundle: fixture.bundle,
        launch_activation: fixture.launch_activation,
        launch_public_key: fixture.launch_public_key,
        unified_plan: fixture.unified_plan,
        unified_activation: fixture.unified_activation,
        unified_public_key: fixture.unified_public_key,
        runner_manifest: fixture.runner_manifest,
        external_vault_plan: fixture.external_plan,
        provisioned_session: fixture.provisioned,
        injection_manifest: fixture.injection_manifest,
        injection_activation: fixture.injection_activation,
        injection_public_key: fixture.injection_public_key,
        policy: fixture.policy,
        operator_config: fixture.operator_config,
        adapter_config: fixture.adapter_config,
        resolver,
        broker: fixture.broker,
        vault: fixture.vault,
        clock: clock(1_220),
    })
    .expect("host");
    let outcome = host
        .step(
            clock(1_221),
            ExecutionControl::default(),
            StreamControl::default(),
        )
        .expect("step");
    assert!(matches!(
        outcome,
        LiveRunStepOutcome::TeardownPending { .. }
    ));
    let teardown = host.teardown(clock(1_222)).expect("teardown");
    assert!(matches!(teardown, LiveRunTeardownOutcome::Completed { .. }));
    assert!(host.is_terminal());
    std::fs::remove_dir_all(fixture.root).expect("cleanup");
}
