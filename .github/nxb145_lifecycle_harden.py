from pathlib import Path
import re

HOST = Path("crates/nxb-live-run-host/src/host.rs")
ERROR = Path("crates/nxb-live-run-host/src/error.rs")
TESTS = Path("crates/nxb-live-run-host/src/tests.rs")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"NXB-145 {label} anchor mismatch: {text.count(old)}")
    return text.replace(old, new, 1)


error = ERROR.read_text(encoding="utf-8")
error = replace_once(
    error,
    '''    #[error("live-run host teardown failed: {0}")]
    TeardownFailed(String),
''',
    '''    #[error("live-run host teardown failed: {0}")]
    TeardownFailed(String),
    #[error(
        "live-run host initialization failed ({initialization}) and external session cleanup failed ({cleanup})"
    )]
    InitializationCleanupFailed {
        initialization: String,
        cleanup: String,
    },
''',
    "initialization cleanup error",
)
ERROR.write_text(error, encoding="utf-8")

host = HOST.read_text(encoding="utf-8")
initialization_pattern = re.compile(
    r'''        let clock = clock\.validate\(\)\?;\n'''
    r'''        bundle\.verify_artifacts\(.*?'''
    r'''        let pipeline =\n            LivePassivePipeline::new\(PinnedTransportCoordinator::new\(gateway\), adapter_config\)\?;\n''',
    re.S,
)
initialization_replacement = '''        let clock = clock.validate()?;
        let mut broker = broker;
        let mut vault = vault;
        let mut provisioned_session = Some(provisioned_session);
        let setup_result: Result<_, LiveRunHostError> = (|| {
            let provisioned = provisioned_session
                .as_ref()
                .ok_or(LiveRunHostError::SessionAlreadyConsumed)?;
            bundle.verify_artifacts(
                &unified_plan,
                &runner_manifest,
                &external_vault_plan,
                provisioned.receipt(),
                &injection_manifest,
                &policy,
                &operator_config,
                &adapter_config,
                clock.epoch_seconds,
            )?;
            verify_provisioned_session(&bundle, &injection_manifest, provisioned)?;

            fs::create_dir_all(&workspace)
                .map_err(|error| LiveRunHostError::Io(error.to_string()))?;
            let launch_consumed = consume_launch_activation_once(
                &workspace.join("activations/live-run"),
                &bundle,
                &launch_activation,
                &launch_public_key,
                clock.epoch_seconds,
            )?;
            let unified_consumed = consume_unified_activation(
                &workspace.join("activations/unified"),
                &unified_plan,
                &unified_activation,
                &unified_public_key,
                clock.epoch_seconds,
            )?;
            let injection_consumed = consume_injection_activation(
                &workspace.join("activations/session-injection"),
                &injection_manifest,
                &injection_activation,
                &injection_public_key,
                clock.epoch_seconds,
            )?;
            let bound = BoundSessionInjection::bind(
                injection_manifest,
                injection_consumed,
                &unified_plan.binding.discovery_plan_sha256,
                &unified_plan.binding.target_origin_sha256,
                provisioned.session(),
                &vault,
                clock.epoch_seconds,
            )?;

            let (runtime, runtime_recovery) = CheckpointBoundRuntime::initialize(
                workspace.join("operator-state"),
                workspace.join("runtime-journal"),
                unified_plan.clone(),
                &unified_consumed,
                clock,
            )?;
            let (runner, runner_recovery) = ResumableBoundedRunner::initialize(
                workspace.join("runner"),
                unified_plan,
                runner_manifest.clone(),
                runtime_recovery,
                clock,
            )?;
            let gateway = ScopeGateway::new(policy.clone(), 1)?;
            let pipeline =
                LivePassivePipeline::new(PinnedTransportCoordinator::new(gateway), adapter_config)?;
            Ok((
                launch_consumed.marker_path().to_path_buf(),
                runtime,
                runner,
                runner_recovery,
                pipeline,
                bound,
            ))
        })();

        let (launch_activation_marker, runtime, runner, runner_recovery, pipeline, bound) =
            match setup_result {
                Ok(setup) => setup,
                Err(initialization) => {
                    let cleanup = provisioned_session.take().map(|provisioned| {
                        cleanup_failed_initialization(
                            provisioned,
                            &mut broker,
                            &mut vault,
                            clock.epoch_seconds,
                        )
                    });
                    if let Some(Err(cleanup)) = cleanup {
                        return Err(LiveRunHostError::InitializationCleanupFailed {
                            initialization: initialization.to_string(),
                            cleanup: cleanup.to_string(),
                        });
                    }
                    return Err(initialization);
                }
            };
        let provisioned_session = provisioned_session
            .take()
            .ok_or(LiveRunHostError::SessionAlreadyConsumed)?;
'''
host, count = initialization_pattern.subn(initialization_replacement, host, count=1)
if count != 1:
    raise SystemExit(f"NXB-145 initialization anchor mismatch: {count}")
host = replace_once(
    host,
    "            launch_activation_marker: launch_consumed.marker_path().to_path_buf(),\n",
    "            launch_activation_marker,\n",
    "launch marker",
)
host = replace_once(
    host,
    '''        let candidate = self
            .runner
            .latest_checkpoint()
            .pending_queue
            .first()
            .cloned()
            .ok_or_else(|| LiveRunHostError::GatewayDenied("queue_exhausted".into()))?;
''',
    '''        let candidate = match self
            .runner
            .latest_checkpoint()
            .pending_queue
            .first()
            .cloned()
        {
            Some(candidate) => candidate,
            None => {
                let reason = "queue_exhausted".to_string();
                self.ensure_runner_and_runtime_teardown(
                    RunnerStopReason::QueueExhausted,
                    &reason,
                    clock,
                )?;
                return Ok(LiveRunStepOutcome::TeardownPending { reason });
            }
        };
''',
    "queue exhaustion",
)
host = replace_once(
    host,
    "        resolution.validate(&self.bundle, &dns_request)?;\n",
    '''        if let Err(error) = resolution.validate(&self.bundle, &dns_request) {
            return self.fail_closed_step("invalid_dns_resolution", error, clock);
        }
''',
    "DNS validation",
)
host = replace_once(
    host,
    '''        let url = Url::parse(&format!(
            "https://{}{}",
            self.bundle.authority, candidate.target
        ))
        .map_err(|error| LiveRunHostError::InvalidDnsResult(error.to_string()))?;
''',
    '''        let url = match Url::parse(&format!(
            "https://{}{}",
            self.bundle.authority, candidate.target
        )) {
            Ok(url) => url,
            Err(error) => {
                return self.fail_closed_step(
                    "invalid_request_url",
                    LiveRunHostError::InvalidDnsResult(error.to_string()),
                    clock,
                );
            }
        };
''',
    "request URL",
)
host = replace_once(
    host,
    '''        let authorization = self.pipeline.transport_mut().authorize_connection(
            &intent,
            resolution.selected_ip,
            elapsed,
        )?;
''',
    '''        let authorization = match self.pipeline.transport_mut().authorize_connection(
            &intent,
            resolution.selected_ip,
            elapsed,
        ) {
            Ok(authorization) => authorization,
            Err(error) => {
                self.pipeline
                    .transport_mut()
                    .release_context(&resolution.context_id);
                return self.fail_closed_step(
                    "gateway_authorization_failed",
                    error.into(),
                    clock,
                );
            }
        };
''',
    "gateway authorization",
)
host = replace_once(
    host,
    '''    fn ensure_launch_live(&self, now_epoch_seconds: i64) -> Result<(), LiveRunHostError> {
''',
    '''    fn fail_closed_step<T>(
        &mut self,
        reason: &str,
        error: LiveRunHostError,
        clock: RuntimeClock,
    ) -> Result<T, LiveRunHostError> {
        self.ensure_runner_and_runtime_teardown(
            RunnerStopReason::RuntimeContinuationDenied,
            reason,
            clock,
        )?;
        Err(error)
    }

    fn ensure_launch_live(&self, now_epoch_seconds: i64) -> Result<(), LiveRunHostError> {
''',
    "fail-closed helper",
)
host = replace_once(
    host,
    '''fn verify_provisioned_session(
''',
    '''pub(crate) fn cleanup_failed_initialization(
    provisioned: ProvisionedExternalSession,
    broker: &mut SessionBroker,
    vault: &mut InMemorySecretVault,
    now_epoch_seconds: i64,
) -> Result<(), LiveRunHostError> {
    deprovision_external_session(provisioned, broker, vault, now_epoch_seconds)?;
    Ok(())
}

fn verify_provisioned_session(
''',
    "initialization cleanup helper",
)
HOST.write_text(host, encoding="utf-8")

tests = TESTS.read_text(encoding="utf-8")
tests = replace_once(
    tests,
    "use nxb_session::SessionBroker;\n",
    "use nxb_session::{SessionBroker, SessionStatus};\n",
    "session status import",
)
tests = replace_once(
    tests,
    '''use crate::{
    LiveRunHost, LiveRunHostInputs, LiveRunLaunchActivationCertificate,
    LiveRunLaunchActivationPayload, LiveRunLaunchBundle, LiveRunLaunchBundleParameters,
    LiveRunStepOutcome, LiveRunTeardownOutcome, StaticDnsResolver,
};
''',
    '''use crate::host::cleanup_failed_initialization;
use crate::{
    DnsResolutionFailure, DnsResolutionRequest, LiveDnsResolution, LiveDnsResolver, LiveRunHost,
    LiveRunHostError, LiveRunHostInputs, LiveRunLaunchActivationCertificate,
    LiveRunLaunchActivationPayload, LiveRunLaunchBundle, LiveRunLaunchBundleParameters,
    LiveRunStepOutcome, LiveRunTeardownOutcome, StaticDnsResolver,
};

struct InvalidDnsResolver;

impl LiveDnsResolver for InvalidDnsResolver {
    fn resolve(
        &mut self,
        request: &DnsResolutionRequest,
    ) -> Result<LiveDnsResolution, DnsResolutionFailure> {
        let selected_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        Ok(LiveDnsResolution {
            resolver_id: request.resolver_id.clone(),
            context_id: format!("{}-mismatch", request.context_id),
            addresses: BTreeSet::from([selected_ip]),
            selected_ip,
            ttl_seconds: 30,
        })
    }
}
''',
    "invalid DNS fixture",
)
if "fn invalid_dns_result_enters_teardown_before_returning_error()" in tests:
    raise SystemExit("NXB-145 lifecycle tests already present")
tests += '''

#[test]
fn invalid_dns_result_enters_teardown_before_returning_error() {
    let fixture = fixture("invalid-dns");
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
        resolver: InvalidDnsResolver,
        broker: fixture.broker,
        vault: fixture.vault,
        clock: clock(1_220),
    })
    .expect("host");
    let error = host
        .step(
            clock(1_221),
            ExecutionControl::default(),
            StreamControl::default(),
        )
        .expect_err("invalid DNS result must fail closed");
    assert!(matches!(error, LiveRunHostError::InvalidDnsResult(_)));
    assert_eq!(
        host.runner().latest_checkpoint().status,
        nxb_resumable_runner::RunnerStatus::TeardownPending
    );
    let teardown = host.teardown(clock(1_222)).expect("teardown");
    assert!(matches!(teardown, LiveRunTeardownOutcome::Completed { .. }));
    std::fs::remove_dir_all(fixture.root).expect("cleanup");
}

#[test]
fn failed_initialization_cleanup_revokes_session_and_removes_secrets() {
    let Fixture {
        root,
        provisioned,
        mut broker,
        mut vault,
        ..
    } = fixture("initialization-cleanup");
    let session_id = provisioned.session().session_id.clone();
    let handles = provisioned.handles().to_vec();
    cleanup_failed_initialization(provisioned, &mut broker, &mut vault, 1_220)
        .expect("initialization cleanup");
    let metadata = broker.metadata(&session_id).expect("revoked session metadata");
    assert_eq!(metadata.status, SessionStatus::Revoked);
    for handle in handles {
        assert!(vault.metadata(&handle).is_err());
    }
    std::fs::remove_dir_all(root).expect("cleanup");
}
'''
TESTS.write_text(tests, encoding="utf-8")
