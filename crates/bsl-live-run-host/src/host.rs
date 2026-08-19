use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use nxb_executor::ExecutionControl;
use nxb_gateway::{DecisionOutcome, RequestIntent, ScopeGateway};
use nxb_live_adapter::{LiveAdapterConfig, LivePassivePipeline};
use nxb_operator::OperatorConfig;
use nxb_operator_runtime::{CheckpointBoundRuntime, RuntimeClock, RuntimeRecovery};
use nxb_operator_state::OperatorRunStatus;
use nxb_pinned_transport::PinnedTransportCoordinator;
use nxb_policy::CompiledPolicy;
use nxb_resumable_runner::{
    discover_authenticated_response, ResumableBoundedRunner, RunnerManifest, RunnerRecovery,
    RunnerStatus, RunnerStepReceipt, RunnerStopReason,
};
use nxb_session::SessionBroker;
use nxb_session_injection::{
    consume_activation_once as consume_injection_activation, BoundSessionInjection,
    SessionInjectionActivationCertificate, SessionInjectionManifest,
};
use nxb_stream::StreamControl;
use nxb_transport::ConnectionAttempt;
use nxb_unified_operator::{
    consume_activation_once as consume_unified_activation, UnifiedOperatorActivationCertificate,
    UnifiedOperatorPlan,
};
use nxb_vault::InMemorySecretVault;
use nxb_vault_provider::{
    deprovision_external_session, ExternalVaultSessionPlan, ProvisionedExternalSession,
};
use url::Url;

use crate::{
    consume_launch_activation_once, contract::hash_bytes, DnsResolutionRequest, LiveDnsResolver,
    LiveRunHostError, LiveRunLaunchActivationCertificate, LiveRunLaunchBundle,
};

pub struct LiveRunHostInputs<R> {
    pub workspace: PathBuf,
    pub bundle: LiveRunLaunchBundle,
    pub launch_activation: LiveRunLaunchActivationCertificate,
    pub launch_public_key: Vec<u8>,
    pub unified_plan: UnifiedOperatorPlan,
    pub unified_activation: UnifiedOperatorActivationCertificate,
    pub unified_public_key: Vec<u8>,
    pub runner_manifest: RunnerManifest,
    pub external_vault_plan: ExternalVaultSessionPlan,
    pub provisioned_session: ProvisionedExternalSession,
    pub injection_manifest: SessionInjectionManifest,
    pub injection_activation: SessionInjectionActivationCertificate,
    pub injection_public_key: Vec<u8>,
    pub policy: CompiledPolicy,
    pub operator_config: OperatorConfig,
    pub adapter_config: LiveAdapterConfig,
    pub resolver: R,
    pub broker: SessionBroker,
    pub vault: InMemorySecretVault,
    pub clock: RuntimeClock,
}

#[derive(Debug, Clone)]
pub enum LiveRunStepOutcome {
    Executed(RunnerStepReceipt),
    TeardownPending { reason: String },
}

#[derive(Debug, Clone)]
pub enum LiveRunTeardownOutcome {
    Completed {
        external_teardown_receipt_sha256: String,
        runtime_checkpoint_sha256: String,
        runner_checkpoint_sha256: String,
    },
    Aborted {
        reason: String,
        runtime_checkpoint_sha256: String,
        runner_checkpoint_sha256: String,
    },
}

pub struct LiveRunHost<R> {
    workspace: PathBuf,
    bundle: LiveRunLaunchBundle,
    launch_activation_marker: PathBuf,
    runner_manifest: RunnerManifest,
    policy: CompiledPolicy,
    operator_config: OperatorConfig,
    resolver: R,
    used_dns_contexts: BTreeSet<String>,
    started_at_epoch_milliseconds: u64,
    runtime: CheckpointBoundRuntime,
    runner: ResumableBoundedRunner,
    pipeline: LivePassivePipeline,
    bound: BoundSessionInjection,
    broker: SessionBroker,
    vault: InMemorySecretVault,
    provisioned_session: Option<ProvisionedExternalSession>,
    terminal: bool,
}

impl<R> std::fmt::Debug for LiveRunHost<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveRunHost")
            .field("workspace", &self.workspace)
            .field("bundle_sha256", &self.bundle.bundle_sha256)
            .field(
                "runner_checkpoint",
                &self.runner.latest_checkpoint().checkpoint_sha256,
            )
            .field("runner_status", &self.runner.latest_checkpoint().status)
            .field("used_dns_contexts", &self.used_dns_contexts.len())
            .field(
                "provisioned_session",
                &self.provisioned_session.as_ref().map(|_| "<opaque>"),
            )
            .field("terminal", &self.terminal)
            .finish()
    }
}

impl<R: LiveDnsResolver> LiveRunHost<R> {
    pub fn initialize(
        inputs: LiveRunHostInputs<R>,
    ) -> Result<(Self, RunnerRecovery), LiveRunHostError> {
        let LiveRunHostInputs {
            workspace,
            bundle,
            launch_activation,
            launch_public_key,
            unified_plan,
            unified_activation,
            unified_public_key,
            runner_manifest,
            external_vault_plan,
            provisioned_session,
            injection_manifest,
            injection_activation,
            injection_public_key,
            policy,
            operator_config,
            adapter_config,
            resolver,
            broker,
            vault,
            clock,
        } = inputs;
        let clock = clock.validate()?;
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
        let started_at_epoch_milliseconds = clock.epoch_milliseconds;
        let host = Self {
            workspace,
            bundle,
            launch_activation_marker,
            runner_manifest,
            policy,
            operator_config,
            resolver,
            used_dns_contexts: BTreeSet::new(),
            started_at_epoch_milliseconds,
            runtime,
            runner,
            pipeline,
            bound,
            broker,
            vault,
            provisioned_session: Some(provisioned_session),
            terminal: false,
        };
        host.ensure_launch_live(clock.epoch_seconds)?;
        Ok((host, runner_recovery))
    }

    pub fn step(
        &mut self,
        clock: RuntimeClock,
        execution_control: ExecutionControl,
        stream_control: StreamControl,
    ) -> Result<LiveRunStepOutcome, LiveRunHostError> {
        let clock = clock.validate()?;
        if self.terminal {
            return Err(LiveRunHostError::HostTerminal);
        }
        self.ensure_launch_live(clock.epoch_seconds)?;
        if self.runner.latest_checkpoint().status != RunnerStatus::Running {
            self.ensure_runtime_teardown("runner_not_running", clock)?;
            return Ok(LiveRunStepOutcome::TeardownPending {
                reason: "runner_not_running".into(),
            });
        }
        let candidate = match self
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
        let request_index = self.runner.latest_checkpoint().completed_requests;
        let context_id = format!(
            "dns-{}-{request_index:020}",
            &self.bundle.bundle_sha256[..16]
        );
        if !self.used_dns_contexts.insert(context_id.clone()) {
            self.ensure_runner_and_runtime_teardown(
                RunnerStopReason::RuntimeContinuationDenied,
                "dns_context_reused",
                clock,
            )?;
            return Err(LiveRunHostError::DnsContextReused);
        }
        let dns_request = DnsResolutionRequest {
            resolver_id: self.bundle.dns_resolver_id.clone(),
            context_id: context_id.clone(),
            authority: self.bundle.authority.clone(),
            port: 443,
            request_index,
            request_target_sha256: candidate.target_sha256(),
        };
        let resolution = match self.resolver.resolve(&dns_request) {
            Ok(resolution) => resolution,
            Err(failure) => {
                self.ensure_runner_and_runtime_teardown(
                    RunnerStopReason::RuntimeContinuationDenied,
                    "dns_resolution_failed",
                    clock,
                )?;
                return Err(LiveRunHostError::DnsResolution(failure.code().into()));
            }
        };
        if let Err(error) = resolution.validate(&self.bundle, &dns_request) {
            return self.fail_closed_step("invalid_dns_resolution", error, clock);
        }
        let elapsed = self.elapsed(clock)?;
        let url = match Url::parse(&format!(
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
        let intent = RequestIntent {
            url,
            method: candidate.method.code().into(),
            resolved_ips: resolution.addresses.iter().copied().collect(),
            redirect_depth: 0,
            dns_context_id: resolution.context_id.clone(),
            dns_resolver_id: resolution.resolver_id.clone(),
            dns_ttl_seconds: resolution.ttl_seconds,
        };
        let authorization = match self.pipeline.transport_mut().authorize_connection(
            &intent,
            resolution.selected_ip,
            elapsed,
        ) {
            Ok(authorization) => authorization,
            Err(error) => {
                self.pipeline
                    .transport_mut()
                    .release_context(&resolution.context_id);
                return self.fail_closed_step("gateway_authorization_failed", error.into(), clock);
            }
        };
        if authorization.decision.outcome != DecisionOutcome::Allow {
            self.pipeline
                .transport_mut()
                .release_context(&resolution.context_id);
            let reason = format!("gateway_{:?}", authorization.decision.reason);
            self.ensure_runner_and_runtime_teardown(
                RunnerStopReason::RuntimeContinuationDenied,
                &reason,
                clock,
            )?;
            return Ok(LiveRunStepOutcome::TeardownPending { reason });
        }
        let ticket = match authorization.ticket {
            Some(ticket) => ticket,
            None => {
                self.pipeline
                    .transport_mut()
                    .release_context(&resolution.context_id);
                self.ensure_runner_and_runtime_teardown(
                    RunnerStopReason::RuntimeContinuationDenied,
                    "missing_transport_ticket",
                    clock,
                )?;
                return Err(LiveRunHostError::MissingTransportTicket);
            }
        };
        let attempt = ConnectionAttempt {
            ticket_id: ticket.ticket_id,
            dns_context_id: ticket.dns_context_id,
            scheme: ticket.scheme,
            remote_ip: ticket.selected_ip,
            port: ticket.port,
            sni: ticket.sni,
            http_host: ticket.http_host,
            redirect_depth: ticket.redirect_depth,
        };
        let manifest = self.runner_manifest.clone();
        let policy = self.policy.clone();
        let operator_config = self.operator_config.clone();
        let result = self.runner.execute_next_live_authenticated(
            &mut self.runtime,
            &mut self.pipeline,
            attempt,
            elapsed,
            execution_control,
            stream_control,
            &self.bound,
            &mut self.broker,
            &mut self.vault,
            clock,
            |executed, live| {
                discover_authenticated_response(
                    &manifest,
                    &policy,
                    &operator_config,
                    executed,
                    live,
                )
            },
        );
        self.pipeline
            .transport_mut()
            .release_context(&resolution.context_id);
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(error) => {
                let reason = format!("execution_indeterminate:{error}");
                self.ensure_runner_and_runtime_teardown(
                    RunnerStopReason::RuntimeContinuationDenied,
                    &reason,
                    clock,
                )?;
                return Ok(LiveRunStepOutcome::TeardownPending { reason });
            }
        };
        match receipt {
            Some(receipt) if receipt.status == RunnerStatus::Running => {
                Ok(LiveRunStepOutcome::Executed(receipt))
            }
            Some(receipt) => {
                let reason = format!("runner_{:?}", receipt.stop_reason);
                self.ensure_runtime_teardown(&reason, clock)?;
                Ok(LiveRunStepOutcome::TeardownPending { reason })
            }
            None => {
                let reason = "runner_requested_teardown".to_string();
                self.ensure_runtime_teardown(&reason, clock)?;
                Ok(LiveRunStepOutcome::TeardownPending { reason })
            }
        }
    }

    pub fn teardown(
        &mut self,
        clock: RuntimeClock,
    ) -> Result<LiveRunTeardownOutcome, LiveRunHostError> {
        let clock = clock.validate()?;
        if self.terminal {
            return Err(LiveRunHostError::HostTerminal);
        }
        if self.runner.latest_checkpoint().status == RunnerStatus::Running {
            self.runner
                .begin_teardown(RunnerStopReason::RuntimeContinuationDenied, clock)?;
        }
        self.ensure_runtime_teardown("ordered_external_session_teardown", clock)?;
        let provisioned = self
            .provisioned_session
            .take()
            .ok_or(LiveRunHostError::SessionAlreadyConsumed)?;
        match deprovision_external_session(
            provisioned,
            &mut self.broker,
            &mut self.vault,
            clock.epoch_seconds,
        ) {
            Ok(receipt) => {
                receipt.verify()?;
                let runtime_state = self
                    .runtime
                    .complete_teardown(&receipt.receipt_sha256, clock)?;
                let recovery = self.runtime.recover(clock)?;
                let runner_checkpoint = self.runner.record_runtime_terminal(&recovery, clock)?;
                self.terminal = true;
                Ok(LiveRunTeardownOutcome::Completed {
                    external_teardown_receipt_sha256: receipt.receipt_sha256,
                    runtime_checkpoint_sha256: runtime_state.latest.checkpoint_sha256,
                    runner_checkpoint_sha256: runner_checkpoint.checkpoint_sha256,
                })
            }
            Err(error) => {
                let reason = format!("external_teardown_failed:{error}");
                let runtime_state = self.runtime.abort(&reason, clock)?;
                let recovery = self.runtime.recover(clock)?;
                let runner_checkpoint = self.runner.record_runtime_terminal(&recovery, clock)?;
                self.terminal = true;
                Ok(LiveRunTeardownOutcome::Aborted {
                    reason,
                    runtime_checkpoint_sha256: runtime_state.latest.checkpoint_sha256,
                    runner_checkpoint_sha256: runner_checkpoint.checkpoint_sha256,
                })
            }
        }
    }

    pub fn bundle(&self) -> &LiveRunLaunchBundle {
        &self.bundle
    }

    pub fn runner(&self) -> &ResumableBoundedRunner {
        &self.runner
    }

    pub fn runtime_recovery(
        &self,
        clock: RuntimeClock,
    ) -> Result<RuntimeRecovery, LiveRunHostError> {
        Ok(self.runtime.recover(clock)?)
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    fn elapsed(&self, clock: RuntimeClock) -> Result<Duration, LiveRunHostError> {
        let milliseconds = clock
            .epoch_milliseconds
            .checked_sub(self.started_at_epoch_milliseconds)
            .ok_or_else(|| LiveRunHostError::InvalidField("clock_regression".into()))?;
        Ok(Duration::from_millis(milliseconds))
    }

    fn fail_closed_step<T>(
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
        self.bundle.verify(now_epoch_seconds)?;
        if !self.launch_activation_marker.is_file() {
            return Err(LiveRunHostError::ActivationBindingMismatch);
        }
        Ok(())
    }

    fn ensure_runtime_teardown(
        &mut self,
        reason: &str,
        clock: RuntimeClock,
    ) -> Result<(), LiveRunHostError> {
        let recovery = self.runtime.recover(clock)?;
        if !matches!(
            recovery.state.latest.status,
            OperatorRunStatus::Completed
                | OperatorRunStatus::Aborted
                | OperatorRunStatus::TeardownPending
        ) {
            self.runtime.begin_teardown(reason, clock)?;
        }
        Ok(())
    }

    fn ensure_runner_and_runtime_teardown(
        &mut self,
        runner_reason: RunnerStopReason,
        runtime_reason: &str,
        clock: RuntimeClock,
    ) -> Result<(), LiveRunHostError> {
        if self.runner.latest_checkpoint().status == RunnerStatus::Running {
            self.runner.begin_teardown(runner_reason, clock)?;
        }
        self.ensure_runtime_teardown(runtime_reason, clock)
    }
}

impl<R> Drop for LiveRunHost<R> {
    fn drop(&mut self) {
        if self.terminal {
            return;
        }
        let Some(provisioned) = self.provisioned_session.take() else {
            return;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .unwrap_or(1);
        let _ = deprovision_external_session(provisioned, &mut self.broker, &mut self.vault, now);
    }
}

pub(crate) fn cleanup_failed_initialization(
    provisioned: ProvisionedExternalSession,
    broker: &mut SessionBroker,
    vault: &mut InMemorySecretVault,
    now_epoch_seconds: i64,
) -> Result<(), LiveRunHostError> {
    deprovision_external_session(provisioned, broker, vault, now_epoch_seconds)?;
    Ok(())
}

fn verify_provisioned_session(
    bundle: &LiveRunLaunchBundle,
    injection: &SessionInjectionManifest,
    provisioned: &ProvisionedExternalSession,
) -> Result<(), LiveRunHostError> {
    provisioned.receipt().verify()?;
    if provisioned.receipt().receipt_sha256 != bundle.external_vault_bootstrap_receipt_sha256
        || hash_bytes(provisioned.session().session_id.as_bytes())
            != bundle.external_session_id_sha256
        || provisioned.session().session_id != injection.session_id
    {
        return Err(LiveRunHostError::ArtifactBindingMismatch(
            "provisioned_session".into(),
        ));
    }
    let actual = provisioned
        .handles()
        .iter()
        .map(|handle| hash_bytes(handle.as_str().as_bytes()))
        .collect::<BTreeSet<_>>();
    let receipt = provisioned
        .receipt()
        .provisioned_secrets
        .iter()
        .map(|secret| secret.vault_handle_sha256.clone())
        .collect::<BTreeSet<_>>();
    if actual != receipt || actual.len() as u64 != bundle.secret_count {
        return Err(LiveRunHostError::ArtifactBindingMismatch(
            "provisioned_secret_handles".into(),
        ));
    }
    Ok(())
}
