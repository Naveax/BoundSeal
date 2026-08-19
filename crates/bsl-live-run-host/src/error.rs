use thiserror::Error;

#[derive(Debug, Error)]
pub enum LiveRunHostError {
    #[error("live-run launch bundle version is unsupported")]
    UnsupportedBundleVersion,
    #[error("live-run launch activation version is unsupported")]
    UnsupportedActivationVersion,
    #[error("live-run launch bundle validity window is invalid")]
    InvalidBundleWindow,
    #[error("live-run launch activation validity window is invalid")]
    InvalidActivationWindow,
    #[error("live-run launch bundle field is invalid: {0}")]
    InvalidField(String),
    #[error("live-run launch bundle digest mismatch")]
    BundleDigestMismatch,
    #[error("live-run launch bundle does not match its artifacts: {0}")]
    ArtifactBindingMismatch(String),
    #[error("live-run launch activation does not match the bundle")]
    ActivationBindingMismatch,
    #[error("live-run launch activation key mismatch")]
    ActivationKeyMismatch,
    #[error("live-run launch activation signature is invalid")]
    InvalidSignature,
    #[error("live-run launch activation is expired")]
    ActivationExpired,
    #[error("live-run launch activation was already consumed")]
    ActivationReplay,
    #[error("live-run DNS resolution failed: {0}")]
    DnsResolution(String),
    #[error("live-run DNS result is invalid: {0}")]
    InvalidDnsResult(String),
    #[error("live-run DNS context was reused")]
    DnsContextReused,
    #[error("live-run gateway denied the request: {0}")]
    GatewayDenied(String),
    #[error("live-run transport authorization did not issue a ticket")]
    MissingTransportTicket,
    #[error("live-run execution became indeterminate: {0}")]
    ExecutionIndeterminate(String),
    #[error("live-run host is already terminal")]
    HostTerminal,
    #[error("live-run host teardown has already consumed the provisioned session")]
    SessionAlreadyConsumed,
    #[error("live-run host teardown failed: {0}")]
    TeardownFailed(String),
    #[error(
        "live-run host initialization failed ({initialization}) and external session cleanup failed ({cleanup})"
    )]
    InitializationCleanupFailed {
        initialization: String,
        cleanup: String,
    },
    #[error("live-run serialization failed: {0}")]
    Serialization(String),
    #[error("live-run filesystem operation failed: {0}")]
    Io(String),
    #[error(transparent)]
    Unified(#[from] bsl_unified_operator::UnifiedOperatorError),
    #[error(transparent)]
    Runner(#[from] bsl_resumable_runner::RunnerError),
    #[error(transparent)]
    Runtime(#[from] bsl_operator_runtime::RuntimeError),
    #[error(transparent)]
    Provider(#[from] bsl_vault_provider::VaultProviderError),
    #[error(transparent)]
    Injection(#[from] bsl_session_injection::SessionInjectionError),
    #[error(transparent)]
    Policy(#[from] bsl_policy::PolicyError),
    #[error(transparent)]
    Gateway(#[from] bsl_gateway::GatewayError),
    #[error(transparent)]
    Transport(#[from] bsl_pinned_transport::PinnedTransportError),
    #[error(transparent)]
    Adapter(#[from] bsl_live_adapter::LiveAdapterError),
    #[error(transparent)]
    AuthenticatedAdapter(#[from] bsl_live_adapter::LiveAuthenticatedError),
    #[error(transparent)]
    Session(#[from] bsl_session::SessionError),
    #[error(transparent)]
    Vault(#[from] bsl_vault::VaultError),
    #[error(transparent)]
    Operator(#[from] bsl_operator::OperatorError),
}
