#![forbid(unsafe_code)]

mod contract;
mod dns;
mod error;
mod host;

pub use contract::{
    consume_launch_activation_once, ConsumedLiveRunLaunchActivation,
    LiveRunLaunchActivationCertificate, LiveRunLaunchActivationPayload, LiveRunLaunchBundle,
    LiveRunLaunchBundleParameters, LIVE_RUN_LAUNCH_ACTIVATION_VERSION,
    LIVE_RUN_LAUNCH_BUNDLE_VERSION,
};
pub use dns::{
    DnsResolutionFailure, DnsResolutionRequest, LiveDnsResolution, LiveDnsResolver,
    StaticDnsResolver,
};
pub use error::LiveRunHostError;
pub use host::{LiveRunHost, LiveRunHostInputs, LiveRunStepOutcome, LiveRunTeardownOutcome};

#[cfg(test)]
mod tests;
