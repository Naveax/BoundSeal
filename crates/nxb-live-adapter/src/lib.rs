mod backend;
mod model;
mod pipeline;

pub use backend::{LiveConnectBackend, LiveTlsByteStream};
pub use model::{
    LiveAdapterConfig, LiveAdapterError, LiveAdapterLimits, LivePassiveReceipt,
    LivePassiveRequest, LivePassiveResult, LiveTlsObservation, PassiveMethod,
    MAX_LIVE_REQUEST_TARGET_BYTES,
};
pub use pipeline::LivePassivePipeline;

impl LiveAdapterError {
    #[doc(hidden)]
    #[allow(non_snake_case)]
    pub(crate) fn TlsConfiguration(message: String) -> Self {
        Self::InvalidLimits(format!("TLS configuration: {message}"))
    }
}

#[cfg(test)]
mod tests;
