use std::time::Duration;

use nxb_executor::{ExecutionControl, ExecutionOutcome, ExecutorConfig, PermitExecutor};
use nxb_http1::Http1Codec;
use nxb_pinned_transport::PinnedTransportCoordinator;
use nxb_stream::{BoundedByteStream, StreamControl};
use nxb_tls::LibraryVerifiedTlsBinder;
use nxb_transport::{ConnectionAttempt, TicketUseOutcome};

use crate::{
    backend::LiveConnectBackend,
    model::{
        build_live_receipt, LiveAdapterConfig, LiveAdapterError, LivePassiveRequest,
        LivePassiveResult,
    },
};

#[derive(Debug)]
pub struct LivePassivePipeline {
    transport: PinnedTransportCoordinator,
    executor: PermitExecutor<LiveConnectBackend>,
    tls_binder: LibraryVerifiedTlsBinder,
    config: LiveAdapterConfig,
}

impl LivePassivePipeline {
    pub fn new(
        transport: PinnedTransportCoordinator,
        config: LiveAdapterConfig,
    ) -> Result<Self, LiveAdapterError> {
        config.validate()?;
        let backend = LiveConnectBackend::with_mozilla_roots()?;
        Self::with_backend(transport, config, backend)
    }

    fn with_backend(
        transport: PinnedTransportCoordinator,
        config: LiveAdapterConfig,
        backend: LiveConnectBackend,
    ) -> Result<Self, LiveAdapterError> {
        let executor = PermitExecutor::new(
            ExecutorConfig {
                executor_id: config.executor_id.clone(),
            },
            backend,
        )?;
        Ok(Self {
            transport,
            executor,
            tls_binder: LibraryVerifiedTlsBinder::new(),
            config,
        })
    }

    pub fn execute(
        &mut self,
        attempt: ConnectionAttempt,
        elapsed_since_authorization: Duration,
        request: LivePassiveRequest,
        execution_control: ExecutionControl,
        stream_control: StreamControl,
    ) -> Result<LivePassiveResult, LiveAdapterError> {
        request.validate()?;
        let ticket_use = self
            .transport
            .consume_connection_ticket(attempt, elapsed_since_authorization)?;
        let transport_audit_anchor = self.transport.transport_audit().tail_hash().to_string();

        if ticket_use.outcome != TicketUseOutcome::Consumed {
            return Ok(LivePassiveResult {
                ticket_use,
                execution_receipt: None,
                tls_observation: None,
                stream_receipt: None,
                exchange: None,
                receipt: None,
                transport_audit_anchor,
            });
        }

        let Some(permit) = ticket_use.permit.clone() else {
            self.transport.complete_request();
            return Err(LiveAdapterError::ConsumedTicketMissingPermit);
        };

        let execution = match self.executor.execute(
            &permit,
            &transport_audit_anchor,
            self.config.limits.execution,
            execution_control,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.transport.complete_request();
                return Err(error.into());
            }
        };

        if execution.outcome != ExecutionOutcome::Completed {
            self.transport.complete_request();
            return Ok(LivePassiveResult {
                ticket_use,
                execution_receipt: Some(execution),
                tls_observation: None,
                stream_receipt: None,
                exchange: None,
                receipt: None,
                transport_audit_anchor,
            });
        }

        let tls_observation = match self.executor.backend().last_observation().cloned() {
            Some(observation) => observation,
            None => {
                self.transport.complete_request();
                return Err(LiveAdapterError::MissingTlsObservation);
            }
        };
        let tls_stream = match self.executor.backend_mut().take_stream() {
            Some(stream) => stream,
            None => {
                self.transport.complete_request();
                return Err(LiveAdapterError::MissingTlsStream);
            }
        };
        let executor_audit_tail = self.executor.audit().tail_hash().to_string();

        let exchange_result = (|| {
            let stream = BoundedByteStream::open(
                &permit,
                &execution,
                self.executor.audit(),
                self.config.limits.stream,
                tls_stream,
            )?;
            let verified_observation = tls_observation.library_verified(format!(
                "{}:rustls-webpki",
                self.config.executor_id
            ))?;
            let tls_grant = self.tls_binder.bind(&stream, &verified_observation)?;
            let mut codec =
                Http1Codec::new_verified_tls(stream, &tls_grant, self.config.limits.http)?;
            let exchange = codec.exchange(&request.to_http1(), stream_control)?;
            let stream_receipt = codec.stream().receipt();
            let receipt = build_live_receipt(
                &tls_observation,
                &exchange,
                &stream_receipt,
                &execution,
                &transport_audit_anchor,
                &executor_audit_tail,
            )?;
            receipt.verify()?;
            Ok::<_, LiveAdapterError>((exchange, stream_receipt, receipt))
        })();

        // Ticket consumption reserves exactly one gateway in-flight slot. The slot covers
        // connection, TLS and HTTP parsing and is released once on every terminal path.
        self.transport.complete_request();
        let (exchange, stream_receipt, receipt) = exchange_result?;

        Ok(LivePassiveResult {
            ticket_use,
            execution_receipt: Some(execution),
            tls_observation: Some(tls_observation),
            stream_receipt: Some(stream_receipt),
            exchange: Some(exchange),
            receipt: Some(receipt),
            transport_audit_anchor,
        })
    }

    pub fn transport(&self) -> &PinnedTransportCoordinator {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut PinnedTransportCoordinator {
        &mut self.transport
    }

    pub fn executor(&self) -> &PermitExecutor<LiveConnectBackend> {
        &self.executor
    }

    pub fn config(&self) -> &LiveAdapterConfig {
        &self.config
    }
}
