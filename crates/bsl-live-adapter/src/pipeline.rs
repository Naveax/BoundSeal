use std::time::Duration;

use bsl_executor::{ExecutionControl, ExecutionOutcome, ExecutorConfig, PermitExecutor};
use bsl_http1::Http1Codec;
use bsl_pinned_transport::PinnedTransportCoordinator;
use bsl_session::SessionExchangeOptions;
use bsl_stream::{BoundedByteStream, StreamControl};
use bsl_tls::LibraryVerifiedTlsBinder;
use bsl_transport::{ConnectionAttempt, TicketUseOutcome, TransportScheme};

use crate::{
    authenticated::{LiveAuthenticatedError, LiveAuthenticatedResult, LiveSessionInjection},
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
            let verified_observation = tls_observation
                .library_verified(format!("{}:rustls-webpki", self.config.executor_id))?;
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

    pub fn execute_authenticated(
        &mut self,
        attempt: ConnectionAttempt,
        elapsed_since_authorization: Duration,
        request: LivePassiveRequest,
        execution_control: ExecutionControl,
        stream_control: StreamControl,
        injection: LiveSessionInjection<'_>,
    ) -> Result<LiveAuthenticatedResult, LiveAuthenticatedError> {
        request.validate()?;
        if attempt.scheme != TransportScheme::Https {
            return Err(LiveAdapterError::TlsConfiguration(
                "vault-managed sessions require HTTPS".into(),
            )
            .into());
        }

        let session_metadata = injection.broker.metadata(injection.bound.session_id())?;
        let authorization = injection.bound.authorize_request(
            &session_metadata,
            injection.vault,
            &attempt.http_host,
            "https",
            &request.target,
            request.method.code(),
            injection.now_epoch_seconds,
        )?;
        authorization.verify()?;
        let session_context = injection.bound.session_context();
        let session_id = injection.bound.session_id().to_string();
        let lease_seconds = authorization.lease_seconds;

        let ticket_use = self
            .transport
            .consume_connection_ticket(attempt, elapsed_since_authorization)
            .map_err(LiveAdapterError::from)?;
        let transport_audit_anchor = self.transport.transport_audit().tail_hash().to_string();

        if ticket_use.outcome != TicketUseOutcome::Consumed {
            let live = LivePassiveResult {
                ticket_use,
                execution_receipt: None,
                tls_observation: None,
                stream_receipt: None,
                exchange: None,
                receipt: None,
                transport_audit_anchor,
            };
            return Ok(LiveAuthenticatedResult {
                live,
                injection_authorization: authorization,
                session_audit_tail: injection.broker.audit().tail_hash().to_string(),
                vault_audit_tail: injection.vault.audit().tail_hash().to_string(),
            });
        }

        let Some(permit) = ticket_use.permit.clone() else {
            self.transport.complete_request();
            return Err(LiveAdapterError::ConsumedTicketMissingPermit.into());
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
                return Err(LiveAdapterError::from(error).into());
            }
        };

        if execution.outcome != ExecutionOutcome::Completed {
            self.transport.complete_request();
            let live = LivePassiveResult {
                ticket_use,
                execution_receipt: Some(execution),
                tls_observation: None,
                stream_receipt: None,
                exchange: None,
                receipt: None,
                transport_audit_anchor,
            };
            return Ok(LiveAuthenticatedResult {
                live,
                injection_authorization: authorization,
                session_audit_tail: injection.broker.audit().tail_hash().to_string(),
                vault_audit_tail: injection.vault.audit().tail_hash().to_string(),
            });
        }

        let tls_observation = match self.executor.backend().last_observation().cloned() {
            Some(observation) => observation,
            None => {
                self.transport.complete_request();
                return Err(LiveAdapterError::MissingTlsObservation.into());
            }
        };
        let tls_stream = match self.executor.backend_mut().take_stream() {
            Some(stream) => stream,
            None => {
                self.transport.complete_request();
                return Err(LiveAdapterError::MissingTlsStream.into());
            }
        };
        let executor_audit_tail = self.executor.audit().tail_hash().to_string();
        let http_request = request.to_http1();

        let exchange_result = (|| {
            let stream = BoundedByteStream::open(
                &permit,
                &execution,
                self.executor.audit(),
                self.config.limits.stream,
                tls_stream,
            )
            .map_err(LiveAdapterError::from)?;
            let verified_observation = tls_observation
                .library_verified(format!("{}:rustls-webpki", self.config.executor_id))?;
            let tls_grant = self
                .tls_binder
                .bind(&stream, &verified_observation)
                .map_err(LiveAdapterError::from)?;
            let mut codec =
                Http1Codec::new_verified_tls(stream, &tls_grant, self.config.limits.http)
                    .map_err(LiveAdapterError::from)?;
            let exchange = injection.broker.exchange(
                &session_id,
                &session_context,
                injection.vault,
                &mut codec,
                &http_request,
                SessionExchangeOptions {
                    lease_seconds,
                    now_epoch_seconds: injection.now_epoch_seconds,
                    control: stream_control,
                },
            )?;
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
            Ok::<_, LiveAuthenticatedError>((exchange, stream_receipt, receipt))
        })();

        self.transport.complete_request();
        let (exchange, stream_receipt, receipt) = exchange_result?;
        let live = LivePassiveResult {
            ticket_use,
            execution_receipt: Some(execution),
            tls_observation: Some(tls_observation),
            stream_receipt: Some(stream_receipt),
            exchange: Some(exchange),
            receipt: Some(receipt),
            transport_audit_anchor,
        };
        Ok(LiveAuthenticatedResult {
            live,
            injection_authorization: authorization,
            session_audit_tail: injection.broker.audit().tail_hash().to_string(),
            vault_audit_tail: injection.vault.audit().tail_hash().to_string(),
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
