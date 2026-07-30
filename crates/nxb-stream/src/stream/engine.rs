use nxb_executor::{ExecutionReceipt, ExecutorAuditChain};
use nxb_transport::TransportPermit;
use sha2::{Digest, Sha256};

use super::{
    binding::{stream_grant, validate_execution_binding},
    outcome::{classify_read, classify_write, control_outcome, terminal_state},
};
use crate::{
    ByteStreamBackend, StreamAuditChain, StreamAuditEvent, StreamControl, StreamDirection,
    StreamError, StreamGrant, StreamLimits, StreamOpenError, StreamOperationOutcome,
    StreamOperationReceipt, StreamReadResult, StreamReceipt, StreamState, StreamWriteResult,
};

#[derive(Debug)]
pub struct BoundedByteStream<B> {
    grant: StreamGrant,
    limits: StreamLimits,
    backend: B,
    state: StreamState,
    read_bytes: u64,
    written_bytes: u64,
    elapsed_milliseconds: u64,
    operation_count: u64,
    audit: StreamAuditChain,
}

impl<B: ByteStreamBackend> BoundedByteStream<B> {
    pub fn open(
        permit: &TransportPermit,
        execution_receipt: &ExecutionReceipt,
        executor_audit: &ExecutorAuditChain,
        limits: StreamLimits,
        backend: B,
    ) -> Result<Self, StreamOpenError> {
        let limits = limits.validate()?;
        executor_audit
            .verify()
            .map_err(StreamOpenError::InvalidExecutorAudit)?;
        let executor_record = executor_audit
            .records()
            .iter()
            .find(|record| record.event.execution_id == execution_receipt.execution_id)
            .ok_or(StreamOpenError::MissingExecutorAuditRecord)?;
        validate_execution_binding(permit, execution_receipt, executor_record)?;

        let grant = stream_grant(permit, execution_receipt, &executor_record.record_hash);
        let audit = StreamAuditChain::new(executor_record.record_hash.clone())?;
        let mut stream = Self {
            grant,
            limits,
            backend,
            state: StreamState::Open,
            read_bytes: 0,
            written_bytes: 0,
            elapsed_milliseconds: 0,
            operation_count: 0,
            audit,
        };
        stream
            .record(
                None,
                StreamOperationOutcome::Opened,
                OperationMetrics::default(),
                StreamState::Open,
                StreamState::Open,
            )
            .map_err(|error| {
                StreamOpenError::BindingMismatch(format!("initial_stream_audit:{error}"))
            })?;
        Ok(stream)
    }

    pub fn grant(&self) -> &StreamGrant {
        &self.grant
    }

    pub fn state(&self) -> StreamState {
        self.state
    }

    pub fn audit(&self) -> &StreamAuditChain {
        &self.audit
    }

    #[cfg(test)]
    pub(crate) fn audit_mut(&mut self) -> &mut StreamAuditChain {
        &mut self.audit
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn read(
        &mut self,
        maximum_bytes: u64,
        control: StreamControl,
    ) -> Result<StreamReadResult, StreamError> {
        self.validate_operation_size(maximum_bytes)?;
        self.ensure_readable()?;

        if let Some(outcome) = control_outcome(control) {
            return self.finish_read_without_backend(maximum_bytes, outcome);
        }
        if self.operation_count >= self.limits.maximum_operations {
            return self.finish_read_without_backend(
                maximum_bytes,
                StreamOperationOutcome::OperationBudgetExceeded,
            );
        }
        if maximum_bytes
            > self
                .limits
                .maximum_read_bytes
                .saturating_sub(self.read_bytes)
        {
            return self.finish_read_without_backend(
                maximum_bytes,
                StreamOperationOutcome::ReadBudgetExceeded,
            );
        }

        let before = self.state;
        let report = self
            .backend
            .read(maximum_bytes, self.limits.read_deadline_milliseconds);
        let elapsed = report.elapsed_milliseconds;
        let total_after = self.elapsed_milliseconds.saturating_add(elapsed);
        if elapsed > self.limits.read_deadline_milliseconds {
            self.elapsed_milliseconds = total_after;
            self.state = StreamState::TimedOut;
            let receipt = self.record(
                Some(StreamDirection::Read),
                StreamOperationOutcome::ReadTimeout,
                OperationMetrics::requested(maximum_bytes, elapsed),
                before,
                self.state,
            )?;
            return Ok(StreamReadResult {
                bytes: Vec::new(),
                receipt,
            });
        }
        if total_after > self.limits.total_deadline_milliseconds {
            self.elapsed_milliseconds = total_after;
            self.state = StreamState::TimedOut;
            let receipt = self.record(
                Some(StreamDirection::Read),
                StreamOperationOutcome::TotalTimeout,
                OperationMetrics::requested(maximum_bytes, elapsed),
                before,
                self.state,
            )?;
            return Ok(StreamReadResult {
                bytes: Vec::new(),
                receipt,
            });
        }
        self.elapsed_milliseconds = total_after;

        let (bytes, outcome, next_state) = classify_read(report.status, maximum_bytes, self.state);
        let transferred = bytes.len() as u64;
        if self.read_bytes.saturating_add(transferred) > self.limits.maximum_read_bytes {
            self.state = StreamState::BudgetExceeded;
            let receipt = self.record(
                Some(StreamDirection::Read),
                StreamOperationOutcome::ReadBudgetExceeded,
                OperationMetrics::requested(maximum_bytes, elapsed),
                before,
                self.state,
            )?;
            return Ok(StreamReadResult {
                bytes: Vec::new(),
                receipt,
            });
        }

        self.read_bytes = self.read_bytes.saturating_add(transferred);
        self.state = next_state;
        let metrics = OperationMetrics {
            requested_bytes: maximum_bytes,
            transferred_bytes: transferred,
            payload_sha256: (!bytes.is_empty()).then(|| payload_hash(&bytes)),
            elapsed_milliseconds: elapsed,
        };
        let receipt = self.record(
            Some(StreamDirection::Read),
            outcome,
            metrics,
            before,
            self.state,
        )?;
        Ok(StreamReadResult { bytes, receipt })
    }

    pub fn write(
        &mut self,
        bytes: &[u8],
        control: StreamControl,
    ) -> Result<StreamWriteResult, StreamError> {
        let requested = bytes.len() as u64;
        self.validate_operation_size(requested)?;
        self.ensure_writable()?;

        if let Some(outcome) = control_outcome(control) {
            return self.finish_write_without_backend(requested, outcome);
        }
        if self.operation_count >= self.limits.maximum_operations {
            return self.finish_write_without_backend(
                requested,
                StreamOperationOutcome::OperationBudgetExceeded,
            );
        }
        if requested
            > self
                .limits
                .maximum_write_bytes
                .saturating_sub(self.written_bytes)
        {
            return self.finish_write_without_backend(
                requested,
                StreamOperationOutcome::WriteBudgetExceeded,
            );
        }

        let before = self.state;
        let report = self
            .backend
            .write(bytes, self.limits.write_deadline_milliseconds);
        let elapsed = report.elapsed_milliseconds;
        let total_after = self.elapsed_milliseconds.saturating_add(elapsed);
        if elapsed > self.limits.write_deadline_milliseconds {
            self.elapsed_milliseconds = total_after;
            self.state = StreamState::TimedOut;
            let receipt = self.record(
                Some(StreamDirection::Write),
                StreamOperationOutcome::WriteTimeout,
                OperationMetrics::requested(requested, elapsed),
                before,
                self.state,
            )?;
            return Ok(StreamWriteResult { receipt });
        }
        if total_after > self.limits.total_deadline_milliseconds {
            self.elapsed_milliseconds = total_after;
            self.state = StreamState::TimedOut;
            let receipt = self.record(
                Some(StreamDirection::Write),
                StreamOperationOutcome::TotalTimeout,
                OperationMetrics::requested(requested, elapsed),
                before,
                self.state,
            )?;
            return Ok(StreamWriteResult { receipt });
        }
        self.elapsed_milliseconds = total_after;

        let (accepted, outcome, next_state) = classify_write(report.status, requested, self.state);
        if self.written_bytes.saturating_add(accepted) > self.limits.maximum_write_bytes {
            self.state = StreamState::BudgetExceeded;
            let receipt = self.record(
                Some(StreamDirection::Write),
                StreamOperationOutcome::WriteBudgetExceeded,
                OperationMetrics::requested(requested, elapsed),
                before,
                self.state,
            )?;
            return Ok(StreamWriteResult { receipt });
        }

        self.written_bytes = self.written_bytes.saturating_add(accepted);
        self.state = next_state;
        let metrics = OperationMetrics {
            requested_bytes: requested,
            transferred_bytes: accepted,
            payload_sha256: (accepted > 0).then(|| payload_hash(&bytes[..accepted as usize])),
            elapsed_milliseconds: elapsed,
        };
        let receipt = self.record(
            Some(StreamDirection::Write),
            outcome,
            metrics,
            before,
            self.state,
        )?;
        Ok(StreamWriteResult { receipt })
    }

    pub fn close(&mut self) -> Result<StreamOperationReceipt, StreamError> {
        if self.state.is_terminal() {
            return Err(StreamError::TerminalState(self.state));
        }
        let before = self.state;
        self.backend.close();
        self.state = StreamState::Closed;
        self.record(
            None,
            StreamOperationOutcome::Closed,
            OperationMetrics::default(),
            before,
            self.state,
        )
    }

    pub fn receipt(&self) -> StreamReceipt {
        StreamReceipt {
            stream_id: self.grant.stream_id.clone(),
            execution_id: self.grant.execution_id.clone(),
            executor_id: self.grant.executor_id.clone(),
            ticket_id: self.grant.ticket_id.clone(),
            decision_id: self.grant.decision_id.clone(),
            dns_context_id: self.grant.dns_context_id.clone(),
            binding_hash: self.grant.binding_hash.clone(),
            endpoint_fingerprint: self.grant.endpoint_fingerprint.clone(),
            executor_audit_anchor: self.grant.executor_audit_anchor.clone(),
            stream_audit_tail: self.audit.tail_hash().into(),
            state: self.state,
            read_bytes: self.read_bytes,
            written_bytes: self.written_bytes,
            elapsed_milliseconds: self.elapsed_milliseconds,
            operation_count: self.operation_count,
        }
    }

    pub fn into_backend(self) -> B {
        self.backend
    }

    fn validate_operation_size(&self, requested: u64) -> Result<(), StreamError> {
        if requested == 0 || requested > self.limits.maximum_operation_bytes {
            return Err(StreamError::InvalidOperationSize);
        }
        Ok(())
    }

    fn ensure_readable(&self) -> Result<(), StreamError> {
        match self.state {
            StreamState::Open | StreamState::WriteClosed => Ok(()),
            StreamState::ReadClosed | StreamState::Closed => Err(StreamError::ReadSideClosed),
            state => Err(StreamError::TerminalState(state)),
        }
    }

    fn ensure_writable(&self) -> Result<(), StreamError> {
        match self.state {
            StreamState::Open | StreamState::ReadClosed => Ok(()),
            StreamState::WriteClosed | StreamState::Closed => Err(StreamError::WriteSideClosed),
            state => Err(StreamError::TerminalState(state)),
        }
    }

    fn finish_read_without_backend(
        &mut self,
        requested: u64,
        outcome: StreamOperationOutcome,
    ) -> Result<StreamReadResult, StreamError> {
        let before = self.state;
        self.state = terminal_state(&outcome, self.state);
        let receipt = self.record(
            Some(StreamDirection::Read),
            outcome,
            OperationMetrics::requested(requested, 0),
            before,
            self.state,
        )?;
        Ok(StreamReadResult {
            bytes: Vec::new(),
            receipt,
        })
    }

    fn finish_write_without_backend(
        &mut self,
        requested: u64,
        outcome: StreamOperationOutcome,
    ) -> Result<StreamWriteResult, StreamError> {
        let before = self.state;
        self.state = terminal_state(&outcome, self.state);
        let receipt = self.record(
            Some(StreamDirection::Write),
            outcome,
            OperationMetrics::requested(requested, 0),
            before,
            self.state,
        )?;
        Ok(StreamWriteResult { receipt })
    }

    fn record(
        &mut self,
        direction: Option<StreamDirection>,
        outcome: StreamOperationOutcome,
        metrics: OperationMetrics,
        state_before: StreamState,
        state_after: StreamState,
    ) -> Result<StreamOperationReceipt, StreamError> {
        self.operation_count = self.operation_count.saturating_add(1);
        let operation_id = format!(
            "{}-operation-{:020}",
            self.grant.stream_id, self.operation_count
        );
        let receipt = StreamOperationReceipt {
            operation_id: operation_id.clone(),
            stream_id: self.grant.stream_id.clone(),
            direction,
            outcome: outcome.clone(),
            requested_bytes: metrics.requested_bytes,
            transferred_bytes: metrics.transferred_bytes,
            payload_sha256: metrics.payload_sha256.clone(),
            elapsed_milliseconds: metrics.elapsed_milliseconds,
            cumulative_read_bytes: self.read_bytes,
            cumulative_written_bytes: self.written_bytes,
            state_before,
            state_after,
        };
        self.audit.append(StreamAuditEvent {
            operation_id,
            stream_id: self.grant.stream_id.clone(),
            execution_id: self.grant.execution_id.clone(),
            executor_id: self.grant.executor_id.clone(),
            ticket_id: self.grant.ticket_id.clone(),
            decision_id: self.grant.decision_id.clone(),
            dns_context_id: self.grant.dns_context_id.clone(),
            binding_hash: self.grant.binding_hash.clone(),
            endpoint_fingerprint: self.grant.endpoint_fingerprint.clone(),
            executor_audit_anchor: self.grant.executor_audit_anchor.clone(),
            remote_ip: self.grant.remote_ip.clone(),
            port: self.grant.port,
            scheme: self.grant.scheme.clone(),
            sni: self.grant.sni.clone(),
            http_host: self.grant.http_host.clone(),
            redirect_depth: self.grant.redirect_depth,
            direction: direction.map(|value| value.code().into()),
            outcome: outcome.code().into(),
            outcome_details: outcome.details(),
            requested_bytes: metrics.requested_bytes,
            transferred_bytes: metrics.transferred_bytes,
            payload_sha256: metrics.payload_sha256,
            elapsed_milliseconds: metrics.elapsed_milliseconds,
            cumulative_read_bytes: self.read_bytes,
            cumulative_written_bytes: self.written_bytes,
            state_before: state_before.code().into(),
            state_after: state_after.code().into(),
        })?;
        Ok(receipt)
    }
}

#[derive(Debug, Clone, Default)]
struct OperationMetrics {
    requested_bytes: u64,
    transferred_bytes: u64,
    payload_sha256: Option<String>,
    elapsed_milliseconds: u64,
}

impl OperationMetrics {
    fn requested(requested_bytes: u64, elapsed_milliseconds: u64) -> Self {
        Self {
            requested_bytes,
            elapsed_milliseconds,
            ..Self::default()
        }
    }
}

fn payload_hash(bytes: &[u8]) -> String {
    to_lower_hex(&Sha256::digest(bytes))
}

fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
