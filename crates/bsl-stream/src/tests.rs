use bsl_executor::{
    ExecutionControl, ExecutionLimits, ExecutionReceipt, ExecutorConfig, PermitExecutor,
    SyntheticBackend, SyntheticScenario,
};
use bsl_transport::{TransportPermit, TransportScheme};

use crate::{
    BackendReadReport, BackendReadStatus, BackendWriteReport, BackendWriteStatus,
    BoundedByteStream, ByteStreamBackend, StreamAuditError, StreamControl, StreamLimits,
    StreamOpenError, StreamOperationOutcome, StreamState,
};

fn permit() -> TransportPermit {
    TransportPermit {
        ticket_id: "ticket-0001".into(),
        decision_id: "decision-0001".into(),
        dns_context_id: "navigation-1".into(),
        scheme: TransportScheme::Https,
        remote_ip: "1.1.1.1".parse().unwrap(),
        port: 443,
        sni: Some("app.example.com".into()),
        http_host: "app.example.com".into(),
        redirect_depth: 0,
        binding_hash: "a".repeat(64),
    }
}

fn execution() -> (
    TransportPermit,
    ExecutionReceipt,
    PermitExecutor<SyntheticBackend>,
) {
    let permit = permit();
    let mut executor = PermitExecutor::new(
        ExecutorConfig {
            executor_id: "fixture-executor".into(),
        },
        SyntheticBackend::new([SyntheticScenario::success(1, 2, 0, 0)]),
    )
    .unwrap();
    let receipt = executor
        .execute(
            &permit,
            &"b".repeat(64),
            ExecutionLimits::default(),
            ExecutionControl::default(),
        )
        .unwrap();
    (permit, receipt, executor)
}

#[derive(Debug, Default)]
struct EmptyBackend;

impl ByteStreamBackend for EmptyBackend {
    fn read(&mut self, _maximum_bytes: u64, _deadline_milliseconds: u64) -> BackendReadReport {
        BackendReadReport {
            elapsed_milliseconds: 0,
            status: BackendReadStatus::Eof,
        }
    }

    fn write(&mut self, bytes: &[u8], _deadline_milliseconds: u64) -> BackendWriteReport {
        BackendWriteReport {
            elapsed_milliseconds: 0,
            status: BackendWriteStatus::Written(bytes.len() as u64),
        }
    }

    fn close(&mut self) {}
}

#[test]
fn opens_only_from_matching_completed_execution_and_audit() {
    let (permit, receipt, executor) = execution();
    let stream = BoundedByteStream::open(
        &permit,
        &receipt,
        executor.audit(),
        StreamLimits::default(),
        EmptyBackend,
    )
    .unwrap();

    assert_eq!(stream.state(), StreamState::Open);
    assert_eq!(
        stream.audit().genesis_anchor(),
        executor.audit().records()[0].record_hash.as_str()
    );
    stream.audit().verify().unwrap();
}

#[test]
fn rejects_mismatched_binding_hash() {
    let (mut permit, receipt, executor) = execution();
    permit.binding_hash = "c".repeat(64);

    let result = BoundedByteStream::open(
        &permit,
        &receipt,
        executor.audit(),
        StreamLimits::default(),
        EmptyBackend,
    );

    assert!(matches!(result, Err(StreamOpenError::BindingMismatch(_))));
}

#[test]
fn rejects_non_completed_execution_receipt() {
    let (permit, mut receipt, executor) = execution();
    receipt.outcome = bsl_executor::ExecutionOutcome::Cancelled;

    let result = BoundedByteStream::open(
        &permit,
        &receipt,
        executor.audit(),
        StreamLimits::default(),
        EmptyBackend,
    );

    assert!(matches!(
        result,
        Err(StreamOpenError::ExecutionNotCompleted)
    ));
}

#[test]
fn audit_detects_modified_operation_metadata() {
    let (permit, receipt, executor) = execution();
    let mut stream = BoundedByteStream::open(
        &permit,
        &receipt,
        executor.audit(),
        StreamLimits::default(),
        EmptyBackend,
    )
    .unwrap();

    stream.audit_mut().records_mut()[0].event.requested_bytes = 99;

    assert_eq!(
        stream.audit().verify(),
        Err(StreamAuditError::RecordHashMismatch { record_index: 0 })
    );
}

#[test]
fn cancellation_is_terminal_without_backend_bytes() {
    let (permit, receipt, executor) = execution();
    let mut stream = BoundedByteStream::open(
        &permit,
        &receipt,
        executor.audit(),
        StreamLimits::default(),
        EmptyBackend,
    )
    .unwrap();

    let result = stream
        .read(
            1,
            StreamControl {
                cancel_requested: true,
                emergency_stop_requested: false,
            },
        )
        .unwrap();

    assert_eq!(result.receipt.outcome, StreamOperationOutcome::Cancelled);
    assert_eq!(stream.state(), StreamState::Cancelled);
    assert_eq!(stream.receipt().read_bytes, 0);
}
