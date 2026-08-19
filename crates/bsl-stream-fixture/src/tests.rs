use nxb_executor::{
    ExecutionControl, ExecutionLimits, ExecutorConfig, PermitExecutor, SyntheticBackend,
    SyntheticScenario,
};
use nxb_stream::{
    BoundedByteStream, StreamControl, StreamLimits, StreamOperationOutcome, StreamState,
};
use nxb_transport::{TransportPermit, TransportScheme};

use super::{FixtureReadEvent, FixtureWriteEvent, InMemoryDuplex};

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

fn stream(backend: InMemoryDuplex, limits: StreamLimits) -> BoundedByteStream<InMemoryDuplex> {
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
    BoundedByteStream::open(&permit, &receipt, executor.audit(), limits, backend).unwrap()
}

#[test]
fn fragments_reads_and_audits_only_hash_and_lengths() {
    let backend = InMemoryDuplex::new(
        [FixtureReadEvent::Bytes {
            bytes: b"abcdef".to_vec(),
            elapsed_milliseconds: 1,
        }],
        [],
    )
    .with_read_fragment_limit(2);
    let mut stream = stream(backend, StreamLimits::default());

    let first = stream.read(4, StreamControl::default()).unwrap();
    let second = stream.read(4, StreamControl::default()).unwrap();

    assert_eq!(first.bytes, b"ab");
    assert_eq!(second.bytes, b"cd");
    assert_eq!(first.receipt.transferred_bytes, 2);
    assert!(first.receipt.payload_sha256.is_some());
    assert_eq!(stream.audit().records()[1].event.transferred_bytes, 2);
    stream.audit().verify().unwrap();
}

#[test]
fn models_partial_write_and_backpressure() {
    let backend = InMemoryDuplex::new(
        [],
        [
            FixtureWriteEvent::Accept {
                maximum_bytes: 2,
                elapsed_milliseconds: 1,
            },
            FixtureWriteEvent::Backpressure {
                elapsed_milliseconds: 1,
            },
        ],
    );
    let mut stream = stream(backend, StreamLimits::default());

    let first = stream.write(b"abcd", StreamControl::default()).unwrap();
    let second = stream.write(b"ef", StreamControl::default()).unwrap();

    assert_eq!(first.receipt.outcome, StreamOperationOutcome::PartialWrite);
    assert_eq!(first.receipt.transferred_bytes, 2);
    assert_eq!(second.receipt.outcome, StreamOperationOutcome::Backpressure);
    assert_eq!(stream.backend().captured_writes(), &[b"ab".to_vec()]);
}

#[test]
fn read_budget_rejects_before_an_extra_backend_call() {
    let backend = InMemoryDuplex::new(
        [
            FixtureReadEvent::Bytes {
                bytes: b"ab".to_vec(),
                elapsed_milliseconds: 0,
            },
            FixtureReadEvent::Bytes {
                bytes: b"cd".to_vec(),
                elapsed_milliseconds: 0,
            },
        ],
        [],
    );
    let limits = StreamLimits {
        maximum_read_bytes: 3,
        maximum_write_bytes: 3,
        maximum_operation_bytes: 3,
        read_deadline_milliseconds: 5,
        write_deadline_milliseconds: 5,
        total_deadline_milliseconds: 10,
        maximum_operations: 10,
    };
    let mut stream = stream(backend, limits);

    stream.read(2, StreamControl::default()).unwrap();
    let rejected = stream.read(2, StreamControl::default()).unwrap();

    assert_eq!(
        rejected.receipt.outcome,
        StreamOperationOutcome::ReadBudgetExceeded
    );
    assert_eq!(stream.state(), StreamState::BudgetExceeded);
    assert_eq!(stream.backend().read_observations().len(), 1);
}

#[test]
fn operation_deadline_discards_late_bytes() {
    let backend = InMemoryDuplex::new(
        [FixtureReadEvent::Bytes {
            bytes: b"late".to_vec(),
            elapsed_milliseconds: 6,
        }],
        [],
    );
    let limits = StreamLimits {
        read_deadline_milliseconds: 5,
        write_deadline_milliseconds: 5,
        total_deadline_milliseconds: 10,
        ..StreamLimits::default()
    };
    let mut stream = stream(backend, limits);

    let result = stream.read(4, StreamControl::default()).unwrap();

    assert!(result.bytes.is_empty());
    assert_eq!(result.receipt.outcome, StreamOperationOutcome::ReadTimeout);
    assert_eq!(stream.state(), StreamState::TimedOut);
}

#[test]
fn eof_closes_only_the_read_half() {
    let backend = InMemoryDuplex::new(
        [FixtureReadEvent::Eof {
            elapsed_milliseconds: 0,
        }],
        [FixtureWriteEvent::Accept {
            maximum_bytes: 8,
            elapsed_milliseconds: 0,
        }],
    );
    let mut stream = stream(backend, StreamLimits::default());

    let read = stream.read(1, StreamControl::default()).unwrap();
    let write = stream.write(b"x", StreamControl::default()).unwrap();

    assert_eq!(read.receipt.outcome, StreamOperationOutcome::Eof);
    assert_eq!(write.receipt.outcome, StreamOperationOutcome::Written);
    assert_eq!(stream.state(), StreamState::ReadClosed);
}

#[test]
fn truncated_read_is_terminal_but_hashes_returned_prefix() {
    let backend = InMemoryDuplex::new(
        [FixtureReadEvent::Truncated {
            bytes: b"partial".to_vec(),
            elapsed_milliseconds: 1,
        }],
        [],
    );
    let mut stream = stream(backend, StreamLimits::default());

    let result = stream.read(7, StreamControl::default()).unwrap();

    assert_eq!(result.bytes, b"partial");
    assert_eq!(result.receipt.outcome, StreamOperationOutcome::Truncated);
    assert!(result.receipt.payload_sha256.is_some());
    assert_eq!(stream.state(), StreamState::Truncated);
}

#[test]
fn reset_and_backend_failure_are_distinct_terminal_states() {
    let reset_backend = InMemoryDuplex::new(
        [FixtureReadEvent::Reset {
            elapsed_milliseconds: 1,
        }],
        [],
    );
    let mut reset_stream = stream(reset_backend, StreamLimits::default());
    let reset = reset_stream.read(1, StreamControl::default()).unwrap();
    assert_eq!(reset.receipt.outcome, StreamOperationOutcome::Reset);
    assert_eq!(reset_stream.state(), StreamState::Reset);

    let failure_backend = InMemoryDuplex::new(
        [FixtureReadEvent::Failure {
            code: "connection_aborted".into(),
            elapsed_milliseconds: 1,
        }],
        [],
    );
    let mut failure_stream = stream(failure_backend, StreamLimits::default());
    let failure = failure_stream.read(1, StreamControl::default()).unwrap();
    assert!(matches!(
        failure.receipt.outcome,
        StreamOperationOutcome::BackendFailure { .. }
    ));
    assert_eq!(failure_stream.state(), StreamState::BackendFailed);
}

#[test]
fn emergency_stop_prevents_backend_use() {
    let backend = InMemoryDuplex::new(
        [FixtureReadEvent::Bytes {
            bytes: b"secret".to_vec(),
            elapsed_milliseconds: 0,
        }],
        [],
    );
    let mut stream = stream(backend, StreamLimits::default());

    let result = stream
        .read(
            6,
            StreamControl {
                cancel_requested: false,
                emergency_stop_requested: true,
            },
        )
        .unwrap();

    assert!(result.bytes.is_empty());
    assert_eq!(
        result.receipt.outcome,
        StreamOperationOutcome::EmergencyStopped
    );
    assert_eq!(stream.backend().read_observations().len(), 0);
    assert_eq!(stream.state(), StreamState::EmergencyStopped);
}

#[test]
fn close_marks_fixture_and_stream_closed() {
    let backend = InMemoryDuplex::default();
    let mut stream = stream(backend, StreamLimits::default());

    let receipt = stream.close().unwrap();

    assert_eq!(receipt.outcome, StreamOperationOutcome::Closed);
    assert_eq!(stream.state(), StreamState::Closed);
    assert!(stream.backend().is_closed());
}
