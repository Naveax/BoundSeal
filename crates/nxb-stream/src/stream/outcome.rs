use crate::{
    BackendReadStatus, BackendWriteStatus, StreamControl, StreamOperationOutcome, StreamState,
};

pub(super) fn classify_read(
    status: BackendReadStatus,
    maximum_bytes: u64,
    state: StreamState,
) -> (Vec<u8>, StreamOperationOutcome, StreamState) {
    match status {
        BackendReadStatus::Data(bytes) if bytes.len() as u64 <= maximum_bytes => {
            (bytes, StreamOperationOutcome::Data, state)
        }
        BackendReadStatus::Data(_) => backend_read_overflow("backend_read_overflow"),
        BackendReadStatus::Eof => (
            Vec::new(),
            StreamOperationOutcome::Eof,
            close_read_side(state),
        ),
        BackendReadStatus::Backpressure => {
            (Vec::new(), StreamOperationOutcome::Backpressure, state)
        }
        BackendReadStatus::Timeout => (
            Vec::new(),
            StreamOperationOutcome::ReadTimeout,
            StreamState::TimedOut,
        ),
        BackendReadStatus::Reset => (
            Vec::new(),
            StreamOperationOutcome::Reset,
            StreamState::Reset,
        ),
        BackendReadStatus::Truncated(bytes) if bytes.len() as u64 <= maximum_bytes => (
            bytes,
            StreamOperationOutcome::Truncated,
            StreamState::Truncated,
        ),
        BackendReadStatus::Truncated(_) => backend_read_overflow("backend_truncated_read_overflow"),
        BackendReadStatus::Failure(code) => (
            Vec::new(),
            StreamOperationOutcome::BackendFailure {
                backend_code: sanitize_backend_code(&code),
            },
            StreamState::BackendFailed,
        ),
    }
}

pub(super) fn classify_write(
    status: BackendWriteStatus,
    requested: u64,
    state: StreamState,
) -> (u64, StreamOperationOutcome, StreamState) {
    match status {
        BackendWriteStatus::Written(accepted) if accepted <= requested => {
            let outcome = if accepted == requested {
                StreamOperationOutcome::Written
            } else {
                StreamOperationOutcome::PartialWrite
            };
            (accepted, outcome, state)
        }
        BackendWriteStatus::Written(_) => (
            0,
            StreamOperationOutcome::BackendFailure {
                backend_code: "backend_write_overflow".into(),
            },
            StreamState::BackendFailed,
        ),
        BackendWriteStatus::Backpressure => (0, StreamOperationOutcome::Backpressure, state),
        BackendWriteStatus::Timeout => (
            0,
            StreamOperationOutcome::WriteTimeout,
            StreamState::TimedOut,
        ),
        BackendWriteStatus::Reset => (0, StreamOperationOutcome::Reset, StreamState::Reset),
        BackendWriteStatus::Closed => (0, StreamOperationOutcome::Closed, close_write_side(state)),
        BackendWriteStatus::Failure(code) => (
            0,
            StreamOperationOutcome::BackendFailure {
                backend_code: sanitize_backend_code(&code),
            },
            StreamState::BackendFailed,
        ),
    }
}

pub(super) fn control_outcome(control: StreamControl) -> Option<StreamOperationOutcome> {
    if control.emergency_stop_requested {
        Some(StreamOperationOutcome::EmergencyStopped)
    } else if control.cancel_requested {
        Some(StreamOperationOutcome::Cancelled)
    } else {
        None
    }
}

pub(super) fn terminal_state(
    outcome: &StreamOperationOutcome,
    current: StreamState,
) -> StreamState {
    match outcome {
        StreamOperationOutcome::Cancelled => StreamState::Cancelled,
        StreamOperationOutcome::EmergencyStopped => StreamState::EmergencyStopped,
        StreamOperationOutcome::ReadTimeout
        | StreamOperationOutcome::WriteTimeout
        | StreamOperationOutcome::TotalTimeout => StreamState::TimedOut,
        StreamOperationOutcome::ReadBudgetExceeded
        | StreamOperationOutcome::WriteBudgetExceeded
        | StreamOperationOutcome::OperationBudgetExceeded => StreamState::BudgetExceeded,
        StreamOperationOutcome::Reset => StreamState::Reset,
        StreamOperationOutcome::Truncated => StreamState::Truncated,
        StreamOperationOutcome::BackendFailure { .. } => StreamState::BackendFailed,
        StreamOperationOutcome::Eof => close_read_side(current),
        StreamOperationOutcome::Closed => close_write_side(current),
        _ => current,
    }
}

fn backend_read_overflow(code: &str) -> (Vec<u8>, StreamOperationOutcome, StreamState) {
    (
        Vec::new(),
        StreamOperationOutcome::BackendFailure {
            backend_code: code.into(),
        },
        StreamState::BackendFailed,
    )
}

fn close_read_side(state: StreamState) -> StreamState {
    match state {
        StreamState::Open => StreamState::ReadClosed,
        StreamState::WriteClosed => StreamState::Closed,
        other => other,
    }
}

fn close_write_side(state: StreamState) -> StreamState {
    match state {
        StreamState::Open => StreamState::WriteClosed,
        StreamState::ReadClosed => StreamState::Closed,
        other => other,
    }
}

fn sanitize_backend_code(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    if is_valid_identifier(&normalized) {
        normalized
    } else {
        "invalid_backend_code".into()
    }
}

fn is_valid_identifier(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}
