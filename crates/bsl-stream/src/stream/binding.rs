use nxb_executor::{ExecutionOutcome, ExecutionReceipt, ExecutionState, ExecutorAuditRecord};
use nxb_transport::TransportPermit;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{StreamGrant, StreamOpenError};

pub(super) fn validate_execution_binding(
    permit: &TransportPermit,
    receipt: &ExecutionReceipt,
    record: &ExecutorAuditRecord,
) -> Result<(), StreamOpenError> {
    if receipt.outcome != ExecutionOutcome::Completed
        || receipt.state_history.last() != Some(&ExecutionState::Completed)
    {
        return Err(StreamOpenError::ExecutionNotCompleted);
    }

    let expected_fingerprint = endpoint_fingerprint(permit, &receipt.transport_audit_anchor);
    let checks = [
        (
            receipt.ticket_id == permit.ticket_id && record.event.ticket_id == permit.ticket_id,
            "ticket_id",
        ),
        (
            receipt.decision_id == permit.decision_id
                && record.event.decision_id == permit.decision_id,
            "decision_id",
        ),
        (
            receipt.dns_context_id == permit.dns_context_id
                && record.event.dns_context_id == permit.dns_context_id,
            "dns_context_id",
        ),
        (
            receipt.binding_hash == permit.binding_hash
                && record.event.binding_hash == permit.binding_hash,
            "binding_hash",
        ),
        (
            receipt.endpoint_fingerprint == expected_fingerprint
                && record.event.endpoint_fingerprint == expected_fingerprint,
            "endpoint_fingerprint",
        ),
        (
            record.event.execution_id == receipt.execution_id,
            "execution_id",
        ),
        (
            record.event.executor_id == receipt.executor_id,
            "executor_id",
        ),
        (
            record.event.transport_audit_anchor == receipt.transport_audit_anchor,
            "transport_audit_anchor",
        ),
        (
            record.event.remote_ip == permit.remote_ip.to_string(),
            "remote_ip",
        ),
        (record.event.port == permit.port, "port"),
        (record.event.scheme == permit.scheme.code(), "scheme"),
        (record.event.sni == permit.sni, "sni"),
        (record.event.http_host == permit.http_host, "http_host"),
        (
            record.event.redirect_depth == permit.redirect_depth,
            "redirect_depth",
        ),
        (
            record.event.outcome == ExecutionOutcome::Completed.code(),
            "outcome",
        ),
        (
            record.event.read_bytes == receipt.read_bytes
                && record.event.written_bytes == receipt.written_bytes,
            "byte_counters",
        ),
    ];

    for (matches, field) in checks {
        if !matches {
            return Err(StreamOpenError::BindingMismatch(field.into()));
        }
    }
    Ok(())
}

pub(super) fn stream_grant(
    permit: &TransportPermit,
    receipt: &ExecutionReceipt,
    executor_audit_anchor: &str,
) -> StreamGrant {
    #[derive(Serialize)]
    struct Material<'a> {
        execution_id: &'a str,
        ticket_id: &'a str,
        binding_hash: &'a str,
        endpoint_fingerprint: &'a str,
        executor_audit_anchor: &'a str,
    }

    let bytes = serde_json::to_vec(&Material {
        execution_id: &receipt.execution_id,
        ticket_id: &permit.ticket_id,
        binding_hash: &permit.binding_hash,
        endpoint_fingerprint: &receipt.endpoint_fingerprint,
        executor_audit_anchor,
    })
    .expect("stream grant material is serializable");
    let digest = to_lower_hex(&Sha256::digest(bytes));
    StreamGrant {
        stream_id: format!("stream-{}", &digest[..32]),
        execution_id: receipt.execution_id.clone(),
        executor_id: receipt.executor_id.clone(),
        ticket_id: permit.ticket_id.clone(),
        decision_id: permit.decision_id.clone(),
        dns_context_id: permit.dns_context_id.clone(),
        binding_hash: permit.binding_hash.clone(),
        endpoint_fingerprint: receipt.endpoint_fingerprint.clone(),
        executor_audit_anchor: executor_audit_anchor.into(),
        remote_ip: permit.remote_ip.to_string(),
        port: permit.port,
        scheme: permit.scheme.code().into(),
        sni: permit.sni.clone(),
        http_host: permit.http_host.clone(),
        redirect_depth: permit.redirect_depth,
    }
}

fn endpoint_fingerprint(permit: &TransportPermit, transport_audit_anchor: &str) -> String {
    #[derive(Serialize)]
    struct Material<'a> {
        ticket_id: &'a str,
        decision_id: &'a str,
        dns_context_id: &'a str,
        scheme: &'a str,
        remote_ip: std::net::IpAddr,
        port: u16,
        sni: Option<&'a str>,
        http_host: &'a str,
        redirect_depth: u8,
        binding_hash: &'a str,
        transport_audit_anchor: &'a str,
    }

    let bytes = serde_json::to_vec(&Material {
        ticket_id: &permit.ticket_id,
        decision_id: &permit.decision_id,
        dns_context_id: &permit.dns_context_id,
        scheme: permit.scheme.code(),
        remote_ip: permit.remote_ip,
        port: permit.port,
        sni: permit.sni.as_deref(),
        http_host: &permit.http_host,
        redirect_depth: permit.redirect_depth,
        binding_hash: &permit.binding_hash,
        transport_audit_anchor,
    })
    .expect("endpoint fingerprint material is serializable");
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
