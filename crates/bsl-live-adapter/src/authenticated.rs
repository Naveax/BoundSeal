use nxb_session::SessionBroker;
use nxb_session_injection::{BoundSessionInjection, InjectionUseAuthorization};
use nxb_vault::InMemorySecretVault;
use thiserror::Error;

use crate::{LiveAdapterError, LivePassiveResult};

pub struct LiveSessionInjection<'a> {
    pub bound: &'a BoundSessionInjection,
    pub broker: &'a mut SessionBroker,
    pub vault: &'a mut InMemorySecretVault,
    pub now_epoch_seconds: i64,
}

impl std::fmt::Debug for LiveSessionInjection<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveSessionInjection")
            .field("manifest_sha256", &self.bound.manifest().manifest_sha256)
            .field(
                "session_id_sha256",
                &sha256(self.bound.session_id().as_bytes()),
            )
            .field("now_epoch_seconds", &self.now_epoch_seconds)
            .field("broker", &"<opaque session broker>")
            .field("vault", &"<opaque secret vault>")
            .finish()
    }
}

pub struct LiveAuthenticatedResult {
    pub live: LivePassiveResult,
    pub injection_authorization: InjectionUseAuthorization,
    pub session_audit_tail: String,
    pub vault_audit_tail: String,
}

impl std::fmt::Debug for LiveAuthenticatedResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveAuthenticatedResult")
            .field("injection_authorization", &self.injection_authorization)
            .field("session_audit_tail", &self.session_audit_tail)
            .field("vault_audit_tail", &self.vault_audit_tail)
            .field("live", &"<sensitive authenticated response omitted>")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum LiveAuthenticatedError {
    #[error("live adapter rejected authenticated execution: {0}")]
    Live(#[from] LiveAdapterError),
    #[error("session broker rejected authenticated execution: {0}")]
    Session(#[from] nxb_session::SessionError),
    #[error("session injection boundary rejected authenticated execution: {0}")]
    Injection(#[from] nxb_session_injection::SessionInjectionError),
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
