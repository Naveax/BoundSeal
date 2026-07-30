use crate::TlsSessionGrant;

impl TlsSessionGrant {
    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn binding_hash(&self) -> &str {
        &self.binding_hash
    }

    pub fn stream_audit_anchor(&self) -> &str {
        &self.stream_audit_anchor
    }

    pub fn http_host(&self) -> &str {
        &self.http_host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn redirect_depth(&self) -> u8 {
        self.redirect_depth
    }
}
