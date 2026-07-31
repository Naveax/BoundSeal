impl FinalAssuranceAuthority {
    pub fn audit(&self) -> &AssuranceAuditChain {
        &self.audit
    }
}
