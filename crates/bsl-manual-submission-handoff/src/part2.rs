#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManualSubmissionHandoffCertificate {
    pub manifest: ManualSubmissionHandoffManifest,
    pub signature_hex: String,
}

impl ManualSubmissionHandoffCertificate {
    pub fn verify(
        &self,
        plan: &UnifiedOperatorPlan,
        closure: &RunClosureCertificate,
        report: &ReportBundle,
        export_manifest: &ExportManifest,
        public_key: &[u8],
    ) -> Result<(), ManualHandoffError> {
        closure.verify(plan, public_key)?;
        self.manifest
            .verify(plan, closure, report, export_manifest)?;
        if public_key.len() != 32
            || lower_hex(&Sha256::digest(public_key)) != plan.activation_key_id_sha256
        {
            return Err(ManualHandoffError::PublicKeyMismatch);
        }
        let signature = decode_hex(&self.signature_hex)?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&self.manifest.signing_bytes()?, &signature)
            .map_err(|_| ManualHandoffError::InvalidSignature)
    }
}
