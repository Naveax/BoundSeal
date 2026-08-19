#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemFreezeManifest {
    pub freeze_id: String,
    pub policy_snapshot_sha256: String,
    pub platform_release_certificate_sha256: String,
    pub integration_certificate_sha256: String,
    pub operator_control_certificate_sha256: String,
    pub component_roots: BTreeMap<String, String>,
    pub schema_roots: BTreeMap<String, String>,
    pub freeze_sha256: String,
}
