#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssuranceCoverageMatrix {
    pub policy_snapshot_sha256: String,
    pub requirements: BTreeMap<String, AssuranceRequirement>,
    pub evidence: BTreeMap<String, Vec<CoverageEvidence>>,
    pub matrix_sha256: String,
}
