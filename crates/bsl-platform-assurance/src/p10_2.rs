#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationStep {
    BindCertificates,
    LoadScenarioFixture,
    ValidatePolicyClosure,
    ValidateAuditClosure,
    ValidateDeterminism,
    Finalize,
}
impl IntegrationStep {
    pub fn canonical() -> [Self; 6] {
        [
            Self::BindCertificates,
            Self::LoadScenarioFixture,
            Self::ValidatePolicyClosure,
            Self::ValidateAuditClosure,
            Self::ValidateDeterminism,
            Self::Finalize,
        ]
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationScenarioFixture {
    pub scenario_id: String,
    pub policy_snapshot_sha256: String,
    pub fixture_root_sha256: String,
    pub expected_steps: BTreeSet<IntegrationStep>,
    pub expected_result_sha256: String,
    pub scenario_sha256: String,
}
impl IntegrationScenarioFixture {
    pub fn new(
        scenario_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        fixture_root_sha256: impl Into<String>,
        expected_result_sha256: impl Into<String>,
    ) -> Result<Self, AssuranceError> {
        let scenario_id = scenario_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        let fixture_root_sha256 = fixture_root_sha256.into();
        let expected_result_sha256 = expected_result_sha256.into();
        validate_identifier(&scenario_id, "integration scenario")?;
        validate_sha256(&policy_snapshot_sha256, "scenario policy")?;
        validate_sha256(&fixture_root_sha256, "scenario fixture root")?;
        validate_sha256(&expected_result_sha256, "scenario expected result")?;
        let expected_steps = IntegrationStep::canonical().into_iter().collect();
        let scenario_sha256 = hash_serializable(&(
            &scenario_id,
            &policy_snapshot_sha256,
            &fixture_root_sha256,
            &expected_steps,
            &expected_result_sha256,
        ))?;
        Ok(Self {
            scenario_id,
            policy_snapshot_sha256,
            fixture_root_sha256,
            expected_steps,
            expected_result_sha256,
            scenario_sha256,
        })
    }
    pub fn verify(&self) -> Result<(), AssuranceError> {
        let canonical = IntegrationStep::canonical()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let expected = hash_serializable(&(
            &self.scenario_id,
            &self.policy_snapshot_sha256,
            &self.fixture_root_sha256,
            &self.expected_steps,
            &self.expected_result_sha256,
        ))?;
        if self.expected_steps != canonical || expected != self.scenario_sha256 {
            return Err(AssuranceError::InvalidBinding(
                "scenario step set or digest".into(),
            ));
        }
        Ok(())
    }
}
