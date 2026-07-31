#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionClass {
    Documentation,
    OperationalNote,
    HardSafety,
    IdentityBinding,
    AuditIntegrity,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssuranceExceptionRequest {
    pub request_id: String,
    pub class: ExceptionClass,
    pub requirement_id: String,
    pub reason_sha256: String,
    pub request_sha256: String,
}
impl AssuranceExceptionRequest {
    pub fn new(
        request_id: impl Into<String>,
        class: ExceptionClass,
        requirement_id: impl Into<String>,
        reason_sha256: impl Into<String>,
    ) -> Result<Self, AssuranceError> {
        let request_id = request_id.into();
        let requirement_id = requirement_id.into();
        let reason_sha256 = reason_sha256.into();
        validate_identifier(&request_id, "exception request")?;
        validate_identifier(&requirement_id, "exception requirement")?;
        validate_sha256(&reason_sha256, "exception reason")?;
        let request_sha256 =
            hash_serializable(&(&request_id, class, &requirement_id, &reason_sha256))?;
        Ok(Self {
            request_id,
            class,
            requirement_id,
            reason_sha256,
            request_sha256,
        })
    }
    pub fn is_waivable(&self) -> bool {
        matches!(
            self.class,
            ExceptionClass::Documentation | ExceptionClass::OperationalNote
        )
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExceptionDecision {
    pub request_sha256: String,
    pub accepted: bool,
    pub decision_sha256: String,
}
#[derive(Debug, Default)]
pub struct AssuranceExceptionAuthority;
impl AssuranceExceptionAuthority {
    pub fn decide(
        &self,
        request: &AssuranceExceptionRequest,
    ) -> Result<ExceptionDecision, AssuranceError> {
        let accepted = request.is_waivable();
        let decision_sha256 = hash_serializable(&(&request.request_sha256, accepted))?;
        Ok(ExceptionDecision {
            request_sha256: request.request_sha256.clone(),
            accepted,
            decision_sha256,
        })
    }
}
