use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const EVENT_SCHEMA: &str = "nxb.event.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub schema: String,
    pub event_id: String,
    pub run_id: String,
    pub source: String,
    pub kind: EventKind,
    pub captured_at: DateTime<Utc>,
    pub asset: String,
    pub data: Value,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    AssetObserved,
    EndpointObserved,
    RequestObserved,
    ResponseObserved,
    PolicyDecision,
    TestObservation,
    FindingCandidate,
    EvidenceRecorded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub tool_name: String,
    pub tool_version: String,
    pub tool_commit: Option<String>,
    pub policy_decision_id: String,
}

#[derive(Debug, Error)]
pub enum EventError {
    #[error("event JSON could not be parsed: {0}")]
    Parse(String),
    #[error("event is invalid: {0}")]
    Invalid(String),
}

impl EventEnvelope {
    pub fn from_json(input: &str) -> Result<Self, EventError> {
        serde_json::from_str(input).map_err(|error| EventError::Parse(error.to_string()))
    }

    pub fn validate(&self) -> Result<(), EventError> {
        if self.schema != EVENT_SCHEMA {
            return Err(EventError::Invalid(format!(
                "unsupported event schema {}; expected {EVENT_SCHEMA}",
                self.schema
            )));
        }

        validate_identifier("event_id", &self.event_id)?;
        validate_identifier("run_id", &self.run_id)?;
        validate_text("source", &self.source, 128)?;
        validate_text("asset", &self.asset, 2_048)?;
        validate_text("provenance.tool_name", &self.provenance.tool_name, 128)?;
        validate_text("provenance.tool_version", &self.provenance.tool_version, 128)?;
        validate_identifier(
            "provenance.policy_decision_id",
            &self.provenance.policy_decision_id,
        )?;

        if let Some(commit) = &self.provenance.tool_commit {
            if commit.len() < 7
                || commit.len() > 64
                || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(EventError::Invalid(
                    "provenance.tool_commit must be a 7-64 character hexadecimal revision"
                        .into(),
                ));
            }
        }

        if !self.data.is_object() {
            return Err(EventError::Invalid("data must be a JSON object".into()));
        }

        Ok(())
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<(), EventError> {
    validate_text(field, value, 128)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
    }) {
        return Err(EventError::Invalid(format!(
            "{field} contains unsupported characters"
        )));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, maximum_length: usize) -> Result<(), EventError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > maximum_length {
        return Err(EventError::Invalid(format!(
            "{field} must contain 1-{maximum_length} characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    fn event() -> EventEnvelope {
        EventEnvelope {
            schema: EVENT_SCHEMA.into(),
            event_id: "evt-001".into(),
            run_id: "run-001".into(),
            source: "fixture".into(),
            kind: EventKind::EndpointObserved,
            captured_at: Utc::now(),
            asset: "https://app.example.com".into(),
            data: json!({"method": "GET", "path": "/api/me"}),
            provenance: Provenance {
                tool_name: "nxb-fixture".into(),
                tool_version: "0.1.0".into(),
                tool_commit: Some("abcdef0".into()),
                policy_decision_id: "decision-001".into(),
            },
        }
    }

    #[test]
    fn accepts_valid_event() {
        event().validate().unwrap();
    }

    #[test]
    fn rejects_wrong_schema() {
        let mut event = event();
        event.schema = "nxb.event.v2".into();
        assert!(event.validate().is_err());
    }

    #[test]
    fn rejects_non_object_data() {
        let mut event = event();
        event.data = json!([1, 2, 3]);
        assert!(event.validate().is_err());
    }
}
