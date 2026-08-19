use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MILESTONE_START: u16 = 0;
pub const MILESTONE_END: u16 = 119;
pub const WORKSPACE_CRATE_COUNT: u16 = 34;

const DEMO_SCHEMA: &str = "bsl.demo.receipt.v1";
const DEMO_MODE: &str = "synthetic-networkless";
const DEMO_STAGES: [&str; 12] = [
    "policy_compilation",
    "scope_gateway",
    "destination_transport_authorization",
    "bounded_stream",
    "tls_peer_identity",
    "strict_http_exchange",
    "content_analysis",
    "request_planning",
    "passive_finding",
    "safe_validation",
    "evidence_reporting",
    "assurance_program_closure",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DemoStageReceipt {
    pub sequence: u16,
    pub stage: String,
    pub previous_hash: String,
    pub record_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DemoReceipt {
    pub schema: String,
    pub mode: String,
    pub milestone_start: u16,
    pub milestone_end: u16,
    pub workspace_crate_count: u16,
    pub stage_count: u16,
    pub genesis_hash: String,
    pub tail_hash: String,
    pub stages: Vec<DemoStageReceipt>,
}

pub fn build_demo_receipt() -> Result<DemoReceipt> {
    let genesis_hash = hash_bytes(
        format!(
            "{DEMO_SCHEMA}\0{DEMO_MODE}\0{MILESTONE_START}\0{MILESTONE_END}\0{WORKSPACE_CRATE_COUNT}"
        )
        .as_bytes(),
    );
    let mut previous_hash = genesis_hash.clone();
    let mut stages = Vec::with_capacity(DEMO_STAGES.len());

    for (index, stage) in DEMO_STAGES.iter().enumerate() {
        let sequence = u16::try_from(index + 1).context("demo stage sequence overflow")?;
        let record_hash = hash_bytes(format!("{sequence}\0{stage}\0{previous_hash}").as_bytes());
        stages.push(DemoStageReceipt {
            sequence,
            stage: (*stage).to_string(),
            previous_hash,
            record_hash: record_hash.clone(),
        });
        previous_hash = record_hash;
    }

    let receipt = DemoReceipt {
        schema: DEMO_SCHEMA.to_string(),
        mode: DEMO_MODE.to_string(),
        milestone_start: MILESTONE_START,
        milestone_end: MILESTONE_END,
        workspace_crate_count: WORKSPACE_CRATE_COUNT,
        stage_count: u16::try_from(stages.len()).context("demo stage count overflow")?,
        genesis_hash,
        tail_hash: previous_hash,
        stages,
    };
    verify_demo_receipt(&receipt)?;
    Ok(receipt)
}

pub fn verify_demo_receipt(receipt: &DemoReceipt) -> Result<()> {
    if receipt.schema != DEMO_SCHEMA
        || receipt.mode != DEMO_MODE
        || receipt.milestone_start != MILESTONE_START
        || receipt.milestone_end != MILESTONE_END
        || receipt.workspace_crate_count != WORKSPACE_CRATE_COUNT
        || usize::from(receipt.stage_count) != DEMO_STAGES.len()
        || receipt.stages.len() != DEMO_STAGES.len()
    {
        bail!("demo receipt header does not match the contract-complete profile");
    }

    let expected_genesis = hash_bytes(
        format!(
            "{DEMO_SCHEMA}\0{DEMO_MODE}\0{MILESTONE_START}\0{MILESTONE_END}\0{WORKSPACE_CRATE_COUNT}"
        )
        .as_bytes(),
    );
    if receipt.genesis_hash != expected_genesis {
        bail!("demo receipt genesis hash mismatch");
    }

    let mut previous_hash = expected_genesis;
    for (index, (stage, expected_stage)) in
        receipt.stages.iter().zip(DEMO_STAGES.iter()).enumerate()
    {
        let expected_sequence = u16::try_from(index + 1).context("demo stage sequence overflow")?;
        if stage.sequence != expected_sequence
            || stage.stage != *expected_stage
            || stage.previous_hash != previous_hash
        {
            bail!("demo stage {} binding mismatch", index + 1);
        }
        let expected_hash = hash_bytes(
            format!("{}\0{}\0{}", stage.sequence, stage.stage, previous_hash).as_bytes(),
        );
        if stage.record_hash != expected_hash {
            bail!("demo stage {} hash mismatch", index + 1);
        }
        previous_hash = expected_hash;
    }

    if receipt.tail_hash != previous_hash {
        bail!("demo receipt tail hash mismatch");
    }
    Ok(())
}

pub fn write_demo_receipt(path: &Path, receipt: &DemoReceipt) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(receipt).context("could not serialize demo receipt")?;
    fs::write(path, bytes)
        .with_context(|| format!("could not write demo receipt {}", path.display()))
}

pub fn read_demo_receipt(path: &Path) -> Result<DemoReceipt> {
    let bytes = fs::read(path)
        .with_context(|| format!("could not read demo receipt {}", path.display()))?;
    serde_json::from_slice(&bytes).context("demo receipt JSON is invalid")
}

pub fn default_demo_output() -> PathBuf {
    PathBuf::from("target/bsl-demo-receipt.json")
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_receipt_verifies() {
        let receipt = build_demo_receipt().unwrap();
        verify_demo_receipt(&receipt).unwrap();
        assert_eq!(receipt.stages.len(), DEMO_STAGES.len());
    }

    #[test]
    fn tampered_receipt_is_rejected() {
        let mut receipt = build_demo_receipt().unwrap();
        receipt.stages[4].stage = "network_escape".into();
        assert!(verify_demo_receipt(&receipt).is_err());
    }

    #[test]
    fn receipt_contains_no_network_target_or_secret_material() {
        let receipt = build_demo_receipt().unwrap();
        let serialized = serde_json::to_string(&receipt).unwrap();
        for forbidden in [
            "http://",
            "https://",
            "authorization:",
            "proxy-authorization:",
            "cookie:",
            "set-cookie:",
            "bearer ",
            "password=",
            "token=",
            "secret=",
            "private_key",
        ] {
            assert!(!serialized.to_ascii_lowercase().contains(forbidden));
        }
    }
}
