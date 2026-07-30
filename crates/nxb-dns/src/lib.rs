use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsObservation {
    pub context_id: String,
    pub host: String,
    pub addresses: BTreeSet<IpAddr>,
    pub resolver_id: String,
    pub ttl_seconds: u32,
    pub observed_at_milliseconds: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsPinStatus {
    Pinned,
    Matched,
}

impl DnsPinStatus {
    pub fn code(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::Matched => "matched",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPin {
    context_id: String,
    host: String,
    addresses: BTreeSet<IpAddr>,
    resolver_id: String,
    first_observed_at_milliseconds: u64,
    last_observed_at_milliseconds: u64,
    initial_ttl_seconds: u32,
    latest_ttl_seconds: u32,
}

impl DnsPin {
    pub fn addresses(&self) -> &BTreeSet<IpAddr> {
        &self.addresses
    }

    pub fn resolver_id(&self) -> &str {
        &self.resolver_id
    }

    pub fn initial_ttl_seconds(&self) -> u32 {
        self.initial_ttl_seconds
    }

    pub fn latest_ttl_seconds(&self) -> u32 {
        self.latest_ttl_seconds
    }

    pub fn first_observed_at_milliseconds(&self) -> u64 {
        self.first_observed_at_milliseconds
    }

    pub fn last_observed_at_milliseconds(&self) -> u64 {
        self.last_observed_at_milliseconds
    }
}

#[derive(Debug, Default)]
pub struct DnsPinSet {
    pins: BTreeMap<(String, String), DnsPin>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DnsPinError {
    #[error("DNS context_id is invalid")]
    InvalidContextId,
    #[error("DNS resolver_id is invalid")]
    InvalidResolverId,
    #[error("DNS host is invalid")]
    InvalidHost,
    #[error("DNS observation contains no addresses")]
    EmptyAddressSet,
    #[error("DNS observation clock moved backwards")]
    ClockRegression,
    #[error("DNS resolver changed within a pinned context")]
    ResolverChanged {
        expected: String,
        observed: String,
    },
    #[error("DNS rebinding detected for {host}")]
    RebindingDetected {
        host: String,
        pinned: BTreeSet<IpAddr>,
        observed: BTreeSet<IpAddr>,
    },
}

impl DnsPinSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pin_or_validate(
        &mut self,
        observation: DnsObservation,
    ) -> Result<DnsPinStatus, DnsPinError> {
        validate_observation(&observation)?;

        let context_id = normalize_identifier(&observation.context_id);
        let resolver_id = normalize_identifier(&observation.resolver_id);
        let host = normalize_host(&observation.host);
        let key = (context_id.clone(), host.clone());

        match self.pins.get_mut(&key) {
            Some(pin) => {
                if observation.observed_at_milliseconds < pin.last_observed_at_milliseconds {
                    return Err(DnsPinError::ClockRegression);
                }
                if resolver_id != pin.resolver_id {
                    return Err(DnsPinError::ResolverChanged {
                        expected: pin.resolver_id.clone(),
                        observed: resolver_id,
                    });
                }
                if observation.addresses != pin.addresses {
                    return Err(DnsPinError::RebindingDetected {
                        host,
                        pinned: pin.addresses.clone(),
                        observed: observation.addresses,
                    });
                }

                pin.last_observed_at_milliseconds = observation.observed_at_milliseconds;
                pin.latest_ttl_seconds = observation.ttl_seconds;
                Ok(DnsPinStatus::Matched)
            }
            None => {
                self.pins.insert(
                    key,
                    DnsPin {
                        context_id,
                        host,
                        addresses: observation.addresses,
                        resolver_id,
                        first_observed_at_milliseconds: observation.observed_at_milliseconds,
                        last_observed_at_milliseconds: observation.observed_at_milliseconds,
                        initial_ttl_seconds: observation.ttl_seconds,
                        latest_ttl_seconds: observation.ttl_seconds,
                    },
                );
                Ok(DnsPinStatus::Pinned)
            }
        }
    }

    pub fn get(&self, context_id: &str, host: &str) -> Option<&DnsPin> {
        self.pins
            .get(&(normalize_identifier(context_id), normalize_host(host)))
    }

    pub fn release_context(&mut self, context_id: &str) -> usize {
        let normalized = normalize_identifier(context_id);
        let before = self.pins.len();
        self.pins
            .retain(|(stored_context, _), _| stored_context != &normalized);
        before - self.pins.len()
    }

    pub fn len(&self) -> usize {
        self.pins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

fn validate_observation(observation: &DnsObservation) -> Result<(), DnsPinError> {
    if !is_valid_identifier(&observation.context_id) {
        return Err(DnsPinError::InvalidContextId);
    }
    if !is_valid_identifier(&observation.resolver_id) {
        return Err(DnsPinError::InvalidResolverId);
    }
    if !is_valid_host(&observation.host) {
        return Err(DnsPinError::InvalidHost);
    }
    if observation.addresses.is_empty() {
        return Err(DnsPinError::EmptyAddressSet);
    }
    Ok(())
}

fn normalize_identifier(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn is_valid_identifier(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
}

fn normalize_host(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_valid_host(value: &str) -> bool {
    let host = normalize_host(value);
    if host.is_empty() || host.len() > 253 || host.contains(':') || host.contains('/') {
        return false;
    }

    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(context: &str, host: &str, addresses: &[&str], at: u64) -> DnsObservation {
        DnsObservation {
            context_id: context.into(),
            host: host.into(),
            addresses: addresses
                .iter()
                .map(|value| value.parse().unwrap())
                .collect(),
            resolver_id: "system-resolver".into(),
            ttl_seconds: 60,
            observed_at_milliseconds: at,
        }
    }

    #[test]
    fn pins_then_matches_the_same_set() {
        let mut pins = DnsPinSet::new();
        assert_eq!(
            pins.pin_or_validate(observation(
                "navigation-1",
                "app.example.com",
                &["8.8.8.8", "1.1.1.1"],
                0,
            ))
            .unwrap(),
            DnsPinStatus::Pinned
        );
        assert_eq!(
            pins.pin_or_validate(observation(
                "navigation-1",
                "APP.EXAMPLE.COM.",
                &["1.1.1.1", "8.8.8.8"],
                50,
            ))
            .unwrap(),
            DnsPinStatus::Matched
        );
    }

    #[test]
    fn rejects_public_to_public_rebinding() {
        let mut pins = DnsPinSet::new();
        pins.pin_or_validate(observation(
            "navigation-1",
            "app.example.com",
            &["8.8.8.8"],
            0,
        ))
        .unwrap();

        assert!(matches!(
            pins.pin_or_validate(observation(
                "navigation-1",
                "app.example.com",
                &["1.1.1.1"],
                10,
            )),
            Err(DnsPinError::RebindingDetected { .. })
        ));
    }

    #[test]
    fn permits_different_addresses_in_separate_contexts() {
        let mut pins = DnsPinSet::new();
        pins.pin_or_validate(observation(
            "navigation-1",
            "app.example.com",
            &["8.8.8.8"],
            0,
        ))
        .unwrap();
        pins.pin_or_validate(observation(
            "navigation-2",
            "app.example.com",
            &["1.1.1.1"],
            0,
        ))
        .unwrap();
        assert_eq!(pins.len(), 2);
    }

    #[test]
    fn pins_redirect_hosts_independently() {
        let mut pins = DnsPinSet::new();
        pins.pin_or_validate(observation(
            "navigation-1",
            "app.example.com",
            &["8.8.8.8"],
            0,
        ))
        .unwrap();
        pins.pin_or_validate(observation(
            "navigation-1",
            "cdn.example.com",
            &["1.1.1.1"],
            10,
        ))
        .unwrap();
        assert_eq!(pins.len(), 2);
    }

    #[test]
    fn rejects_resolver_changes_inside_context() {
        let mut pins = DnsPinSet::new();
        pins.pin_or_validate(observation(
            "navigation-1",
            "app.example.com",
            &["8.8.8.8"],
            0,
        ))
        .unwrap();
        let mut changed = observation(
            "navigation-1",
            "app.example.com",
            &["8.8.8.8"],
            10,
        );
        changed.resolver_id = "alternate-resolver".into();
        assert!(matches!(
            pins.pin_or_validate(changed),
            Err(DnsPinError::ResolverChanged { .. })
        ));
    }

    #[test]
    fn release_context_removes_only_its_pins() {
        let mut pins = DnsPinSet::new();
        pins.pin_or_validate(observation(
            "navigation-1",
            "app.example.com",
            &["8.8.8.8"],
            0,
        ))
        .unwrap();
        pins.pin_or_validate(observation(
            "navigation-2",
            "app.example.com",
            &["1.1.1.1"],
            0,
        ))
        .unwrap();

        assert_eq!(pins.release_context("navigation-1"), 1);
        assert_eq!(pins.len(), 1);
        assert!(pins.get("navigation-2", "app.example.com").is_some());
    }
}
