impl RootCauseCorrelator {
    pub fn new(limits: CorrelationLimits) -> Result<Self, CorrelationError> {
        Ok(Self {
            limits: limits.validate()?,
            clusters: BTreeMap::new(),
            finding_to_root_cause: BTreeMap::new(),
            total_members: 0,
            exact_duplicate_observations: 0,
        })
    }

    pub fn correlate(
        &mut self,
        finding: &Finding,
        evidence: &CorrelationEvidence,
    ) -> Result<CorrelationDisposition, CorrelationError> {
        validate_correlation_finding(finding)?;
        evidence.validate()?;
        let root_cause_id = evidence.root_cause_id(&finding.rule_id)?;

        if let Some(existing_root) = self.finding_to_root_cause.get(&finding.finding_id) {
            if existing_root == &root_cause_id {
                self.exact_duplicate_observations =
                    self.exact_duplicate_observations.saturating_add(1);
                return Ok(CorrelationDisposition::ExactDuplicate);
            }
            return Err(CorrelationError::FindingIdentityConflict);
        }

        if self.total_members >= self.limits.maximum_total_members {
            return Err(CorrelationError::MemberBudget);
        }

        if let Some(cluster) = self.clusters.get_mut(&root_cause_id) {
            if cluster.finding_ids.len() >= self.limits.maximum_members_per_cluster {
                return Err(CorrelationError::MemberBudget);
            }
            let endpoint_is_new = !cluster
                .affected_endpoint_sha256
                .contains(&finding.endpoint_sha256);
            if endpoint_is_new
                && cluster.affected_endpoint_sha256.len()
                    >= self.limits.maximum_endpoints_per_cluster
            {
                return Err(CorrelationError::EndpointBudget);
            }

            cluster.finding_ids.insert(finding.finding_id.clone());
            cluster
                .affected_endpoint_sha256
                .insert(finding.endpoint_sha256.clone());
            cluster.evidence_sha256.insert(finding.evidence_sha256.clone());
            cluster.highest_severity = cluster.highest_severity.max(finding.severity);
            cluster.minimum_confidence = cluster.minimum_confidence.min(finding.confidence);
            self.finding_to_root_cause
                .insert(finding.finding_id.clone(), root_cause_id);
            self.total_members = self.total_members.saturating_add(1);

            return Ok(if endpoint_is_new {
                CorrelationDisposition::AdditionalAffectedEndpoint
            } else {
                CorrelationDisposition::AdditionalFindingSameEndpoint
            });
        }

        if self.clusters.len() >= self.limits.maximum_clusters {
            return Err(CorrelationError::ClusterBudget);
        }
        let cluster = RootCauseCluster {
            root_cause_id: root_cause_id.clone(),
            rule_id: finding.rule_id.clone(),
            title: finding.title.clone(),
            policy_snapshot_sha256: evidence.policy_snapshot_sha256.clone(),
            normalization_version: evidence.normalization_version.clone(),
            component_sha256: evidence.component_sha256.clone(),
            normalized_evidence_sha256: evidence.normalized_evidence_sha256.clone(),
            response_shape_sha256: evidence.response_shape_sha256.clone(),
            highest_severity: finding.severity,
            minimum_confidence: finding.confidence,
            finding_ids: BTreeSet::from([finding.finding_id.clone()]),
            affected_endpoint_sha256: BTreeSet::from([finding.endpoint_sha256.clone()]),
            evidence_sha256: BTreeSet::from([finding.evidence_sha256.clone()]),
        };
        self.clusters.insert(root_cause_id.clone(), cluster);
        self.finding_to_root_cause
            .insert(finding.finding_id.clone(), root_cause_id);
        self.total_members = self.total_members.saturating_add(1);
        Ok(CorrelationDisposition::NewRootCause)
    }

    pub fn cluster(&self, root_cause_id: &str) -> Option<&RootCauseCluster> {
        self.clusters.get(root_cause_id)
    }

    pub fn clusters(&self) -> impl Iterator<Item = &RootCauseCluster> {
        self.clusters.values()
    }

    pub fn export_clusters(&self) -> Vec<RootCauseCluster> {
        self.clusters.values().cloned().collect()
    }

    pub fn receipt(&self) -> Result<CorrelationReceipt, CorrelationError> {
        let total_endpoint_memberships = self.clusters.values().fold(0_u64, |sum, cluster| {
            sum.saturating_add(cluster.affected_endpoint_count())
        });
        let cluster_digests = self
            .clusters
            .values()
            .map(RootCauseCluster::cluster_digest)
            .collect::<Result<Vec<_>, _>>()?;
        let correlation_tail_sha256 = correlation_hash_serializable(&(
            &cluster_digests,
            self.total_members,
            self.exact_duplicate_observations,
        ))?;
        Ok(CorrelationReceipt {
            root_cause_clusters: self.clusters.len() as u64,
            total_finding_memberships: self.total_members as u64,
            total_endpoint_memberships,
            exact_duplicate_observations: self.exact_duplicate_observations,
            correlation_tail_sha256,
        })
    }
}

fn validate_correlation_finding(finding: &Finding) -> Result<(), CorrelationError> {
    for (value, name) in [
        (&finding.finding_id, "finding_id"),
        (&finding.endpoint_sha256, "endpoint_sha256"),
        (&finding.evidence_sha256, "evidence_sha256"),
    ] {
        if !correlation_is_sha256(value) {
            return Err(CorrelationError::InvalidInput(name.into()));
        }
    }
    validate_rule_id(&finding.rule_id)?;
    if finding.title.is_empty()
        || finding.title.len() > 512
        || finding
            .title
            .bytes()
            .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n')
    {
        return Err(CorrelationError::InvalidInput("finding title".into()));
    }
    Ok(())
}

fn validate_rule_id(rule_id: &str) -> Result<(), CorrelationError> {
    if rule_id.is_empty()
        || rule_id.len() > 192
        || !rule_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(CorrelationError::InvalidInput("rule_id".into()));
    }
    Ok(())
}

fn correlation_is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn correlation_hash_serializable<T: Serialize>(value: &T) -> Result<String, CorrelationError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CorrelationError::Serialization(error.to_string()))?;
    Ok(correlation_hash(&bytes))
}

fn correlation_hash(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
