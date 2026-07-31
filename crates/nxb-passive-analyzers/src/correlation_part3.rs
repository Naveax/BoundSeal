pub const MIN_ACCOUNTED_CLUSTER_BYTES: u64 = 1024;
pub const MIN_ACCOUNTED_MEMBER_BYTES: u64 = 256;
pub const MIN_ACCOUNTED_ENDPOINT_BYTES: u64 = 96;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationResourceBudget {
    pub cluster_budget_bytes: u64,
    pub member_budget_bytes: u64,
    pub endpoint_budget_bytes: u64,
    pub source_unique_finding_capacity: u64,
    pub source_distinct_endpoint_capacity: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedCorrelationCapacity {
    pub limits: CorrelationLimits,
    pub memory_limited_clusters: u64,
    pub memory_limited_members: u64,
    pub memory_limited_endpoints: u64,
}

impl CorrelationResourceBudget {
    pub fn derive(self) -> Result<DerivedCorrelationCapacity, CorrelationError> {
        if self.cluster_budget_bytes < MIN_ACCOUNTED_CLUSTER_BYTES
            || self.member_budget_bytes < MIN_ACCOUNTED_MEMBER_BYTES
            || self.endpoint_budget_bytes < MIN_ACCOUNTED_ENDPOINT_BYTES
            || self.source_unique_finding_capacity == 0
            || self.source_distinct_endpoint_capacity == 0
        {
            return Err(CorrelationError::InvalidLimits(
                "resource budgets must support at least one correlation member".into(),
            ));
        }

        let memory_limited_clusters = self.cluster_budget_bytes / MIN_ACCOUNTED_CLUSTER_BYTES;
        let memory_limited_members = self.member_budget_bytes / MIN_ACCOUNTED_MEMBER_BYTES;
        let memory_limited_endpoints = self.endpoint_budget_bytes / MIN_ACCOUNTED_ENDPOINT_BYTES;

        let maximum_clusters = memory_limited_clusters
            .min(self.source_unique_finding_capacity)
            .min(MAX_CORRELATION_CLUSTERS as u64);
        let maximum_total_members = memory_limited_members
            .min(self.source_unique_finding_capacity)
            .min(MAX_TOTAL_CORRELATION_MEMBERS as u64);
        let maximum_endpoints_per_cluster = memory_limited_endpoints
            .min(self.source_distinct_endpoint_capacity)
            .min(MAX_ENDPOINTS_PER_CLUSTER as u64);
        let maximum_members_per_cluster = maximum_total_members.min(MAX_MEMBERS_PER_CLUSTER as u64);

        let limits = CorrelationLimits {
            maximum_clusters: usize::try_from(maximum_clusters).unwrap_or(usize::MAX),
            maximum_members_per_cluster: usize::try_from(maximum_members_per_cluster)
                .unwrap_or(usize::MAX),
            maximum_endpoints_per_cluster: usize::try_from(maximum_endpoints_per_cluster)
                .unwrap_or(usize::MAX),
            maximum_total_members: usize::try_from(maximum_total_members).unwrap_or(usize::MAX),
        }
        .validate()?;

        Ok(DerivedCorrelationCapacity {
            limits,
            memory_limited_clusters,
            memory_limited_members,
            memory_limited_endpoints,
        })
    }
}
