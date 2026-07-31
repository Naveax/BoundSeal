#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityNode {
    pub node_id: String,
    pub kind: CapabilityNodeKind,
    pub subject_sha256: String,
    pub policy_snapshot_sha256: String,
    pub finding_state: Option<FindingState>,
    pub labels: BTreeMap<String, String>,
}

impl CapabilityNode {
    pub fn new(
        node_id: impl Into<String>,
        kind: CapabilityNodeKind,
        subject_sha256: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        finding_state: Option<FindingState>,
        labels: BTreeMap<String, String>,
    ) -> Result<Self, WorkflowError> {
        let node_id = node_id.into();
        validate_identifier(&node_id, "capability node")?;
        let subject_sha256 = subject_sha256.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&subject_sha256, "capability subject")?;
        validate_sha256(&policy_snapshot_sha256, "capability policy snapshot")?;
        if (kind == CapabilityNodeKind::Finding) != finding_state.is_some()
            || labels.len() > 64
            || labels.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 96
                    || value.len() > 512
                    || key.bytes().any(|byte| byte.is_ascii_control())
                    || value.bytes().any(|byte| byte == 0)
            })
        {
            return Err(WorkflowError::InvalidRiskChain);
        }
        Ok(Self {
            node_id,
            kind,
            subject_sha256,
            policy_snapshot_sha256,
            finding_state,
            labels,
        })
    }

    fn is_chain_eligible(&self) -> bool {
        self.kind != CapabilityNodeKind::Finding
            || matches!(
                self.finding_state,
                Some(FindingState::Validated | FindingState::Reportable | FindingState::Closed)
            )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityEdge {
    pub edge_id: String,
    pub from_node_id: String,
    pub to_node_id: String,
    pub kind: CapabilityEdgeKind,
    pub evidence_sha256: String,
}

impl CapabilityEdge {
    pub fn new(
        from_node_id: impl Into<String>,
        to_node_id: impl Into<String>,
        kind: CapabilityEdgeKind,
        evidence_sha256: impl Into<String>,
    ) -> Result<Self, WorkflowError> {
        let from_node_id = from_node_id.into();
        let to_node_id = to_node_id.into();
        validate_identifier(&from_node_id, "capability edge from")?;
        validate_identifier(&to_node_id, "capability edge to")?;
        if from_node_id == to_node_id {
            return Err(WorkflowError::InvalidRiskChain);
        }
        let evidence_sha256 = evidence_sha256.into();
        validate_sha256(&evidence_sha256, "capability edge evidence")?;
        let edge_id = format!(
            "cap-edge-{}",
            &hash_serializable(&(
                &from_node_id,
                &to_node_id,
                kind,
                &evidence_sha256,
            ))?[..24]
        );
        Ok(Self {
            edge_id,
            from_node_id,
            to_node_id,
            kind,
            evidence_sha256,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskChainStep {
    pub sequence: usize,
    pub node_id: String,
    pub node_kind: CapabilityNodeKind,
    pub subject_sha256: String,
    pub via_edge_id: Option<String>,
    pub via_edge_kind: Option<CapabilityEdgeKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskChain {
    pub chain_id: String,
    pub start_node_id: String,
    pub goal_node_id: String,
    pub steps: Vec<RiskChainStep>,
    pub evidence_sha256: BTreeSet<String>,
    pub executable: bool,
    pub chain_sha256: String,
}

#[derive(Debug)]
pub struct CapabilityGraph {
    policy_snapshot_sha256: String,
    nodes: BTreeMap<String, CapabilityNode>,
    edges: BTreeMap<String, CapabilityEdge>,
    outgoing: BTreeMap<String, BTreeSet<String>>,
    audit: WorkflowAuditChain,
}

impl CapabilityGraph {
    pub fn new(
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, WorkflowError> {
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "capability graph policy")?;
        Ok(Self {
            policy_snapshot_sha256,
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            audit: WorkflowAuditChain::new(audit_genesis)?,
        })
    }

    pub fn add_node(&mut self, node: CapabilityNode) -> Result<&CapabilityNode, WorkflowError> {
        if self.nodes.len() >= MAX_CAPABILITY_GRAPH_NODES {
            return Err(WorkflowError::GraphLimit);
        }
        if node.policy_snapshot_sha256 != self.policy_snapshot_sha256 {
            return Err(WorkflowError::InvalidRiskChain);
        }
        if self.nodes.contains_key(&node.node_id) {
            return Err(WorkflowError::DuplicateNode);
        }
        let node_id = node.node_id.clone();
        self.nodes.insert(node_id.clone(), node);
        self.audit.append(WorkflowAuditEvent {
            action: "capability_node_added".into(),
            subject_id: node_id.clone(),
            outcome: "added".into(),
            metadata: BTreeMap::new(),
        })?;
        Ok(self.nodes.get(&node_id).expect("capability node inserted"))
    }

    pub fn add_edge(&mut self, edge: CapabilityEdge) -> Result<&CapabilityEdge, WorkflowError> {
        if self.edges.len() >= MAX_CAPABILITY_GRAPH_EDGES {
            return Err(WorkflowError::GraphLimit);
        }
        if !self.nodes.contains_key(&edge.from_node_id)
            || !self.nodes.contains_key(&edge.to_node_id)
        {
            return Err(WorkflowError::UnknownNode);
        }
        if self.edges.contains_key(&edge.edge_id) {
            return Err(WorkflowError::DuplicateEdge);
        }
        let edge_id = edge.edge_id.clone();
        self.outgoing
            .entry(edge.from_node_id.clone())
            .or_default()
            .insert(edge_id.clone());
        self.edges.insert(edge_id.clone(), edge);
        self.audit.append(WorkflowAuditEvent {
            action: "capability_edge_added".into(),
            subject_id: edge_id.clone(),
            outcome: "added".into(),
            metadata: BTreeMap::new(),
        })?;
        Ok(self.edges.get(&edge_id).expect("capability edge inserted"))
    }

    pub fn synthesize_risk_chain(
        &self,
        start_node_id: &str,
        goal_node_id: &str,
        maximum_depth: usize,
    ) -> Result<RiskChain, WorkflowError> {
        if maximum_depth == 0
            || maximum_depth > MAX_RISK_CHAIN_DEPTH
            || !self.nodes.contains_key(start_node_id)
            || !self.nodes.contains_key(goal_node_id)
        {
            return Err(WorkflowError::InvalidRiskChain);
        }
        let mut queue = VecDeque::from([vec![start_node_id.to_string()]]);
        let mut selected_path = None;
        while let Some(path) = queue.pop_front() {
            let current = path.last().expect("risk-chain path");
            if current == goal_node_id {
                selected_path = Some(path);
                break;
            }
            if path.len() > maximum_depth {
                continue;
            }
            for edge_id in self.outgoing.get(current).into_iter().flatten() {
                let edge = self.edges.get(edge_id).expect("capability edge index");
                if matches!(edge.kind, CapabilityEdgeKind::Compensates)
                    || path.contains(&edge.to_node_id)
                {
                    continue;
                }
                let next = self.nodes.get(&edge.to_node_id).expect("capability node index");
                if !next.is_chain_eligible() {
                    continue;
                }
                let mut next_path = path.clone();
                next_path.push(edge.to_node_id.clone());
                queue.push_back(next_path);
            }
        }
        let path = selected_path.ok_or(WorkflowError::InvalidRiskChain)?;
        if path.len().saturating_sub(1) > maximum_depth {
            return Err(WorkflowError::InvalidRiskChain);
        }
        let mut steps = Vec::with_capacity(path.len());
        let mut evidence_sha256 = BTreeSet::new();
        for (index, node_id) in path.iter().enumerate() {
            let node = self.nodes.get(node_id).expect("risk-chain node");
            let (via_edge_id, via_edge_kind) = if index == 0 {
                (None, None)
            } else {
                let previous = &path[index - 1];
                let edge = self
                    .outgoing
                    .get(previous)
                    .into_iter()
                    .flatten()
                    .filter_map(|edge_id| self.edges.get(edge_id))
                    .find(|edge| edge.to_node_id == *node_id)
                    .ok_or(WorkflowError::InvalidRiskChain)?;
                evidence_sha256.insert(edge.evidence_sha256.clone());
                (Some(edge.edge_id.clone()), Some(edge.kind))
            };
            steps.push(RiskChainStep {
                sequence: index + 1,
                node_id: node.node_id.clone(),
                node_kind: node.kind,
                subject_sha256: node.subject_sha256.clone(),
                via_edge_id,
                via_edge_kind,
            });
        }
        let chain_sha256 = hash_serializable(&(
            start_node_id,
            goal_node_id,
            &steps,
            &evidence_sha256,
        ))?;
        Ok(RiskChain {
            chain_id: format!("risk-chain-{}", &chain_sha256[..24]),
            start_node_id: start_node_id.into(),
            goal_node_id: goal_node_id.into(),
            steps,
            evidence_sha256,
            executable: false,
            chain_sha256,
        })
    }

    pub fn nodes(&self) -> &BTreeMap<String, CapabilityNode> {
        &self.nodes
    }

    pub fn edges(&self) -> &BTreeMap<String, CapabilityEdge> {
        &self.edges
    }

    pub fn audit(&self) -> &WorkflowAuditChain {
        &self.audit
    }
}
