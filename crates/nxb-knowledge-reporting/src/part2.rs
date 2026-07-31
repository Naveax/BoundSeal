#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeNode {
    pub node_id: String,
    pub kind: KnowledgeNodeKind,
    pub key_sha256: String,
    pub policy_snapshot_sha256: String,
    pub provenance_sha256: String,
    pub labels: BTreeMap<String, String>,
}

impl KnowledgeNode {
    pub fn new(
        node_id: impl Into<String>,
        kind: KnowledgeNodeKind,
        key_sha256: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        provenance_sha256: impl Into<String>,
        labels: BTreeMap<String, String>,
    ) -> Result<Self, KnowledgeError> {
        let node_id = node_id.into();
        validate_identifier(&node_id, "node_id")?;
        let key_sha256 = key_sha256.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        let provenance_sha256 = provenance_sha256.into();
        for (name, value) in [
            ("node key", &key_sha256),
            ("policy snapshot", &policy_snapshot_sha256),
            ("provenance", &provenance_sha256),
        ] {
            validate_sha256(value, name)?;
        }
        validate_labels(&labels)?;
        Ok(Self {
            node_id,
            kind,
            key_sha256,
            policy_snapshot_sha256,
            provenance_sha256,
            labels,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeEdge {
    pub edge_id: String,
    pub from_node_id: String,
    pub to_node_id: String,
    pub kind: KnowledgeEdgeKind,
    pub provenance_sha256: String,
    pub confidence_basis_sha256: String,
}

impl KnowledgeEdge {
    pub fn new(
        from_node_id: impl Into<String>,
        to_node_id: impl Into<String>,
        kind: KnowledgeEdgeKind,
        provenance_sha256: impl Into<String>,
        confidence_basis_sha256: impl Into<String>,
    ) -> Result<Self, KnowledgeError> {
        let from_node_id = from_node_id.into();
        let to_node_id = to_node_id.into();
        validate_identifier(&from_node_id, "edge from")?;
        validate_identifier(&to_node_id, "edge to")?;
        if from_node_id == to_node_id && kind != KnowledgeEdgeKind::SameAs {
            return Err(KnowledgeError::UnknownNode);
        }
        let provenance_sha256 = provenance_sha256.into();
        let confidence_basis_sha256 = confidence_basis_sha256.into();
        validate_sha256(&provenance_sha256, "edge provenance")?;
        validate_sha256(&confidence_basis_sha256, "edge confidence")?;
        let edge_id = format!(
            "edge-{}",
            &hash_serializable(&(
                &from_node_id,
                &to_node_id,
                kind,
                &provenance_sha256,
                &confidence_basis_sha256,
            ))?[..24]
        );
        Ok(Self {
            edge_id,
            from_node_id,
            to_node_id,
            kind,
            provenance_sha256,
            confidence_basis_sha256,
        })
    }
}

#[derive(Debug)]
pub struct ApplicationKnowledgeGraph {
    policy_snapshot_sha256: String,
    nodes: BTreeMap<String, KnowledgeNode>,
    edges: BTreeMap<String, KnowledgeEdge>,
    outgoing: BTreeMap<String, BTreeSet<String>>,
    incoming: BTreeMap<String, BTreeSet<String>>,
    audit: KnowledgeAuditChain,
}

impl ApplicationKnowledgeGraph {
    pub fn new(
        policy_snapshot_sha256: impl Into<String>,
        audit_genesis: impl Into<String>,
    ) -> Result<Self, KnowledgeError> {
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "graph policy snapshot")?;
        Ok(Self {
            policy_snapshot_sha256,
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
            audit: KnowledgeAuditChain::new(audit_genesis)?,
        })
    }

    pub fn add_node(&mut self, node: KnowledgeNode) -> Result<&KnowledgeNode, KnowledgeError> {
        if self.nodes.len() >= MAX_GRAPH_NODES {
            return Err(KnowledgeError::GraphLimit);
        }
        if node.policy_snapshot_sha256 != self.policy_snapshot_sha256 {
            return Err(KnowledgeError::InvalidEvidence(
                "node policy snapshot drift".into(),
            ));
        }
        if self.nodes.contains_key(&node.node_id) {
            return Err(KnowledgeError::DuplicateNode);
        }
        let node_id = node.node_id.clone();
        self.nodes.insert(node_id.clone(), node);
        self.audit.append(KnowledgeAuditEvent {
            action: "knowledge_node_added".into(),
            subject_id: node_id.clone(),
            outcome: "added".into(),
            metadata: BTreeMap::from([(
                "node_kind".into(),
                format!("{:?}", self.nodes[&node_id].kind).to_ascii_lowercase(),
            )]),
        })?;
        Ok(self.nodes.get(&node_id).expect("knowledge node inserted"))
    }

    pub fn add_edge(&mut self, edge: KnowledgeEdge) -> Result<&KnowledgeEdge, KnowledgeError> {
        if self.edges.len() >= MAX_GRAPH_EDGES {
            return Err(KnowledgeError::GraphLimit);
        }
        if !self.nodes.contains_key(&edge.from_node_id)
            || !self.nodes.contains_key(&edge.to_node_id)
        {
            return Err(KnowledgeError::UnknownNode);
        }
        if self.edges.contains_key(&edge.edge_id) {
            return Err(KnowledgeError::DuplicateEdge);
        }
        let edge_id = edge.edge_id.clone();
        self.outgoing
            .entry(edge.from_node_id.clone())
            .or_default()
            .insert(edge_id.clone());
        self.incoming
            .entry(edge.to_node_id.clone())
            .or_default()
            .insert(edge_id.clone());
        self.edges.insert(edge_id.clone(), edge);
        self.audit.append(KnowledgeAuditEvent {
            action: "knowledge_edge_added".into(),
            subject_id: edge_id.clone(),
            outcome: "added".into(),
            metadata: BTreeMap::new(),
        })?;
        Ok(self.edges.get(&edge_id).expect("knowledge edge inserted"))
    }

    pub fn node(&self, node_id: &str) -> Option<&KnowledgeNode> {
        self.nodes.get(node_id)
    }

    pub fn edge(&self, edge_id: &str) -> Option<&KnowledgeEdge> {
        self.edges.get(edge_id)
    }

    pub fn outgoing_edges(&self, node_id: &str) -> Vec<&KnowledgeEdge> {
        self.outgoing
            .get(node_id)
            .into_iter()
            .flatten()
            .filter_map(|edge_id| self.edges.get(edge_id))
            .collect()
    }

    pub fn incoming_edges(&self, node_id: &str) -> Vec<&KnowledgeEdge> {
        self.incoming
            .get(node_id)
            .into_iter()
            .flatten()
            .filter_map(|edge_id| self.edges.get(edge_id))
            .collect()
    }

    pub fn nodes(&self) -> &BTreeMap<String, KnowledgeNode> {
        &self.nodes
    }

    pub fn edges(&self) -> &BTreeMap<String, KnowledgeEdge> {
        &self.edges
    }

    pub fn audit(&self) -> &KnowledgeAuditChain {
        &self.audit
    }
}

fn validate_labels(labels: &BTreeMap<String, String>) -> Result<(), KnowledgeError> {
    if labels.len() > 64
        || labels.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 96
                || value.len() > 512
                || key.bytes().any(|byte| byte.is_ascii_control())
                || value.bytes().any(|byte| byte == 0)
        })
    {
        return Err(KnowledgeError::InvalidEvidence("node labels".into()));
    }
    Ok(())
}
