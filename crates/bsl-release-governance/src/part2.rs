#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComponentRecord {
    pub component_id: String,
    pub kind: ComponentKind,
    pub version: String,
    pub source_sha256: String,
    pub artifact_sha256: String,
    pub license_id: String,
    pub dependency_ids: BTreeSet<String>,
    pub component_sha256: String,
}

impl ComponentRecord {
    pub fn new(
        component_id: impl Into<String>,
        kind: ComponentKind,
        version: impl Into<String>,
        source_sha256: impl Into<String>,
        artifact_sha256: impl Into<String>,
        license_id: impl Into<String>,
        dependency_ids: BTreeSet<String>,
    ) -> Result<Self, ReleaseError> {
        let component_id = component_id.into();
        let version = version.into();
        let source_sha256 = source_sha256.into();
        let artifact_sha256 = artifact_sha256.into();
        let license_id = license_id.into();
        validate_identifier(&component_id, "component")?;
        validate_identifier(&version, "component version")?;
        validate_identifier(&license_id, "component license")?;
        validate_sha256(&source_sha256, "component source")?;
        validate_sha256(&artifact_sha256, "component artifact")?;
        if dependency_ids.len() > MAX_DEPENDENCIES_PER_COMPONENT
            || dependency_ids.contains(&component_id)
            || dependency_ids
                .iter()
                .any(|dependency| validate_identifier(dependency, "dependency").is_err())
        {
            return Err(ReleaseError::InvalidInventory(
                "component dependency bounds".into(),
            ));
        }
        let component_sha256 = hash_serializable(&(
            &component_id,
            kind,
            &version,
            &source_sha256,
            &artifact_sha256,
            &license_id,
            &dependency_ids,
        ))?;
        Ok(Self {
            component_id,
            kind,
            version,
            source_sha256,
            artifact_sha256,
            license_id,
            dependency_ids,
            component_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), ReleaseError> {
        let expected = hash_serializable(&(
            &self.component_id,
            self.kind,
            &self.version,
            &self.source_sha256,
            &self.artifact_sha256,
            &self.license_id,
            &self.dependency_ids,
        ))?;
        if expected != self.component_sha256 {
            return Err(ReleaseError::InvalidInventory(
                "component digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComponentInventory {
    pub inventory_id: String,
    pub policy_snapshot_sha256: String,
    pub components: BTreeMap<String, ComponentRecord>,
    pub build_profile: String,
    pub inventory_root_sha256: String,
}

impl ComponentInventory {
    pub fn new(
        inventory_id: impl Into<String>,
        policy_snapshot_sha256: impl Into<String>,
        components: Vec<ComponentRecord>,
        build_profile: impl Into<String>,
    ) -> Result<Self, ReleaseError> {
        let inventory_id = inventory_id.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        let build_profile = build_profile.into();
        validate_identifier(&inventory_id, "component inventory")?;
        validate_identifier(&build_profile, "build profile")?;
        validate_sha256(&policy_snapshot_sha256, "inventory policy")?;
        if components.is_empty() || components.len() > MAX_COMPONENTS {
            return Err(ReleaseError::InvalidInventory(
                "component count".into(),
            ));
        }
        let mut by_id = BTreeMap::new();
        for component in components {
            component.verify()?;
            if by_id
                .insert(component.component_id.clone(), component)
                .is_some()
            {
                return Err(ReleaseError::InvalidInventory(
                    "duplicate component identifier".into(),
                ));
            }
        }
        validate_dependency_graph(&by_id)?;
        let inventory_root_sha256 = hash_serializable(&(
            &inventory_id,
            &policy_snapshot_sha256,
            &by_id,
            &build_profile,
        ))?;
        Ok(Self {
            inventory_id,
            policy_snapshot_sha256,
            components: by_id,
            build_profile,
            inventory_root_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), ReleaseError> {
        for component in self.components.values() {
            component.verify()?;
        }
        validate_dependency_graph(&self.components)?;
        let expected = hash_serializable(&(
            &self.inventory_id,
            &self.policy_snapshot_sha256,
            &self.components,
            &self.build_profile,
        ))?;
        if expected != self.inventory_root_sha256 {
            return Err(ReleaseError::InvalidInventory(
                "inventory root mismatch".into(),
            ));
        }
        Ok(())
    }
}

fn validate_dependency_graph(
    components: &BTreeMap<String, ComponentRecord>,
) -> Result<(), ReleaseError> {
    let mut indegree = components
        .keys()
        .map(|component_id| (component_id.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut outgoing = BTreeMap::<String, BTreeSet<String>>::new();
    for component in components.values() {
        for dependency in &component.dependency_ids {
            if !components.contains_key(dependency) {
                return Err(ReleaseError::InvalidInventory(
                    "unknown component dependency".into(),
                ));
            }
            *indegree
                .get_mut(&component.component_id)
                .expect("component indegree") += 1;
            outgoing
                .entry(dependency.clone())
                .or_default()
                .insert(component.component_id.clone());
        }
    }
    let mut queue = indegree
        .iter()
        .filter_map(|(component_id, degree)| (*degree == 0).then_some(component_id.clone()))
        .collect::<VecDeque<_>>();
    let mut visited = 0_usize;
    while let Some(component_id) = queue.pop_front() {
        visited += 1;
        for dependent in outgoing.get(&component_id).into_iter().flatten() {
            let degree = indegree.get_mut(dependent).expect("dependent indegree");
            *degree = degree.saturating_sub(1);
            if *degree == 0 {
                queue.push_back(dependent.clone());
            }
        }
    }
    if visited != components.len() {
        return Err(ReleaseError::InvalidInventory(
            "component dependency cycle".into(),
        ));
    }
    Ok(())
}
