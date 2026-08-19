#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRole {
    Protocol,
    Safety,
    Audit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPanelMember {
    pub reviewer_id: String,
    pub role: ReviewRole,
    pub organization_root_sha256: String,
    pub implementation_root_sha256: String,
    pub external_io_capable: bool,
    pub member_sha256: String,
}

impl ReviewPanelMember {
    pub fn new(
        reviewer_id: impl Into<String>,
        role: ReviewRole,
        organization_root_sha256: impl Into<String>,
        implementation_root_sha256: impl Into<String>,
        external_io_capable: bool,
    ) -> Result<Self, PostClosureError> {
        let reviewer_id = reviewer_id.into();
        let organization_root_sha256 = organization_root_sha256.into();
        let implementation_root_sha256 = implementation_root_sha256.into();
        validate_identifier(&reviewer_id, "reviewer")?;
        validate_sha256(&organization_root_sha256, "reviewer organization")?;
        validate_sha256(&implementation_root_sha256, "reviewer implementation")?;
        if external_io_capable {
            return Err(PostClosureError::InvalidRenewal(
                "reviewer external-I/O capability".into(),
            ));
        }
        let member_sha256 = hash_serializable(&(
            &reviewer_id,
            role,
            &organization_root_sha256,
            &implementation_root_sha256,
            external_io_capable,
        ))?;
        Ok(Self {
            reviewer_id,
            role,
            organization_root_sha256,
            implementation_root_sha256,
            external_io_capable,
            member_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.reviewer_id, "reviewer")?;
        validate_sha256(&self.organization_root_sha256, "reviewer organization")?;
        validate_sha256(&self.implementation_root_sha256, "reviewer implementation")?;
        if self.external_io_capable {
            return Err(PostClosureError::InvalidRenewal(
                "reviewer external-I/O capability".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.reviewer_id,
            self.role,
            &self.organization_root_sha256,
            &self.implementation_root_sha256,
            self.external_io_capable,
        ))?;
        if expected != self.member_sha256 {
            return Err(PostClosureError::InvalidRenewal(
                "reviewer member digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPanel {
    pub panel_id: String,
    pub succession_certificate_sha256: String,
    pub members: BTreeMap<String, ReviewPanelMember>,
    pub panel_sha256: String,
}

impl ReviewPanel {
    pub fn new(
        panel_id: impl Into<String>,
        succession: &SuccessionCertificate,
        members: Vec<ReviewPanelMember>,
    ) -> Result<Self, PostClosureError> {
        succession.verify()?;
        let panel_id = panel_id.into();
        validate_identifier(&panel_id, "review panel")?;
        if members.len() < 3 || members.len() > MAX_REVIEWERS {
            return Err(PostClosureError::InvalidRenewal(
                "review panel cardinality".into(),
            ));
        }
        let mut by_id = BTreeMap::new();
        let mut organizations = BTreeSet::new();
        let mut implementations = BTreeSet::new();
        let mut roles = BTreeSet::new();
        for member in members {
            member.verify()?;
            organizations.insert(member.organization_root_sha256.clone());
            implementations.insert(member.implementation_root_sha256.clone());
            roles.insert(member.role);
            if by_id.insert(member.reviewer_id.clone(), member).is_some() {
                return Err(PostClosureError::InvalidRenewal(
                    "duplicate review panel member".into(),
                ));
            }
        }
        let expected_roles = [ReviewRole::Protocol, ReviewRole::Safety, ReviewRole::Audit]
            .into_iter()
            .collect::<BTreeSet<_>>();
        if organizations.len() < 3 || implementations.len() < 3 || !expected_roles.is_subset(&roles)
        {
            return Err(PostClosureError::InvalidRenewal(
                "review panel diversity or role coverage".into(),
            ));
        }
        let succession_certificate_sha256 = succession.certificate_sha256.clone();
        let panel_sha256 = hash_serializable(&(&panel_id, &succession_certificate_sha256, &by_id))?;
        Ok(Self {
            panel_id,
            succession_certificate_sha256,
            members: by_id,
            panel_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.panel_id, "review panel")?;
        validate_sha256(
            &self.succession_certificate_sha256,
            "review panel succession certificate",
        )?;
        if self.members.len() < 3 || self.members.len() > MAX_REVIEWERS {
            return Err(PostClosureError::InvalidRenewal(
                "review panel cardinality".into(),
            ));
        }
        let mut organizations = BTreeSet::new();
        let mut implementations = BTreeSet::new();
        let mut roles = BTreeSet::new();
        for (key, member) in &self.members {
            member.verify()?;
            if key != &member.reviewer_id {
                return Err(PostClosureError::InvalidRenewal(
                    "review panel key mismatch".into(),
                ));
            }
            organizations.insert(member.organization_root_sha256.clone());
            implementations.insert(member.implementation_root_sha256.clone());
            roles.insert(member.role);
        }
        let expected_roles = [ReviewRole::Protocol, ReviewRole::Safety, ReviewRole::Audit]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let expected = hash_serializable(&(
            &self.panel_id,
            &self.succession_certificate_sha256,
            &self.members,
        ))?;
        if organizations.len() < 3
            || implementations.len() < 3
            || !expected_roles.is_subset(&roles)
            || expected != self.panel_sha256
        {
            return Err(PostClosureError::InvalidRenewal(
                "review panel diversity, role or digest".into(),
            ));
        }
        Ok(())
    }
}
