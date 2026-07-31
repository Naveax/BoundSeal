#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicVerifierReceipt {
    pub verifier_id: String,
    pub organization_root_sha256: String,
    pub implementation_root_sha256: String,
    pub bundle_sha256: String,
    pub epoch_sha256: String,
    pub result_sha256: String,
    pub verified: bool,
    pub receipt_sha256: String,
}

impl PublicVerifierReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verifier_id: impl Into<String>,
        organization_root_sha256: impl Into<String>,
        implementation_root_sha256: impl Into<String>,
        bundle: &PublicVerificationBundle,
        epoch: &TrustEpoch,
        result_sha256: impl Into<String>,
        verified: bool,
    ) -> Result<Self, PostClosureError> {
        bundle.verify()?;
        epoch.verify()?;
        let verifier_id = verifier_id.into();
        let organization_root_sha256 = organization_root_sha256.into();
        let implementation_root_sha256 = implementation_root_sha256.into();
        let result_sha256 = result_sha256.into();
        validate_identifier(&verifier_id, "public verifier")?;
        validate_sha256(&organization_root_sha256, "public verifier organization")?;
        validate_sha256(
            &implementation_root_sha256,
            "public verifier implementation",
        )?;
        validate_sha256(&result_sha256, "public verifier result")?;
        if epoch.public_bundle_sha256 != bundle.bundle_sha256 || !verified {
            return Err(PostClosureError::InvalidProgramClosure(
                "public verifier binding or result".into(),
            ));
        }
        let bundle_sha256 = bundle.bundle_sha256.clone();
        let epoch_sha256 = epoch.epoch_sha256.clone();
        let receipt_sha256 = hash_serializable(&(
            &verifier_id,
            &organization_root_sha256,
            &implementation_root_sha256,
            &bundle_sha256,
            &epoch_sha256,
            &result_sha256,
            verified,
        ))?;
        Ok(Self {
            verifier_id,
            organization_root_sha256,
            implementation_root_sha256,
            bundle_sha256,
            epoch_sha256,
            result_sha256,
            verified,
            receipt_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.verifier_id, "public verifier")?;
        for (name, value) in [
            (
                "public verifier organization",
                self.organization_root_sha256.as_str(),
            ),
            (
                "public verifier implementation",
                self.implementation_root_sha256.as_str(),
            ),
            ("public verifier bundle", self.bundle_sha256.as_str()),
            ("public verifier epoch", self.epoch_sha256.as_str()),
            ("public verifier result", self.result_sha256.as_str()),
        ] {
            validate_sha256(value, name)?;
        }
        if !self.verified {
            return Err(PostClosureError::InvalidProgramClosure(
                "public verifier result".into(),
            ));
        }
        let expected = hash_serializable(&(
            &self.verifier_id,
            &self.organization_root_sha256,
            &self.implementation_root_sha256,
            &self.bundle_sha256,
            &self.epoch_sha256,
            &self.result_sha256,
            self.verified,
        ))?;
        if expected != self.receipt_sha256 {
            return Err(PostClosureError::InvalidProgramClosure(
                "public verifier receipt digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicVerificationQuorum {
    pub quorum_id: String,
    pub bundle_sha256: String,
    pub epoch_sha256: String,
    pub receipts: BTreeMap<String, PublicVerifierReceipt>,
    pub quorum_sha256: String,
}

impl PublicVerificationQuorum {
    pub fn new(
        quorum_id: impl Into<String>,
        bundle: &PublicVerificationBundle,
        epoch: &TrustEpoch,
        receipts: Vec<PublicVerifierReceipt>,
    ) -> Result<Self, PostClosureError> {
        bundle.verify()?;
        epoch.verify()?;
        let quorum_id = quorum_id.into();
        validate_identifier(&quorum_id, "public verification quorum")?;
        if receipts.len() < 3 || receipts.len() > MAX_PUBLIC_VERIFIERS {
            return Err(PostClosureError::InvalidProgramClosure(
                "public verification quorum cardinality".into(),
            ));
        }
        let mut by_id = BTreeMap::new();
        let mut organizations = BTreeSet::new();
        let mut implementations = BTreeSet::new();
        let mut results = BTreeSet::new();
        for receipt in receipts {
            receipt.verify()?;
            if receipt.bundle_sha256 != bundle.bundle_sha256
                || receipt.epoch_sha256 != epoch.epoch_sha256
            {
                return Err(PostClosureError::InvalidProgramClosure(
                    "public verification receipt binding".into(),
                ));
            }
            organizations.insert(receipt.organization_root_sha256.clone());
            implementations.insert(receipt.implementation_root_sha256.clone());
            results.insert(receipt.result_sha256.clone());
            if by_id.insert(receipt.verifier_id.clone(), receipt).is_some() {
                return Err(PostClosureError::InvalidProgramClosure(
                    "duplicate public verifier".into(),
                ));
            }
        }
        if organizations.len() < 3 || implementations.len() < 3 || results.len() != 1 {
            return Err(PostClosureError::InvalidProgramClosure(
                "public verification diversity or result drift".into(),
            ));
        }
        let bundle_sha256 = bundle.bundle_sha256.clone();
        let epoch_sha256 = epoch.epoch_sha256.clone();
        let quorum_sha256 =
            hash_serializable(&(&quorum_id, &bundle_sha256, &epoch_sha256, &by_id))?;
        Ok(Self {
            quorum_id,
            bundle_sha256,
            epoch_sha256,
            receipts: by_id,
            quorum_sha256,
        })
    }

    pub fn verify(&self) -> Result<(), PostClosureError> {
        validate_identifier(&self.quorum_id, "public verification quorum")?;
        validate_sha256(&self.bundle_sha256, "public quorum bundle")?;
        validate_sha256(&self.epoch_sha256, "public quorum epoch")?;
        if self.receipts.len() < 3 || self.receipts.len() > MAX_PUBLIC_VERIFIERS {
            return Err(PostClosureError::InvalidProgramClosure(
                "public verification quorum cardinality".into(),
            ));
        }
        let mut organizations = BTreeSet::new();
        let mut implementations = BTreeSet::new();
        let mut results = BTreeSet::new();
        for (key, receipt) in &self.receipts {
            receipt.verify()?;
            if key != &receipt.verifier_id
                || receipt.bundle_sha256 != self.bundle_sha256
                || receipt.epoch_sha256 != self.epoch_sha256
            {
                return Err(PostClosureError::InvalidProgramClosure(
                    "public verification quorum binding".into(),
                ));
            }
            organizations.insert(receipt.organization_root_sha256.clone());
            implementations.insert(receipt.implementation_root_sha256.clone());
            results.insert(receipt.result_sha256.clone());
        }
        let expected = hash_serializable(&(
            &self.quorum_id,
            &self.bundle_sha256,
            &self.epoch_sha256,
            &self.receipts,
        ))?;
        if organizations.len() < 3
            || implementations.len() < 3
            || results.len() != 1
            || expected != self.quorum_sha256
        {
            return Err(PostClosureError::InvalidProgramClosure(
                "public verification diversity, drift or digest".into(),
            ));
        }
        Ok(())
    }
}
