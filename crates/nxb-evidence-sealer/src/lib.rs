#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use nxb_knowledge_reporting::{EvidenceInput, EvidenceRecord};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const SEALED_EVIDENCE_VERSION: u32 = 1;
pub const SEALED_EVIDENCE_ALGORITHM: &str = "aes-256-gcm";
pub const SEALED_EVIDENCE_SUFFIX: &str = ".nxbseal";
pub const MAX_SEALED_EVIDENCE_BYTES: usize = 1024 * 1024;
pub const MAX_STORE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const AES_256_KEY_BYTES: usize = 32;
const GCM_NONCE_BYTES: usize = 12;
const GCM_TAG_BYTES: usize = 16;

pub struct EvidenceSealingKey {
    bytes: [u8; AES_256_KEY_BYTES],
}

impl EvidenceSealingKey {
    pub fn new(bytes: [u8; AES_256_KEY_BYTES]) -> Self {
        Self { bytes }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for EvidenceSealingKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for EvidenceSealingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceSealingKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

pub struct ProductionEvidenceSealer {
    key_id: String,
    key: aead::LessSafeKey,
    random: SystemRandom,
}

impl fmt::Debug for ProductionEvidenceSealer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionEvidenceSealer")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ProductionEvidenceSealer {
    pub fn new(
        key_id: impl Into<String>,
        key_material: EvidenceSealingKey,
    ) -> Result<Self, EvidenceSealerError> {
        let key_id = key_id.into();
        validate_identifier(&key_id, "key_id")?;
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key_material.as_bytes())
            .map_err(|_| EvidenceSealerError::Crypto)?;
        Ok(Self {
            key_id,
            key: aead::LessSafeKey::new(unbound),
            random: SystemRandom::new(),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    fn seal(
        &self,
        binding: SealedEvidenceBinding,
        plaintext: &[u8],
    ) -> Result<SealedEvidenceEnvelope, EvidenceSealerError> {
        if plaintext.is_empty() || plaintext.len() > MAX_SEALED_EVIDENCE_BYTES {
            return Err(EvidenceSealerError::EnvelopeLimit);
        }
        let mut nonce_bytes = [0_u8; GCM_NONCE_BYTES];
        self.random
            .fill(&mut nonce_bytes)
            .map_err(|_| EvidenceSealerError::Random)?;
        self.seal_with_nonce(binding, plaintext, nonce_bytes)
    }

    fn seal_with_nonce(
        &self,
        binding: SealedEvidenceBinding,
        plaintext: &[u8],
        nonce_bytes: [u8; GCM_NONCE_BYTES],
    ) -> Result<SealedEvidenceEnvelope, EvidenceSealerError> {
        binding.validate()?;
        let aad_bytes = canonical_json(&binding)?;
        let plaintext_sha256 = hash_bytes(plaintext);
        let mut ciphertext = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce_bytes),
                aead::Aad::from(aad_bytes.as_slice()),
                &mut ciphertext,
            )
            .map_err(|_| EvidenceSealerError::Crypto)?;
        if ciphertext.len() != plaintext.len() + GCM_TAG_BYTES {
            return Err(EvidenceSealerError::Crypto);
        }
        let ciphertext_sha256 = hash_bytes(&ciphertext);
        let envelope = SealedEvidenceEnvelope {
            version: SEALED_EVIDENCE_VERSION,
            algorithm: SEALED_EVIDENCE_ALGORITHM.into(),
            key_id: self.key_id.clone(),
            binding,
            nonce_hex: lower_hex(&nonce_bytes),
            plaintext_sha256,
            ciphertext_sha256,
            ciphertext_hex: lower_hex(&ciphertext),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    fn open(
        &self,
        envelope: &SealedEvidenceEnvelope,
    ) -> Result<Vec<u8>, EvidenceSealerError> {
        envelope.validate()?;
        if envelope.key_id != self.key_id {
            return Err(EvidenceSealerError::KeyIdMismatch);
        }
        let nonce = decode_fixed_hex::<GCM_NONCE_BYTES>(&envelope.nonce_hex, "nonce")?;
        let mut ciphertext = decode_hex(&envelope.ciphertext_hex, "ciphertext")?;
        if hash_bytes(&ciphertext) != envelope.ciphertext_sha256 {
            return Err(EvidenceSealerError::CiphertextDigestMismatch);
        }
        let aad_bytes = canonical_json(&envelope.binding)?;
        let plaintext_length = {
            let plaintext = self
                .key
                .open_in_place(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(aad_bytes.as_slice()),
                    &mut ciphertext,
                )
                .map_err(|_| EvidenceSealerError::Crypto)?;
            plaintext.len()
        };
        ciphertext.truncate(plaintext_length);
        if hash_bytes(&ciphertext) != envelope.plaintext_sha256 {
            return Err(EvidenceSealerError::PlaintextDigestMismatch);
        }
        Ok(ciphertext)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedEvidenceBinding {
    pub evidence_id: String,
    pub content_sha256: String,
    pub policy_snapshot_sha256: String,
    pub provenance_sha256: String,
    pub audit_tail_hash: String,
}

impl SealedEvidenceBinding {
    fn from_record(record: &EvidenceRecord) -> Self {
        Self {
            evidence_id: record.evidence_id.clone(),
            content_sha256: record.content_sha256.clone(),
            policy_snapshot_sha256: record.policy_snapshot_sha256.clone(),
            provenance_sha256: record.provenance_sha256.clone(),
            audit_tail_hash: record.audit_tail_hash.clone(),
        }
    }

    fn validate(&self) -> Result<(), EvidenceSealerError> {
        validate_identifier(&self.evidence_id, "evidence_id")?;
        validate_sha256(&self.content_sha256, "content_sha256")?;
        validate_sha256(&self.policy_snapshot_sha256, "policy_snapshot_sha256")?;
        validate_sha256(&self.provenance_sha256, "provenance_sha256")?;
        validate_sha256(&self.audit_tail_hash, "audit_tail_hash")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedEvidenceEnvelope {
    pub version: u32,
    pub algorithm: String,
    pub key_id: String,
    pub binding: SealedEvidenceBinding,
    pub nonce_hex: String,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub ciphertext_hex: String,
}

impl SealedEvidenceEnvelope {
    fn validate(&self) -> Result<(), EvidenceSealerError> {
        if self.version != SEALED_EVIDENCE_VERSION {
            return Err(EvidenceSealerError::UnsupportedVersion);
        }
        if self.algorithm != SEALED_EVIDENCE_ALGORITHM {
            return Err(EvidenceSealerError::UnsupportedAlgorithm);
        }
        validate_identifier(&self.key_id, "key_id")?;
        self.binding.validate()?;
        validate_sha256(&self.plaintext_sha256, "plaintext_sha256")?;
        validate_sha256(&self.ciphertext_sha256, "ciphertext_sha256")?;
        if self.nonce_hex.len() != GCM_NONCE_BYTES * 2 {
            return Err(EvidenceSealerError::InvalidHex("nonce".into()));
        }
        let ciphertext_bytes = self.ciphertext_hex.len() / 2;
        if self.ciphertext_hex.is_empty()
            || self.ciphertext_hex.len() % 2 != 0
            || ciphertext_bytes > MAX_SEALED_EVIDENCE_BYTES + GCM_TAG_BYTES
        {
            return Err(EvidenceSealerError::EnvelopeLimit);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedEvidenceReceipt {
    pub evidence_id: String,
    pub key_id: String,
    pub file_name: String,
    pub envelope_sha256: String,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub stored_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedEvidenceManifestEntry {
    pub evidence_id: String,
    pub file_name: String,
    pub file_sha256: String,
    pub key_id: String,
    pub content_sha256: String,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub stored_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedEvidenceManifest {
    pub version: u32,
    pub policy_snapshot_sha256: String,
    pub entries: Vec<SealedEvidenceManifestEntry>,
    pub total_stored_bytes: u64,
    pub manifest_sha256: String,
}

impl SealedEvidenceManifest {
    fn calculate_sha256(&self) -> Result<String, EvidenceSealerError> {
        hash_serializable(&(
            self.version,
            &self.policy_snapshot_sha256,
            &self.entries,
            self.total_stored_bytes,
        ))
    }
}

#[derive(Debug)]
pub struct EncryptedEvidenceStore {
    directory: PathBuf,
    policy_snapshot_sha256: String,
    maximum_store_bytes: u64,
    sealer: ProductionEvidenceSealer,
}

impl EncryptedEvidenceStore {
    pub fn initialize(
        directory: impl Into<PathBuf>,
        policy_snapshot_sha256: impl Into<String>,
        maximum_store_bytes: u64,
        sealer: ProductionEvidenceSealer,
    ) -> Result<Self, EvidenceSealerError> {
        let directory = directory.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "policy_snapshot_sha256")?;
        validate_store_budget(maximum_store_bytes)?;
        match fs::symlink_metadata(&directory) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(EvidenceSealerError::InvalidStoreDirectory);
                }
                if fs::read_dir(&directory)
                    .map_err(io_error)?
                    .next()
                    .transpose()
                    .map_err(io_error)?
                    .is_some()
                {
                    return Err(EvidenceSealerError::DirectoryNotEmpty);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&directory).map_err(io_error)?;
                sync_parent(&directory)?;
            }
            Err(error) => return Err(io_error(error)),
        }
        Ok(Self {
            directory,
            policy_snapshot_sha256,
            maximum_store_bytes,
            sealer,
        })
    }

    pub fn open_existing(
        directory: impl Into<PathBuf>,
        policy_snapshot_sha256: impl Into<String>,
        maximum_store_bytes: u64,
        sealer: ProductionEvidenceSealer,
    ) -> Result<Self, EvidenceSealerError> {
        let directory = directory.into();
        let policy_snapshot_sha256 = policy_snapshot_sha256.into();
        validate_sha256(&policy_snapshot_sha256, "policy_snapshot_sha256")?;
        validate_store_budget(maximum_store_bytes)?;
        let metadata = fs::symlink_metadata(&directory).map_err(io_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(EvidenceSealerError::InvalidStoreDirectory);
        }
        let store = Self {
            directory,
            policy_snapshot_sha256,
            maximum_store_bytes,
            sealer,
        };
        store.scan_entries()?;
        Ok(store)
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn policy_snapshot_sha256(&self) -> &str {
        &self.policy_snapshot_sha256
    }

    pub fn maximum_store_bytes(&self) -> u64 {
        self.maximum_store_bytes
    }

    pub fn seal(
        &self,
        record: &EvidenceRecord,
    ) -> Result<SealedEvidenceReceipt, EvidenceSealerError> {
        validate_record(record)?;
        if record.policy_snapshot_sha256 != self.policy_snapshot_sha256 {
            return Err(EvidenceSealerError::PolicySnapshotMismatch);
        }
        let entries = self.scan_entries()?;
        if entries.contains_key(&record.evidence_id) {
            return Err(EvidenceSealerError::EvidenceAlreadyExists);
        }
        let plaintext = canonical_json(record)?;
        let envelope = self
            .sealer
            .seal(SealedEvidenceBinding::from_record(record), &plaintext)?;
        let envelope_bytes = canonical_json(&envelope)?;
        if envelope_bytes.len() > MAX_SEALED_EVIDENCE_BYTES {
            return Err(EvidenceSealerError::EnvelopeLimit);
        }
        let current_bytes = store_bytes(&entries)?;
        let next_bytes = current_bytes
            .checked_add(envelope_bytes.len() as u64)
            .ok_or(EvidenceSealerError::WorkspaceBudgetExceeded)?;
        if next_bytes > self.maximum_store_bytes {
            return Err(EvidenceSealerError::WorkspaceBudgetExceeded);
        }
        let file_name = sealed_file_name(&record.evidence_id);
        self.publish(&record.evidence_id, &file_name, &envelope, &envelope_bytes)?;
        let recovered = self.open(&record.evidence_id)?;
        if recovered != *record {
            return Err(EvidenceSealerError::BindingMismatch);
        }
        Ok(SealedEvidenceReceipt {
            evidence_id: record.evidence_id.clone(),
            key_id: envelope.key_id.clone(),
            file_name,
            envelope_sha256: hash_bytes(&envelope_bytes),
            plaintext_sha256: envelope.plaintext_sha256,
            ciphertext_sha256: envelope.ciphertext_sha256,
            stored_bytes: envelope_bytes.len() as u64,
        })
    }

    pub fn open(&self, evidence_id: &str) -> Result<EvidenceRecord, EvidenceSealerError> {
        validate_identifier(evidence_id, "evidence_id")?;
        let entries = self.scan_entries()?;
        let path = entries
            .get(evidence_id)
            .ok_or(EvidenceSealerError::EvidenceNotFound)?;
        self.open_path(evidence_id, path)
    }

    pub fn verify_all(&self) -> Result<SealedEvidenceManifest, EvidenceSealerError> {
        let entries = self.scan_entries()?;
        let total_stored_bytes = store_bytes(&entries)?;
        let mut manifest_entries = Vec::with_capacity(entries.len());
        for (evidence_id, path) in entries {
            let bytes = read_bounded_file(&path)?;
            let envelope = parse_canonical_envelope(&bytes)?;
            let record = self.open_envelope(&evidence_id, &envelope)?;
            manifest_entries.push(SealedEvidenceManifestEntry {
                evidence_id: evidence_id.clone(),
                file_name: sealed_file_name(&evidence_id),
                file_sha256: hash_bytes(&bytes),
                key_id: envelope.key_id,
                content_sha256: record.content_sha256,
                plaintext_sha256: envelope.plaintext_sha256,
                ciphertext_sha256: envelope.ciphertext_sha256,
                stored_bytes: bytes.len() as u64,
            });
        }
        let mut manifest = SealedEvidenceManifest {
            version: SEALED_EVIDENCE_VERSION,
            policy_snapshot_sha256: self.policy_snapshot_sha256.clone(),
            entries: manifest_entries,
            total_stored_bytes,
            manifest_sha256: String::new(),
        };
        manifest.manifest_sha256 = manifest.calculate_sha256()?;
        Ok(manifest)
    }

    fn open_path(
        &self,
        evidence_id: &str,
        path: &Path,
    ) -> Result<EvidenceRecord, EvidenceSealerError> {
        let bytes = read_bounded_file(path)?;
        let envelope = parse_canonical_envelope(&bytes)?;
        self.open_envelope(evidence_id, &envelope)
    }

    fn open_envelope(
        &self,
        evidence_id: &str,
        envelope: &SealedEvidenceEnvelope,
    ) -> Result<EvidenceRecord, EvidenceSealerError> {
        if envelope.binding.evidence_id != evidence_id
            || envelope.binding.policy_snapshot_sha256 != self.policy_snapshot_sha256
        {
            return Err(EvidenceSealerError::BindingMismatch);
        }
        let plaintext = self.sealer.open(envelope)?;
        let record: EvidenceRecord = serde_json::from_slice(&plaintext)
            .map_err(|error| EvidenceSealerError::Serialization(error.to_string()))?;
        if plaintext != canonical_json(&record)? {
            return Err(EvidenceSealerError::NonCanonicalPlaintext);
        }
        validate_record(&record)?;
        if SealedEvidenceBinding::from_record(&record) != envelope.binding {
            return Err(EvidenceSealerError::BindingMismatch);
        }
        Ok(record)
    }

    fn publish(
        &self,
        evidence_id: &str,
        file_name: &str,
        envelope: &SealedEvidenceEnvelope,
        bytes: &[u8],
    ) -> Result<(), EvidenceSealerError> {
        let final_path = self.directory.join(file_name);
        let temporary_path = self.directory.join(format!(
            ".{evidence_id}.{}.{}.tmp",
            std::process::id(),
            envelope.nonce_hex
        ));
        let publication = (|| -> Result<(), EvidenceSealerError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary_path)
                .map_err(io_error)?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(io_error)?;
            fs::hard_link(&temporary_path, &final_path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    EvidenceSealerError::EvidenceAlreadyExists
                } else {
                    io_error(error)
                }
            })?;
            sync_directory(&self.directory)?;
            Ok(())
        })();
        if let Err(error) = publication {
            let _ = fs::remove_file(&temporary_path);
            return Err(error);
        }
        fs::remove_file(&temporary_path).map_err(io_error)?;
        sync_directory(&self.directory)
    }

    fn scan_entries(&self) -> Result<BTreeMap<String, PathBuf>, EvidenceSealerError> {
        let mut entries = BTreeMap::new();
        let mut total_bytes = 0_u64;
        for entry in fs::read_dir(&self.directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let file_type = entry.file_type().map_err(io_error)?;
            if !file_type.is_file() || file_type.is_symlink() {
                return Err(EvidenceSealerError::UnexpectedStoreEntry);
            }
            let file_name = entry
                .file_name()
                .into_string()
                .map_err(|_| EvidenceSealerError::UnexpectedStoreEntry)?;
            if file_name.starts_with('.') || file_name.ends_with(".tmp") {
                return Err(EvidenceSealerError::IncompletePublication);
            }
            let evidence_id = parse_sealed_file_name(&file_name)?;
            let metadata = entry.metadata().map_err(io_error)?;
            if metadata.len() == 0 || metadata.len() > MAX_SEALED_EVIDENCE_BYTES as u64 {
                return Err(EvidenceSealerError::EnvelopeLimit);
            }
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or(EvidenceSealerError::WorkspaceBudgetExceeded)?;
            if total_bytes > self.maximum_store_bytes {
                return Err(EvidenceSealerError::WorkspaceBudgetExceeded);
            }
            if entries.insert(evidence_id, entry.path()).is_some() {
                return Err(EvidenceSealerError::DuplicateEvidenceEntry);
            }
        }
        Ok(entries)
    }
}

fn validate_record(record: &EvidenceRecord) -> Result<(), EvidenceSealerError> {
    validate_identifier(&record.evidence_id, "evidence_id")?;
    validate_identifier(&record.subject_id, "subject_id")?;
    validate_sha256(&record.provenance_sha256, "provenance_sha256")?;
    validate_sha256(&record.policy_snapshot_sha256, "policy_snapshot_sha256")?;
    validate_sha256(&record.content_sha256, "content_sha256")?;
    validate_sha256(&record.audit_tail_hash, "audit_tail_hash")?;
    let input = EvidenceInput {
        class: record.class,
        subject_id: record.subject_id.clone(),
        summary: record.summary.clone(),
        metadata: record.metadata.clone(),
        provenance_sha256: record.provenance_sha256.clone(),
        policy_snapshot_sha256: record.policy_snapshot_sha256.clone(),
        redaction_count: record.redaction_count,
        redaction_verified: true,
    };
    input
        .validate()
        .map_err(|error| EvidenceSealerError::InvalidEvidence(error.to_string()))?;
    let input_bytes = serde_json::to_vec(&input)
        .map_err(|error| EvidenceSealerError::Serialization(error.to_string()))?;
    if input_bytes.len() != record.serialized_bytes
        || hash_bytes(&input_bytes) != record.content_sha256
        || record.evidence_id != format!("evidence-{}", &record.content_sha256[..24])
    {
        return Err(EvidenceSealerError::EvidenceContentDigestMismatch);
    }
    Ok(())
}

fn parse_canonical_envelope(
    bytes: &[u8],
) -> Result<SealedEvidenceEnvelope, EvidenceSealerError> {
    let envelope: SealedEvidenceEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| EvidenceSealerError::Serialization(error.to_string()))?;
    if bytes != canonical_json(&envelope)? {
        return Err(EvidenceSealerError::NonCanonicalEnvelope);
    }
    envelope.validate()?;
    Ok(envelope)
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, EvidenceSealerError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(EvidenceSealerError::UnexpectedStoreEntry);
    }
    if metadata.len() == 0 || metadata.len() > MAX_SEALED_EVIDENCE_BYTES as u64 {
        return Err(EvidenceSealerError::EnvelopeLimit);
    }
    fs::read(path).map_err(io_error)
}

fn validate_store_budget(maximum_store_bytes: u64) -> Result<(), EvidenceSealerError> {
    if maximum_store_bytes == 0 || maximum_store_bytes > MAX_STORE_BYTES {
        return Err(EvidenceSealerError::InvalidStoreBudget);
    }
    Ok(())
}

fn store_bytes(entries: &BTreeMap<String, PathBuf>) -> Result<u64, EvidenceSealerError> {
    entries.values().try_fold(0_u64, |total, path| {
        let length = fs::metadata(path).map_err(io_error)?.len();
        total
            .checked_add(length)
            .ok_or(EvidenceSealerError::WorkspaceBudgetExceeded)
    })
}

fn sealed_file_name(evidence_id: &str) -> String {
    format!("{evidence_id}{SEALED_EVIDENCE_SUFFIX}")
}

fn parse_sealed_file_name(file_name: &str) -> Result<String, EvidenceSealerError> {
    let evidence_id = file_name
        .strip_suffix(SEALED_EVIDENCE_SUFFIX)
        .ok_or(EvidenceSealerError::UnexpectedStoreEntry)?;
    validate_identifier(evidence_id, "evidence_id")?;
    if !evidence_id.starts_with("evidence-") {
        return Err(EvidenceSealerError::UnexpectedStoreEntry);
    }
    Ok(evidence_id.into())
}

fn validate_identifier(value: &str, field: &str) -> Result<(), EvidenceSealerError> {
    if value.is_empty()
        || value.len() > 192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(EvidenceSealerError::InvalidIdentifier(field.into()));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), EvidenceSealerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EvidenceSealerError::InvalidSha256(field.into()));
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, EvidenceSealerError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| EvidenceSealerError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, EvidenceSealerError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| EvidenceSealerError::Serialization(error.to_string()))?;
    Ok(hash_bytes(&bytes))
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

fn decode_fixed_hex<const N: usize>(
    value: &str,
    field: &str,
) -> Result<[u8; N], EvidenceSealerError> {
    let bytes = decode_hex(value, field)?;
    bytes
        .try_into()
        .map_err(|_| EvidenceSealerError::InvalidHex(field.into()))
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, EvidenceSealerError> {
    if value.len() % 2 != 0 {
        return Err(EvidenceSealerError::InvalidHex(field.into()));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for index in (0..bytes.len()).step_by(2) {
        let high = hex_nibble(bytes[index])
            .ok_or_else(|| EvidenceSealerError::InvalidHex(field.into()))?;
        let low = hex_nibble(bytes[index + 1])
            .ok_or_else(|| EvidenceSealerError::InvalidHex(field.into()))?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), EvidenceSealerError> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), EvidenceSealerError> {
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), EvidenceSealerError> {
    match path.parent() {
        Some(parent) => sync_directory(parent),
        None => Ok(()),
    }
}

fn io_error(error: std::io::Error) -> EvidenceSealerError {
    EvidenceSealerError::Io(error.to_string())
}

#[derive(Debug, Error)]
pub enum EvidenceSealerError {
    #[error("unsupported sealed-evidence version")]
    UnsupportedVersion,
    #[error("unsupported sealed-evidence algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("invalid SHA-256 field: {0}")]
    InvalidSha256(String),
    #[error("invalid hexadecimal field: {0}")]
    InvalidHex(String),
    #[error("invalid evidence store directory")]
    InvalidStoreDirectory,
    #[error("evidence store directory must be empty during initialization")]
    DirectoryNotEmpty,
    #[error("invalid evidence store byte budget")]
    InvalidStoreBudget,
    #[error("sealed evidence exceeds the configured envelope bound")]
    EnvelopeLimit,
    #[error("evidence store byte budget was exceeded")]
    WorkspaceBudgetExceeded,
    #[error("evidence record is invalid: {0}")]
    InvalidEvidence(String),
    #[error("evidence content digest or identifier is invalid")]
    EvidenceContentDigestMismatch,
    #[error("evidence policy snapshot does not match the store")]
    PolicySnapshotMismatch,
    #[error("sealed evidence binding does not match the recovered record or store")]
    BindingMismatch,
    #[error("sealed evidence key identifier does not match the active key")]
    KeyIdMismatch,
    #[error("ciphertext SHA-256 does not match the envelope")]
    CiphertextDigestMismatch,
    #[error("plaintext SHA-256 does not match the envelope")]
    PlaintextDigestMismatch,
    #[error("sealed envelope is not canonical JSON")]
    NonCanonicalEnvelope,
    #[error("decrypted evidence record is not canonical JSON")]
    NonCanonicalPlaintext,
    #[error("evidence record already exists")]
    EvidenceAlreadyExists,
    #[error("evidence record was not found")]
    EvidenceNotFound,
    #[error("duplicate evidence entry exists")]
    DuplicateEvidenceEntry,
    #[error("unexpected entry exists in the dedicated evidence store")]
    UnexpectedStoreEntry,
    #[error("evidence publication was interrupted")]
    IncompletePublication,
    #[error("cryptographic random generation failed")]
    Random,
    #[error("authenticated encryption or decryption failed")]
    Crypto,
    #[error("sealed evidence serialization failed: {0}")]
    Serialization(String),
    #[error("sealed evidence I/O failed: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use nxb_knowledge_reporting::{EvidenceClass, EvidenceStore};
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn sha(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn key(byte: u8) -> EvidenceSealingKey {
        EvidenceSealingKey::new([byte; AES_256_KEY_BYTES])
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "nxb-evidence-sealer-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn evidence_record(policy_snapshot_sha256: &str) -> EvidenceRecord {
        let mut store = EvidenceStore::new(policy_snapshot_sha256, sha('a')).expect("store");
        store
            .insert(EvidenceInput {
                class: EvidenceClass::Observation,
                subject_id: "endpoint-login".into(),
                summary: "Redacted response timing observation".into(),
                metadata: BTreeMap::from([
                    ("method".into(), "GET".into()),
                    ("status".into(), "200".into()),
                ]),
                provenance_sha256: sha('b'),
                policy_snapshot_sha256: policy_snapshot_sha256.into(),
                redaction_count: 2,
                redaction_verified: true,
            })
            .expect("evidence")
            .clone()
    }

    #[test]
    fn encrypted_store_round_trip_and_manifest() {
        let directory = temporary_directory("round-trip");
        let policy = sha('c');
        let record = evidence_record(&policy);
        let store = EncryptedEvidenceStore::initialize(
            &directory,
            &policy,
            4 * 1024 * 1024,
            ProductionEvidenceSealer::new("evidence-key-1", key(7)).expect("sealer"),
        )
        .expect("initialize");
        let receipt = store.seal(&record).expect("seal");
        assert_eq!(receipt.evidence_id, record.evidence_id);
        assert_eq!(store.open(&record.evidence_id).expect("open"), record);
        let manifest = store.verify_all().expect("manifest");
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.total_stored_bytes, receipt.stored_bytes);
        validate_sha256(&manifest.manifest_sha256, "manifest").expect("manifest digest");
        fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn duplicate_publication_is_rejected() {
        let directory = temporary_directory("duplicate");
        let policy = sha('d');
        let record = evidence_record(&policy);
        let store = EncryptedEvidenceStore::initialize(
            &directory,
            &policy,
            4 * 1024 * 1024,
            ProductionEvidenceSealer::new("evidence-key-1", key(8)).expect("sealer"),
        )
        .expect("initialize");
        store.seal(&record).expect("first seal");
        assert!(matches!(
            store.seal(&record),
            Err(EvidenceSealerError::EvidenceAlreadyExists)
        ));
        fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn wrong_key_fails_closed() {
        let directory = temporary_directory("wrong-key");
        let policy = sha('e');
        let record = evidence_record(&policy);
        EncryptedEvidenceStore::initialize(
            &directory,
            &policy,
            4 * 1024 * 1024,
            ProductionEvidenceSealer::new("evidence-key-1", key(9)).expect("sealer"),
        )
        .expect("initialize")
        .seal(&record)
        .expect("seal");
        let reopened = EncryptedEvidenceStore::open_existing(
            &directory,
            &policy,
            4 * 1024 * 1024,
            ProductionEvidenceSealer::new("evidence-key-1", key(10)).expect("sealer"),
        )
        .expect("reopen");
        assert!(matches!(
            reopened.open(&record.evidence_id),
            Err(EvidenceSealerError::Crypto)
        ));
        fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn wrong_key_identifier_fails_before_decryption() {
        let directory = temporary_directory("wrong-key-id");
        let policy = sha('f');
        let record = evidence_record(&policy);
        EncryptedEvidenceStore::initialize(
            &directory,
            &policy,
            4 * 1024 * 1024,
            ProductionEvidenceSealer::new("evidence-key-1", key(11)).expect("sealer"),
        )
        .expect("initialize")
        .seal(&record)
        .expect("seal");
        let reopened = EncryptedEvidenceStore::open_existing(
            &directory,
            &policy,
            4 * 1024 * 1024,
            ProductionEvidenceSealer::new("evidence-key-2", key(11)).expect("sealer"),
        )
        .expect("reopen");
        assert!(matches!(
            reopened.open(&record.evidence_id),
            Err(EvidenceSealerError::KeyIdMismatch)
        ));
        fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn ciphertext_tampering_is_rejected() {
        let directory = temporary_directory("tamper");
        let policy = sha('1');
        let record = evidence_record(&policy);
        let store = EncryptedEvidenceStore::initialize(
            &directory,
            &policy,
            4 * 1024 * 1024,
            ProductionEvidenceSealer::new("evidence-key-1", key(12)).expect("sealer"),
        )
        .expect("initialize");
        store.seal(&record).expect("seal");
        let path = directory.join(sealed_file_name(&record.evidence_id));
        let bytes = fs::read(&path).expect("read");
        let mut envelope: SealedEvidenceEnvelope =
            serde_json::from_slice(&bytes).expect("envelope");
        envelope.ciphertext_hex.replace_range(0..2, "00");
        fs::write(&path, canonical_json(&envelope).expect("canonical")).expect("tamper");
        assert!(matches!(
            store.open(&record.evidence_id),
            Err(EvidenceSealerError::CiphertextDigestMismatch)
        ));
        fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn noncanonical_envelope_is_rejected() {
        let directory = temporary_directory("noncanonical");
        let policy = sha('2');
        let record = evidence_record(&policy);
        let store = EncryptedEvidenceStore::initialize(
            &directory,
            &policy,
            4 * 1024 * 1024,
            ProductionEvidenceSealer::new("evidence-key-1", key(13)).expect("sealer"),
        )
        .expect("initialize");
        store.seal(&record).expect("seal");
        let path = directory.join(sealed_file_name(&record.evidence_id));
        let mut bytes = fs::read(&path).expect("read");
        bytes.push(b' ');
        fs::write(&path, bytes).expect("rewrite");
        assert!(matches!(
            store.open(&record.evidence_id),
            Err(EvidenceSealerError::NonCanonicalEnvelope)
        ));
        fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn policy_drift_is_rejected() {
        let directory = temporary_directory("policy-drift");
        let policy = sha('3');
        let record = evidence_record(&sha('4'));
        let store = EncryptedEvidenceStore::initialize(
            &directory,
            &policy,
            4 * 1024 * 1024,
            ProductionEvidenceSealer::new("evidence-key-1", key(14)).expect("sealer"),
        )
        .expect("initialize");
        assert!(matches!(
            store.seal(&record),
            Err(EvidenceSealerError::PolicySnapshotMismatch)
        ));
        fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn interrupted_publication_fails_closed() {
        let directory = temporary_directory("interrupted");
        let policy = sha('5');
        fs::create_dir(&directory).expect("directory");
        fs::write(directory.join(".evidence-test.1.tmp"), b"partial").expect("temporary");
        assert!(matches!(
            EncryptedEvidenceStore::open_existing(
                &directory,
                &policy,
                4 * 1024 * 1024,
                ProductionEvidenceSealer::new("evidence-key-1", key(15)).expect("sealer"),
            ),
            Err(EvidenceSealerError::IncompletePublication)
        ));
        fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn key_debug_output_is_redacted() {
        let key = key(16);
        assert_eq!(
            format!("{key:?}"),
            "EvidenceSealingKey { bytes: \"[REDACTED]\" }"
        );
    }
}
