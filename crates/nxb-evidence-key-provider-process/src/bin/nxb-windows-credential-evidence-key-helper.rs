#![deny(unsafe_op_in_unsafe_fn)]

use std::io::{self, BufWriter};

use nxb_evidence_key_provider::EVIDENCE_SEALING_KEY_BYTES;
use nxb_vault::SecretKind;
use nxb_vault_provider::ProviderIdentity;
use nxb_vault_provider_process::{
    protocol::{read_host_message, write_provider_message},
    sha256_file, sha256_hex, HostMessage, ProcessVaultProviderError, ProviderMessage,
    MAX_PROCESS_METADATA_BYTES, PROCESS_PROVIDER_PROTOCOL_VERSION,
};
use zeroize::Zeroizing;

const PROVIDER_ID: &str = "nxb-windows-credential-evidence-key";
const CAPABILITY_V1: &[u8] = b"nxb152-windows-credential-manager-evidence-key-fetch-v1";
const TARGET_PREFIX: &str = "Naveax_NXBounty_EvidenceKey::";
#[cfg(windows)]
const VERSION_COMMENT_PREFIX: &str = "NXB_EVIDENCE_KEY_VERSION:";
const SYNTHETIC_AUTHORITY: &str = "evidence-key-provider.invalid";
const ADAPTER_WORKER_ID: &str = "evidence-key-process";
const ADAPTER_TENANT_ID: &str = "evidence-key-store";
const ADAPTER_ROLE_ID: &str = "sealing-key";
const MAX_IDENTIFIER_BYTES: usize = 192;
const MAX_PROVIDER_HANDLE_BYTES: usize = 512;

struct HelperError;

impl From<ProcessVaultProviderError> for HelperError {
    fn from(_: ProcessVaultProviderError) -> Self {
        Self
    }
}

struct ActiveSession {
    store_id: String,
    expires_at_epoch_seconds: i64,
    fetch_attempted: bool,
}

struct CredentialRecord {
    version_id: String,
    value: Zeroizing<Vec<u8>>,
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum WinCredError {
    UnsupportedPlatform,
    Missing,
    InvalidRecord,
    Io,
}

fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}

fn run() -> Result<(), HelperError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = BufWriter::new(stdout.lock());

    let (hello, secret) = read_host_message(&mut reader)?;
    if !secret.is_empty() {
        return Err(HelperError);
    }

    let nonce_hex = match hello {
        HostMessage::Hello {
            protocol_version,
            nonce_hex,
            maximum_metadata_bytes,
            maximum_secret_bytes,
        } if protocol_version == PROCESS_PROVIDER_PROTOCOL_VERSION
            && maximum_metadata_bytes == MAX_PROCESS_METADATA_BYTES as u64
            && maximum_secret_bytes == nxb_vault::MAX_SECRET_BYTES as u64 =>
        {
            nonce_hex
        }
        _ => return Err(HelperError),
    };

    let executable = std::env::current_exe().map_err(|_| HelperError)?;
    let identity = ProviderIdentity {
        provider_id: PROVIDER_ID.into(),
        provider_instance_sha256: sha256_file(&executable)?,
        capability_sha256: sha256_hex(CAPABILITY_V1),
    };

    write_provider_message(
        &mut writer,
        &ProviderMessage::Hello {
            protocol_version: PROCESS_PROVIDER_PROTOCOL_VERSION,
            nonce_sha256: sha256_hex(nonce_hex.as_bytes()),
            identity,
        },
        &[],
    )?;

    let mut active: Option<ActiveSession> = None;

    loop {
        let (message, secret) = read_host_message(&mut reader)?;
        if !secret.is_empty() {
            return Err(HelperError);
        }

        match message {
            HostMessage::Begin { sequence, request } if active.is_none() => {
                if request.requested_secret_count != 1
                    || request.scheme != "https"
                    || request.authority != SYNTHETIC_AUTHORITY
                    || request.worker_id != ADAPTER_WORKER_ID
                    || request.tenant_id != ADAPTER_TENANT_ID
                    || request.role_id != ADAPTER_ROLE_ID
                    || request.session_expires_at_epoch_seconds <= 0
                    || !valid_identifier(&request.account_id)
                {
                    return Err(HelperError);
                }

                active = Some(ActiveSession {
                    store_id: request.account_id,
                    expires_at_epoch_seconds: request.session_expires_at_epoch_seconds,
                    fetch_attempted: false,
                });
                write_provider_message(&mut writer, &ProviderMessage::Begun { sequence }, &[])?;
            }
            HostMessage::Fetch { sequence, request } => {
                let session = active.as_mut().ok_or(HelperError)?;
                if session.fetch_attempted {
                    return Err(HelperError);
                }
                session.fetch_attempted = true;

                if request.kind != SecretKind::ApiKey
                    || request.maximum_value_bytes != EVIDENCE_SEALING_KEY_BYTES as u64
                    || !valid_identifier(&request.logical_id)
                    || request
                        .required_version_sha256
                        .as_ref()
                        .is_some_and(|value| !valid_sha256(value))
                {
                    write_failure(&mut writer, sequence, "windows_credential_request_invalid")?;
                    continue;
                }

                let Some(expected_target) = target_name(&session.store_id, &request.logical_id)
                else {
                    write_failure(&mut writer, sequence, "windows_credential_request_invalid")?;
                    continue;
                };

                if request.provider_handle != expected_target {
                    write_failure(&mut writer, sequence, "windows_credential_handle_mismatch")?;
                    continue;
                }

                let record = match wincred::read_evidence_key(&expected_target) {
                    Ok(record) => record,
                    Err(error) => {
                        write_failure(&mut writer, sequence, wincred_failure_code(error))?;
                        continue;
                    }
                };

                if !valid_identifier(&record.version_id) {
                    write_failure(&mut writer, sequence, "windows_credential_metadata_invalid")?;
                    continue;
                }

                if request
                    .required_version_sha256
                    .as_ref()
                    .is_some_and(|required| sha256_hex(record.version_id.as_bytes()) != *required)
                {
                    write_failure(&mut writer, sequence, "windows_credential_version_mismatch")?;
                    continue;
                }

                write_provider_message(
                    &mut writer,
                    &ProviderMessage::Secret {
                        sequence,
                        version_id: record.version_id,
                        expires_at_epoch_seconds: session.expires_at_epoch_seconds,
                        value_bytes: record.value.len() as u64,
                    },
                    &record.value,
                )?;
            }
            HostMessage::Finish { sequence, .. } if active.is_some() => {
                write_provider_message(&mut writer, &ProviderMessage::Finished { sequence }, &[])?;
                return Ok(());
            }
            _ => return Err(HelperError),
        }
    }
}

fn write_failure<W: io::Write>(
    writer: &mut W,
    sequence: u64,
    code: &str,
) -> Result<(), HelperError> {
    write_provider_message(
        writer,
        &ProviderMessage::Failure {
            sequence,
            code: code.into(),
        },
        &[],
    )?;
    Ok(())
}

fn wincred_failure_code(error: WinCredError) -> &'static str {
    match error {
        WinCredError::UnsupportedPlatform => "windows_credential_unsupported_platform",
        WinCredError::Missing => "windows_credential_missing",
        WinCredError::InvalidRecord => "windows_credential_metadata_invalid",
        WinCredError::Io => "windows_credential_io_failure",
    }
}

fn target_name(store_id: &str, key_id: &str) -> Option<String> {
    if !valid_identifier(store_id) || !valid_identifier(key_id) {
        return None;
    }
    let target = format!("{TARGET_PREFIX}{store_id}::{key_id}");
    if target.len() > MAX_PROVIDER_HANDLE_BYTES {
        return None;
    }
    Some(target)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(windows)]
mod wincred {
    use std::{ffi::c_void, ptr, slice};

    use zeroize::Zeroizing;

    use super::{
        valid_identifier, CredentialRecord, WinCredError, EVIDENCE_SEALING_KEY_BYTES,
        VERSION_COMMENT_PREFIX,
    };

    const CRED_TYPE_GENERIC: u32 = 1;
    const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;
    const CRED_MAX_STRING_LENGTH: usize = 256;
    const ERROR_NOT_FOUND: i32 = 1168;

    #[repr(C)]
    struct FileTime {
        _low_date_time: u32,
        _high_date_time: u32,
    }

    #[repr(C)]
    struct CredentialW {
        _flags: u32,
        credential_type: u32,
        _target_name: *mut u16,
        comment: *mut u16,
        _last_written: FileTime,
        credential_blob_size: u32,
        credential_blob: *mut u8,
        persist: u32,
        _attribute_count: u32,
        _attributes: *mut c_void,
        _target_alias: *mut u16,
        _user_name: *mut u16,
    }

    #[link(name = "Advapi32")]
    unsafe extern "system" {
        #[link_name = "CredReadW"]
        fn cred_read_w(
            target_name: *const u16,
            credential_type: u32,
            flags: u32,
            credential: *mut *mut CredentialW,
        ) -> i32;

        #[link_name = "CredFree"]
        fn cred_free(buffer: *mut c_void);
    }

    struct CredentialGuard(*mut CredentialW);

    impl CredentialGuard {
        fn zero_blob(&mut self) {
            if self.0.is_null() {
                return;
            }
            // SAFETY: `self.0` is owned by this guard after a successful CredReadW call.
            // The credential remains allocated until this guard calls CredFree in Drop.
            let credential = unsafe { &mut *self.0 };
            let size = credential.credential_blob_size as usize;
            if !credential.credential_blob.is_null() && size <= 2560 {
                // SAFETY: Windows documents CredentialBlob as a writable buffer of
                // CredentialBlobSize bytes contained in the CredReadW allocation.
                unsafe { ptr::write_bytes(credential.credential_blob, 0, size) };
            }
        }
    }

    impl Drop for CredentialGuard {
        fn drop(&mut self) {
            if self.0.is_null() {
                return;
            }
            self.zero_blob();
            // SAFETY: the pointer came from a successful CredReadW call and has not
            // been freed elsewhere. CredFree is the required matching deallocator.
            unsafe { cred_free(self.0.cast()) };
            self.0 = ptr::null_mut();
        }
    }

    pub(super) fn read_evidence_key(target: &str) -> Result<CredentialRecord, WinCredError> {
        let mut wide_target: Vec<u16> = target.encode_utf16().collect();
        wide_target.push(0);

        let mut raw_credential = ptr::null_mut();
        // SAFETY: `wide_target` is NUL-terminated and alive for the duration of the call.
        // `raw_credential` is a valid out pointer. Flags are reserved and must be zero.
        let success = unsafe {
            cred_read_w(
                wide_target.as_ptr(),
                CRED_TYPE_GENERIC,
                0,
                &mut raw_credential,
            )
        };
        if success == 0 {
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(ERROR_NOT_FOUND) => Err(WinCredError::Missing),
                _ => Err(WinCredError::Io),
            };
        }
        if raw_credential.is_null() {
            return Err(WinCredError::InvalidRecord);
        }

        let mut guard = CredentialGuard(raw_credential);
        let (version_id, blob_pointer, blob_size) = {
            // SAFETY: the pointer is non-null and owned by `guard` until this scope exits.
            let credential = unsafe { &*guard.0 };
            if credential.credential_type != CRED_TYPE_GENERIC
                || credential.persist != CRED_PERSIST_LOCAL_MACHINE
                || credential.credential_blob_size as usize != EVIDENCE_SEALING_KEY_BYTES
                || credential.credential_blob.is_null()
            {
                return Err(WinCredError::InvalidRecord);
            }
            let comment = read_wide_bounded(credential.comment, CRED_MAX_STRING_LENGTH)?;
            let version_id = comment
                .strip_prefix(VERSION_COMMENT_PREFIX)
                .filter(|value| valid_identifier(value))
                .ok_or(WinCredError::InvalidRecord)?
                .to_owned();
            (
                version_id,
                credential.credential_blob,
                credential.credential_blob_size as usize,
            )
        };

        let mut value = Zeroizing::new(vec![0_u8; blob_size]);
        // SAFETY: both source and destination are valid for exactly `blob_size` bytes,
        // do not overlap, and the source remains allocated by `guard` during the copy.
        unsafe { ptr::copy_nonoverlapping(blob_pointer, value.as_mut_ptr(), blob_size) };
        guard.zero_blob();

        Ok(CredentialRecord { version_id, value })
    }

    fn read_wide_bounded(
        pointer: *const u16,
        maximum_units: usize,
    ) -> Result<String, WinCredError> {
        if pointer.is_null() {
            return Err(WinCredError::InvalidRecord);
        }
        for length in 0..=maximum_units {
            // SAFETY: Windows supplies a NUL-terminated string pointer within the
            // CredReadW allocation. The bounded walk prevents unbounded scanning.
            let unit = unsafe { *pointer.add(length) };
            if unit == 0 {
                // SAFETY: the preceding bounded walk established `length` readable
                // UTF-16 code units before the terminator.
                let units = unsafe { slice::from_raw_parts(pointer, length) };
                return String::from_utf16(units).map_err(|_| WinCredError::InvalidRecord);
            }
        }
        Err(WinCredError::InvalidRecord)
    }
}

#[cfg(not(windows))]
mod wincred {
    use super::{CredentialRecord, WinCredError};

    pub(super) fn read_evidence_key(_: &str) -> Result<CredentialRecord, WinCredError> {
        Err(WinCredError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::{target_name, valid_identifier, valid_sha256, TARGET_PREFIX};

    #[test]
    fn target_mapping_is_exact_and_deterministic() {
        assert_eq!(
            target_name("default-store", "evidence-key-1").as_deref(),
            Some("Naveax_NXBounty_EvidenceKey::default-store::evidence-key-1")
        );
    }

    #[test]
    fn target_mapping_rejects_invalid_identifiers() {
        assert!(target_name("bad/store", "key").is_none());
        assert!(target_name("store", "bad key").is_none());
        assert!(target_name("", "key").is_none());
        assert!(target_name("store", "").is_none());
    }

    #[test]
    fn identifier_and_version_digest_validation_are_strict() {
        assert!(valid_identifier("store:key-1_test.value"));
        assert!(!valid_identifier("store/key"));
        assert!(valid_sha256(&"a".repeat(64)));
        assert!(!valid_sha256(&"A".repeat(64)));
        assert!(!valid_sha256(&"a".repeat(63)));
    }

    #[test]
    fn target_prefix_matches_pass_a_contract() {
        assert_eq!(TARGET_PREFIX, "Naveax_NXBounty_EvidenceKey::");
    }
}
