use std::io::{self, Write};

use serde::Serialize;
use zeroize::Zeroizing;

use super::{target_name, EVIDENCE_SEALING_KEY_BYTES};

const VERSION_RANDOM_BYTES: usize = 16;
const VERSION_ID_PREFIX: &str = "v1-";
const CRED_PERSISTENCE_NAME: &str = "local_machine";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Create,
    Rotate,
    Delete,
    Status,
}

impl Operation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Rotate => "rotate",
            Self::Delete => "delete",
            Self::Status => "status",
        }
    }

    fn mutates(self) -> bool {
        !matches!(self, Self::Status)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Command {
    operation: Operation,
    target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialMetadata {
    version_id: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeError {
    UnsupportedPlatform,
    Missing,
    InvalidRecord,
    Io,
    Random,
}

#[derive(Serialize)]
struct LifecycleOutput<'a> {
    operation: &'a str,
    target: &'a str,
    present: bool,
    version_id: Option<&'a str>,
    key_bytes: Option<usize>,
    persistence: Option<&'static str>,
}

pub(super) fn run() -> Result<(), &'static str> {
    let arguments = std::env::args_os()
        .skip(1)
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "windows_credential_cli_invalid")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let command = parse_command(&arguments)?;
    execute(command)
}

fn parse_command(arguments: &[String]) -> Result<Command, &'static str> {
    let operation = match arguments.first().map(String::as_str) {
        Some("create") => Operation::Create,
        Some("rotate") => Operation::Rotate,
        Some("delete") => Operation::Delete,
        Some("status") => Operation::Status,
        _ => return Err("windows_credential_cli_invalid"),
    };

    let expected_argument_count = if operation.mutates() { 7 } else { 5 };
    if arguments.len() != expected_argument_count
        || arguments.get(1).map(String::as_str) != Some("--store-id")
        || arguments.get(3).map(String::as_str) != Some("--key-id")
    {
        return Err("windows_credential_cli_invalid");
    }

    let target =
        target_name(&arguments[2], &arguments[4]).ok_or("windows_credential_cli_invalid")?;

    if operation.mutates()
        && (arguments.get(5).map(String::as_str) != Some("--confirm-target")
            || arguments.get(6).map(String::as_str) != Some(target.as_str()))
    {
        return Err("windows_credential_confirmation_required");
    }

    Ok(Command { operation, target })
}

fn execute(command: Command) -> Result<(), &'static str> {
    match command.operation {
        Operation::Create => create(&command),
        Operation::Rotate => rotate(&command),
        Operation::Delete => delete(&command),
        Operation::Status => status(&command),
    }
}

fn create(command: &Command) -> Result<(), &'static str> {
    match native::read_metadata(&command.target) {
        Ok(_) => return Err("windows_credential_already_exists"),
        Err(NativeError::Missing) => {}
        Err(error) => return Err(native_error_code(error)),
    }

    let (version_id, key) = new_material()?;
    native::write_evidence_key(&command.target, &version_id, &key).map_err(native_error_code)?;
    drop(key);

    let stored = native::read_metadata(&command.target).map_err(native_error_code)?;
    if stored.version_id != version_id {
        return Err("windows_credential_post_write_verify_failed");
    }

    emit(LifecycleOutput {
        operation: command.operation.as_str(),
        target: &command.target,
        present: true,
        version_id: Some(&version_id),
        key_bytes: Some(EVIDENCE_SEALING_KEY_BYTES),
        persistence: Some(CRED_PERSISTENCE_NAME),
    })
}

fn rotate(command: &Command) -> Result<(), &'static str> {
    native::read_metadata(&command.target).map_err(native_error_code)?;

    let (version_id, key) = new_material()?;
    native::write_evidence_key(&command.target, &version_id, &key).map_err(native_error_code)?;
    drop(key);

    let stored = native::read_metadata(&command.target).map_err(native_error_code)?;
    if stored.version_id != version_id {
        return Err("windows_credential_post_write_verify_failed");
    }

    emit(LifecycleOutput {
        operation: command.operation.as_str(),
        target: &command.target,
        present: true,
        version_id: Some(&version_id),
        key_bytes: Some(EVIDENCE_SEALING_KEY_BYTES),
        persistence: Some(CRED_PERSISTENCE_NAME),
    })
}

fn delete(command: &Command) -> Result<(), &'static str> {
    native::read_metadata(&command.target).map_err(native_error_code)?;
    native::delete_evidence_key(&command.target).map_err(native_error_code)?;
    match native::read_metadata(&command.target) {
        Err(NativeError::Missing) => {}
        Ok(_) => return Err("windows_credential_post_delete_verify_failed"),
        Err(error) => return Err(native_error_code(error)),
    }

    emit(LifecycleOutput {
        operation: command.operation.as_str(),
        target: &command.target,
        present: false,
        version_id: None,
        key_bytes: None,
        persistence: None,
    })
}

fn status(command: &Command) -> Result<(), &'static str> {
    match native::read_metadata(&command.target) {
        Ok(metadata) => emit(LifecycleOutput {
            operation: command.operation.as_str(),
            target: &command.target,
            present: true,
            version_id: Some(&metadata.version_id),
            key_bytes: Some(EVIDENCE_SEALING_KEY_BYTES),
            persistence: Some(CRED_PERSISTENCE_NAME),
        }),
        Err(NativeError::Missing) => emit(LifecycleOutput {
            operation: command.operation.as_str(),
            target: &command.target,
            present: false,
            version_id: None,
            key_bytes: None,
            persistence: None,
        }),
        Err(error) => Err(native_error_code(error)),
    }
}

fn new_material() -> Result<(String, Zeroizing<Vec<u8>>), &'static str> {
    let mut version_random = Zeroizing::new(vec![0_u8; VERSION_RANDOM_BYTES]);
    native::fill_random(&mut version_random).map_err(native_error_code)?;
    let version_id = format!("{VERSION_ID_PREFIX}{}", lower_hex(&version_random));

    let mut key = Zeroizing::new(vec![0_u8; EVIDENCE_SEALING_KEY_BYTES]);
    native::fill_random(&mut key).map_err(native_error_code)?;
    Ok((version_id, key))
}

fn emit(output: LifecycleOutput<'_>) -> Result<(), &'static str> {
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());
    serde_json::to_writer(&mut writer, &output).map_err(|_| "windows_credential_output_failure")?;
    writer
        .write_all(b"\n")
        .and_then(|_| writer.flush())
        .map_err(|_| "windows_credential_output_failure")
}

fn native_error_code(error: NativeError) -> &'static str {
    match error {
        NativeError::UnsupportedPlatform => "windows_credential_unsupported_platform",
        NativeError::Missing => "windows_credential_missing",
        NativeError::InvalidRecord => "windows_credential_metadata_invalid",
        NativeError::Io => "windows_credential_io_failure",
        NativeError::Random => "windows_credential_random_failure",
    }
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

#[cfg(windows)]
mod native {
    use std::{ffi::c_void, ptr, slice};

    use super::super::VERSION_COMMENT_PREFIX;
    use super::{CredentialMetadata, NativeError, EVIDENCE_SEALING_KEY_BYTES};

    const CRED_TYPE_GENERIC: u32 = 1;
    const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;
    const CRED_MAX_STRING_LENGTH: usize = 256;
    const CRED_MAX_CREDENTIAL_BLOB_SIZE: usize = 2560;
    const ERROR_NOT_FOUND: i32 = 1168;
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

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

        #[link_name = "CredWriteW"]
        fn cred_write_w(credential: *const CredentialW, flags: u32) -> i32;

        #[link_name = "CredDeleteW"]
        fn cred_delete_w(target_name: *const u16, credential_type: u32, flags: u32) -> i32;

        #[link_name = "CredFree"]
        fn cred_free(buffer: *mut c_void);
    }

    #[link(name = "Bcrypt")]
    unsafe extern "system" {
        #[link_name = "BCryptGenRandom"]
        fn bcrypt_gen_random(
            algorithm: *mut c_void,
            buffer: *mut u8,
            buffer_bytes: u32,
            flags: u32,
        ) -> i32;
    }

    struct CredentialGuard(*mut CredentialW);

    impl CredentialGuard {
        fn zero_blob(&mut self) {
            if self.0.is_null() {
                return;
            }
            // SAFETY: self.0 is owned by this guard after a successful CredReadW call
            // and remains allocated until CredFree runs in Drop.
            let credential = unsafe { &mut *self.0 };
            let size = credential.credential_blob_size as usize;
            if !credential.credential_blob.is_null() && size <= CRED_MAX_CREDENTIAL_BLOB_SIZE {
                // SAFETY: CredentialBlob points to CredentialBlobSize writable bytes
                // inside the CredReadW allocation while this guard is alive.
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
            // SAFETY: this pointer came from CredReadW and has not been freed elsewhere.
            unsafe { cred_free(self.0.cast()) };
            self.0 = ptr::null_mut();
        }
    }

    pub(super) fn read_metadata(target: &str) -> Result<CredentialMetadata, NativeError> {
        let mut guard = read_guard(target)?;
        let metadata = metadata_from_guard(&guard)?;
        guard.zero_blob();
        Ok(metadata)
    }

    pub(super) fn write_evidence_key(
        target: &str,
        version_id: &str,
        key: &[u8],
    ) -> Result<(), NativeError> {
        if key.len() != EVIDENCE_SEALING_KEY_BYTES {
            return Err(NativeError::InvalidRecord);
        }

        let comment = format!("{VERSION_COMMENT_PREFIX}{version_id}");
        if comment.encode_utf16().count() > CRED_MAX_STRING_LENGTH {
            return Err(NativeError::InvalidRecord);
        }

        let mut wide_target = wide_nul(target);
        let mut wide_comment = wide_nul(&comment);
        let blob_size = u32::try_from(key.len()).map_err(|_| NativeError::InvalidRecord)?;
        let credential = CredentialW {
            _flags: 0,
            credential_type: CRED_TYPE_GENERIC,
            _target_name: wide_target.as_mut_ptr(),
            comment: wide_comment.as_mut_ptr(),
            _last_written: FileTime {
                _low_date_time: 0,
                _high_date_time: 0,
            },
            credential_blob_size: blob_size,
            credential_blob: key.as_ptr().cast_mut(),
            persist: CRED_PERSIST_LOCAL_MACHINE,
            _attribute_count: 0,
            _attributes: ptr::null_mut(),
            _target_alias: ptr::null_mut(),
            _user_name: ptr::null_mut(),
        };

        // SAFETY: all pointers in CredentialW reference live, NUL-terminated metadata
        // buffers or the exact 32-byte key slice for the duration of this synchronous call.
        let success = unsafe { cred_write_w(&credential, 0) };
        if success == 0 {
            return Err(NativeError::Io);
        }
        Ok(())
    }

    pub(super) fn delete_evidence_key(target: &str) -> Result<(), NativeError> {
        let wide_target = wide_nul(target);
        // SAFETY: wide_target is NUL-terminated and alive for the duration of the call.
        let success = unsafe { cred_delete_w(wide_target.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if success == 0 {
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(ERROR_NOT_FOUND) => Err(NativeError::Missing),
                _ => Err(NativeError::Io),
            };
        }
        Ok(())
    }

    pub(super) fn fill_random(buffer: &mut [u8]) -> Result<(), NativeError> {
        let buffer_bytes = u32::try_from(buffer.len()).map_err(|_| NativeError::Random)?;
        // SAFETY: null algorithm is required with BCRYPT_USE_SYSTEM_PREFERRED_RNG;
        // buffer is valid and writable for exactly buffer_bytes bytes.
        let status = unsafe {
            bcrypt_gen_random(
                ptr::null_mut(),
                buffer.as_mut_ptr(),
                buffer_bytes,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(NativeError::Random);
        }
        Ok(())
    }

    fn read_guard(target: &str) -> Result<CredentialGuard, NativeError> {
        let wide_target = wide_nul(target);
        let mut raw_credential = ptr::null_mut();
        // SAFETY: wide_target is NUL-terminated and raw_credential is a valid out pointer.
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
                Some(ERROR_NOT_FOUND) => Err(NativeError::Missing),
                _ => Err(NativeError::Io),
            };
        }
        if raw_credential.is_null() {
            return Err(NativeError::InvalidRecord);
        }
        Ok(CredentialGuard(raw_credential))
    }

    fn metadata_from_guard(guard: &CredentialGuard) -> Result<CredentialMetadata, NativeError> {
        // SAFETY: guard owns a non-null CredReadW allocation for this call.
        let credential = unsafe { &*guard.0 };
        if credential.credential_type != CRED_TYPE_GENERIC
            || credential.persist != CRED_PERSIST_LOCAL_MACHINE
            || credential.credential_blob_size as usize != EVIDENCE_SEALING_KEY_BYTES
            || credential.credential_blob.is_null()
        {
            return Err(NativeError::InvalidRecord);
        }

        let comment = read_wide_bounded(credential.comment, CRED_MAX_STRING_LENGTH)?;
        let version_id = comment
            .strip_prefix(VERSION_COMMENT_PREFIX)
            .filter(|value| valid_version_id(value))
            .ok_or(NativeError::InvalidRecord)?
            .to_owned();
        Ok(CredentialMetadata { version_id })
    }

    fn valid_version_id(value: &str) -> bool {
        value.len() == 35
            && value.starts_with("v1-")
            && value[3..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn read_wide_bounded(pointer: *const u16, maximum_units: usize) -> Result<String, NativeError> {
        if pointer.is_null() {
            return Err(NativeError::InvalidRecord);
        }
        for length in 0..=maximum_units {
            // SAFETY: Windows supplies a NUL-terminated string pointer inside the
            // CredReadW allocation; the walk is bounded to the documented maximum.
            let unit = unsafe { *pointer.add(length) };
            if unit == 0 {
                // SAFETY: the bounded walk established length readable UTF-16 units.
                let units = unsafe { slice::from_raw_parts(pointer, length) };
                return String::from_utf16(units).map_err(|_| NativeError::InvalidRecord);
            }
        }
        Err(NativeError::InvalidRecord)
    }

    fn wide_nul(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod native {
    use super::{CredentialMetadata, NativeError};

    pub(super) fn read_metadata(_: &str) -> Result<CredentialMetadata, NativeError> {
        Err(NativeError::UnsupportedPlatform)
    }

    pub(super) fn write_evidence_key(_: &str, _: &str, _: &[u8]) -> Result<(), NativeError> {
        Err(NativeError::UnsupportedPlatform)
    }

    pub(super) fn delete_evidence_key(_: &str) -> Result<(), NativeError> {
        Err(NativeError::UnsupportedPlatform)
    }

    pub(super) fn fill_random(_: &mut [u8]) -> Result<(), NativeError> {
        Err(NativeError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_command, Command, Operation};

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn status_requires_only_exact_store_and_key_arguments() {
        let command = parse_command(&strings(&[
            "status",
            "--store-id",
            "store-a",
            "--key-id",
            "key-a",
        ]))
        .expect("status arguments should parse");
        assert_eq!(
            command,
            Command {
                operation: Operation::Status,
                target: "Naveax_BoundSeal_EvidenceKey::store-a::key-a".into(),
            }
        );
    }

    #[test]
    fn create_requires_confirmation_bound_to_exact_target() {
        let target = "Naveax_BoundSeal_EvidenceKey::store-a::key-a";
        assert!(parse_command(&strings(&[
            "create",
            "--store-id",
            "store-a",
            "--key-id",
            "key-a",
            "--confirm-target",
            target,
        ]))
        .is_ok());
        assert_eq!(
            parse_command(&strings(&[
                "create",
                "--store-id",
                "store-a",
                "--key-id",
                "key-a",
                "--confirm-target",
                "yes",
            ])),
            Err("windows_credential_confirmation_required")
        );
    }

    #[test]
    fn mutating_commands_reject_missing_confirmation() {
        for operation in ["create", "rotate", "delete"] {
            assert!(parse_command(&strings(&[
                operation,
                "--store-id",
                "store-a",
                "--key-id",
                "key-a",
            ]))
            .is_err());
        }
    }

    #[test]
    fn argument_order_is_fail_closed() {
        assert_eq!(
            parse_command(&strings(&[
                "status",
                "--key-id",
                "key-a",
                "--store-id",
                "store-a",
            ])),
            Err("windows_credential_cli_invalid")
        );
    }
}
