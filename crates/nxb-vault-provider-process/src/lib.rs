#![forbid(unsafe_code)]

use std::{
    fmt,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use nxb_vault::MAX_SECRET_BYTES;
use nxb_vault_provider::{
    ExternalVaultProvider, ProviderFailure, ProviderIdentity, ProviderSecretMaterial,
    ProviderSecretRequest, ProviderSessionOutcome, ProviderSessionRequest,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const PROCESS_PROVIDER_PROTOCOL_VERSION: u32 = 1;
pub const MAX_PROCESS_METADATA_BYTES: usize = 64 * 1024;
pub const MAX_PROCESS_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_PROCESS_OPERATION_SECONDS: u64 = 30;

const FRAME_MAGIC: [u8; 4] = *b"NXB1";
const FRAME_HEADER_BYTES: usize = 12;
const READER_CHANNEL_CAPACITY: usize = 1;
const PROCESS_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone)]
pub struct ProcessVaultProviderConfig {
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub expected_identity: ProviderIdentity,
    pub operation_timeout: Duration,
}

impl fmt::Debug for ProcessVaultProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessVaultProviderConfig")
            .field("executable", &"<absolute pinned executable>")
            .field("executable_sha256", &self.executable_sha256)
            .field("expected_identity", &self.expected_identity)
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProcessVaultProviderError {
    #[error("process-provider configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("provider executable path must be absolute")]
    ExecutablePathNotAbsolute,
    #[error("provider executable must not be addressed through a symbolic link")]
    ExecutableSymlinkDenied,
    #[error("provider executable is not a regular file")]
    ExecutableNotRegularFile,
    #[error("provider executable exceeds the supported size limit")]
    ExecutableTooLarge,
    #[error("provider executable SHA-256 does not match the pinned digest")]
    ExecutableDigestMismatch,
    #[error("provider process could not be spawned")]
    SpawnFailed,
    #[error("provider protocol reader thread could not be spawned")]
    ReaderSpawnFailed,
    #[error("provider process I/O failed")]
    IoFailure,
    #[error("provider process closed its protocol channel unexpectedly")]
    ProcessClosed,
    #[error("provider process exceeded the operation timeout")]
    OperationTimeout,
    #[error("provider process protocol framing or message semantics are invalid")]
    ProtocolViolation,
    #[error("provider process identity does not match the pinned identity")]
    ProviderIdentityMismatch,
    #[error("provider process is in an invalid lifecycle state")]
    InvalidState,
    #[error("provider process exited unsuccessfully")]
    ProcessExitFailure,
    #[error("provider random nonce generation failed")]
    RandomFailure,
    #[error("provider returned invalid secret material")]
    InvalidSecretMaterial,
}

impl ProcessVaultProviderError {
    fn provider_failure_code(&self) -> &'static str {
        match self {
            Self::InvalidConfiguration(_) => "process_invalid_configuration",
            Self::ExecutablePathNotAbsolute
            | Self::ExecutableSymlinkDenied
            | Self::ExecutableNotRegularFile
            | Self::ExecutableTooLarge => "process_executable_invalid",
            Self::ExecutableDigestMismatch => "process_executable_digest_mismatch",
            Self::SpawnFailed | Self::ReaderSpawnFailed | Self::IoFailure => "process_io_failure",
            Self::ProcessClosed | Self::ProcessExitFailure => "process_closed",
            Self::OperationTimeout => "process_timeout",
            Self::ProtocolViolation => "process_protocol_violation",
            Self::ProviderIdentityMismatch => "process_identity_mismatch",
            Self::InvalidState => "process_invalid_state",
            Self::RandomFailure => "process_random_failure",
            Self::InvalidSecretMaterial => "process_secret_invalid",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "message", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostMessage {
    Hello {
        protocol_version: u32,
        nonce_hex: String,
        maximum_metadata_bytes: u64,
        maximum_secret_bytes: u64,
    },
    Begin {
        sequence: u64,
        request: ProviderSessionRequest,
    },
    Fetch {
        sequence: u64,
        request: ProviderSecretRequest,
    },
    Finish {
        sequence: u64,
        outcome: ProviderSessionOutcome,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "message", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderMessage {
    Hello {
        protocol_version: u32,
        nonce_sha256: String,
        identity: ProviderIdentity,
    },
    Begun {
        sequence: u64,
    },
    Secret {
        sequence: u64,
        version_id: String,
        expires_at_epoch_seconds: i64,
        value_bytes: u64,
    },
    Finished {
        sequence: u64,
    },
    Failure {
        sequence: u64,
        code: String,
    },
}

pub mod protocol {
    use super::*;

    pub fn read_host_message<R: Read>(
        reader: &mut R,
    ) -> Result<(HostMessage, Zeroizing<Vec<u8>>), ProcessVaultProviderError> {
        read_frame(reader)
    }

    pub fn write_provider_message<W: Write>(
        writer: &mut W,
        message: &ProviderMessage,
        secret: &[u8],
    ) -> Result<(), ProcessVaultProviderError> {
        write_frame(writer, message, secret)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderState {
    Starting,
    Ready,
    Active(u64),
    TerminatedAbortable(u64),
    Finished,
    Faulted,
}

pub struct ProcessProviderSession {
    session_id: u64,
}

impl fmt::Debug for ProcessProviderSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessProviderSession")
            .field("session_id", &self.session_id)
            .finish()
    }
}

struct ReceivedFrame {
    message: ProviderMessage,
    secret: Zeroizing<Vec<u8>>,
}

pub struct ProcessVaultProvider {
    identity: ProviderIdentity,
    executable_path: PathBuf,
    executable_sha256: String,
    operation_timeout: Duration,
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    responses: Option<Receiver<Result<ReceivedFrame, ProcessVaultProviderError>>>,
    reader: Option<JoinHandle<()>>,
    next_sequence: u64,
    state: ProviderState,
}

impl fmt::Debug for ProcessVaultProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessVaultProvider")
            .field("identity", &self.identity)
            .field("executable", &"<absolute pinned executable>")
            .field("executable_sha256", &self.executable_sha256)
            .field("operation_timeout", &self.operation_timeout)
            .field("state", &self.state)
            .finish()
    }
}

impl ProcessVaultProvider {
    pub fn connect(config: ProcessVaultProviderConfig) -> Result<Self, ProcessVaultProviderError> {
        validate_config(&config)?;
        let executable_path = validate_executable_path(&config.executable)?;
        let digest_before_spawn = sha256_file(&executable_path)?;
        if digest_before_spawn != config.executable_sha256 {
            return Err(ProcessVaultProviderError::ExecutableDigestMismatch);
        }

        let mut command = Command::new(&executable_path);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear()
            .env(
                "NXB_PROVIDER_PROTOCOL_VERSION",
                PROCESS_PROVIDER_PROTOCOL_VERSION.to_string(),
            );
        if let Some(parent) = executable_path.parent() {
            command.current_dir(parent);
        }
        #[cfg(windows)]
        {
            for key in ["SystemRoot", "WINDIR"] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
        }

        let mut child = command
            .spawn()
            .map_err(|_| ProcessVaultProviderError::SpawnFailed)?;
        let stdin = child
            .stdin
            .take()
            .ok_or(ProcessVaultProviderError::SpawnFailed)?;
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ProcessVaultProviderError::SpawnFailed);
            }
        };
        let (sender, receiver) = mpsc::sync_channel(READER_CHANNEL_CAPACITY);
        let reader = match spawn_reader(stdout, sender) {
            Ok(reader) => reader,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };

        let mut provider = Self {
            identity: config.expected_identity,
            executable_path,
            executable_sha256: config.executable_sha256,
            operation_timeout: config.operation_timeout,
            child,
            stdin: Some(BufWriter::new(stdin)),
            responses: Some(receiver),
            reader: Some(reader),
            next_sequence: 1,
            state: ProviderState::Starting,
        };
        if let Err(error) = provider.perform_handshake() {
            provider.terminate_process(ProviderState::Faulted);
            return Err(error);
        }
        Ok(provider)
    }

    fn perform_handshake(&mut self) -> Result<(), ProcessVaultProviderError> {
        let mut nonce = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ProcessVaultProviderError::RandomFailure)?;
        let nonce_hex = lower_hex(&nonce);
        let expected_nonce_sha256 = sha256_hex(nonce_hex.as_bytes());
        nonce.zeroize();

        let frame = self.exchange(&HostMessage::Hello {
            protocol_version: PROCESS_PROVIDER_PROTOCOL_VERSION,
            nonce_hex,
            maximum_metadata_bytes: MAX_PROCESS_METADATA_BYTES as u64,
            maximum_secret_bytes: MAX_SECRET_BYTES as u64,
        })?;
        if !frame.secret.is_empty() {
            return Err(ProcessVaultProviderError::ProtocolViolation);
        }
        match frame.message {
            ProviderMessage::Hello {
                protocol_version,
                nonce_sha256,
                identity,
            } => {
                if protocol_version != PROCESS_PROVIDER_PROTOCOL_VERSION
                    || nonce_sha256 != expected_nonce_sha256
                {
                    return Err(ProcessVaultProviderError::ProtocolViolation);
                }
                identity
                    .validate()
                    .map_err(|_| ProcessVaultProviderError::ProtocolViolation)?;
                if identity != self.identity {
                    return Err(ProcessVaultProviderError::ProviderIdentityMismatch);
                }
            }
            _ => return Err(ProcessVaultProviderError::ProtocolViolation),
        }
        let digest_after_spawn = sha256_file(&self.executable_path)?;
        if digest_after_spawn != self.executable_sha256 {
            return Err(ProcessVaultProviderError::ExecutableDigestMismatch);
        }
        self.state = ProviderState::Ready;
        Ok(())
    }

    fn exchange(
        &mut self,
        message: &HostMessage,
    ) -> Result<ReceivedFrame, ProcessVaultProviderError> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or(ProcessVaultProviderError::ProcessClosed)?;
        write_frame(stdin, message, &[])?;
        let responses = self
            .responses
            .as_ref()
            .ok_or(ProcessVaultProviderError::ProcessClosed)?;
        match responses.recv_timeout(self.operation_timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(ProcessVaultProviderError::OperationTimeout),
            Err(RecvTimeoutError::Disconnected) => Err(ProcessVaultProviderError::ProcessClosed),
        }
    }

    fn allocate_sequence(&mut self) -> Result<u64, ProcessVaultProviderError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ProcessVaultProviderError::InvalidState)?;
        Ok(sequence)
    }

    fn fatal_failure(
        &mut self,
        error: ProcessVaultProviderError,
        abortable_session: Option<u64>,
    ) -> ProviderFailure {
        let state = abortable_session
            .map(ProviderState::TerminatedAbortable)
            .unwrap_or(ProviderState::Faulted);
        self.terminate_process(state);
        ProviderFailure::new(error.provider_failure_code())
            .expect("internal process-provider failure codes are valid")
    }

    fn child_failure(
        &mut self,
        mut code: String,
        abortable_session: Option<u64>,
        keep_process_for_abort: bool,
    ) -> ProviderFailure {
        if !valid_failure_code(&code) {
            code.zeroize();
            return self.fatal_failure(
                ProcessVaultProviderError::ProtocolViolation,
                abortable_session,
            );
        }
        let failure = ProviderFailure::new(code)
            .expect("strictly validated child failure code must satisfy provider contract");
        if !keep_process_for_abort {
            let state = abortable_session
                .map(ProviderState::TerminatedAbortable)
                .unwrap_or(ProviderState::Faulted);
            self.terminate_process(state);
        }
        failure
    }

    fn terminate_process(&mut self, terminal_state: ProviderState) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.responses.take();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.state = terminal_state;
    }

    fn graceful_shutdown(&mut self) -> Result<ExitStatus, ProcessVaultProviderError> {
        self.stdin.take();
        let deadline = Instant::now() + self.operation_timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.responses.take();
                    if let Some(reader) = self.reader.take() {
                        let _ = reader.join();
                    }
                    if !status.success() {
                        self.state = ProviderState::Faulted;
                        return Err(ProcessVaultProviderError::ProcessExitFailure);
                    }
                    self.state = ProviderState::Finished;
                    return Ok(status);
                }
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(PROCESS_EXIT_POLL_INTERVAL);
                }
                Ok(None) => {
                    self.terminate_process(ProviderState::Faulted);
                    return Err(ProcessVaultProviderError::OperationTimeout);
                }
                Err(_) => {
                    self.terminate_process(ProviderState::Faulted);
                    return Err(ProcessVaultProviderError::IoFailure);
                }
            }
        }
    }
}

impl ExternalVaultProvider for ProcessVaultProvider {
    type Session = ProcessProviderSession;

    fn identity(&self) -> ProviderIdentity {
        self.identity.clone()
    }

    fn begin(
        &mut self,
        request: &ProviderSessionRequest,
    ) -> Result<Self::Session, ProviderFailure> {
        if self.state != ProviderState::Ready {
            return Err(self.fatal_failure(ProcessVaultProviderError::InvalidState, None));
        }
        let sequence = match self.allocate_sequence() {
            Ok(sequence) => sequence,
            Err(error) => return Err(self.fatal_failure(error, None)),
        };
        let frame = match self.exchange(&HostMessage::Begin {
            sequence,
            request: request.clone(),
        }) {
            Ok(frame) => frame,
            Err(error) => return Err(self.fatal_failure(error, None)),
        };
        if !frame.secret.is_empty() {
            return Err(self.fatal_failure(ProcessVaultProviderError::ProtocolViolation, None));
        }
        match frame.message {
            ProviderMessage::Begun {
                sequence: response_sequence,
            } if response_sequence == sequence => {
                self.state = ProviderState::Active(sequence);
                Ok(ProcessProviderSession {
                    session_id: sequence,
                })
            }
            ProviderMessage::Failure {
                sequence: response_sequence,
                code,
            } if response_sequence == sequence => Err(self.child_failure(code, None, false)),
            _ => Err(self.fatal_failure(ProcessVaultProviderError::ProtocolViolation, None)),
        }
    }

    fn fetch(
        &mut self,
        session: &mut Self::Session,
        request: &ProviderSecretRequest,
    ) -> Result<ProviderSecretMaterial, ProviderFailure> {
        if self.state != ProviderState::Active(session.session_id) {
            return Err(self.fatal_failure(
                ProcessVaultProviderError::InvalidState,
                Some(session.session_id),
            ));
        }
        let sequence = match self.allocate_sequence() {
            Ok(sequence) => sequence,
            Err(error) => {
                return Err(self.fatal_failure(error, Some(session.session_id)));
            }
        };
        let mut frame = match self.exchange(&HostMessage::Fetch {
            sequence,
            request: request.clone(),
        }) {
            Ok(frame) => frame,
            Err(error) => {
                return Err(self.fatal_failure(error, Some(session.session_id)));
            }
        };
        match frame.message {
            ProviderMessage::Secret {
                sequence: response_sequence,
                version_id,
                expires_at_epoch_seconds,
                value_bytes,
            } if response_sequence == sequence => {
                if value_bytes != frame.secret.len() as u64
                    || frame.secret.is_empty()
                    || value_bytes > request.maximum_value_bytes
                    || frame.secret.len() > MAX_SECRET_BYTES
                {
                    return Err(self.fatal_failure(
                        ProcessVaultProviderError::ProtocolViolation,
                        Some(session.session_id),
                    ));
                }
                let value = std::mem::take(&mut *frame.secret);
                match ProviderSecretMaterial::new(version_id, value, expires_at_epoch_seconds) {
                    Ok(material) => Ok(material),
                    Err(_) => Err(self.fatal_failure(
                        ProcessVaultProviderError::InvalidSecretMaterial,
                        Some(session.session_id),
                    )),
                }
            }
            ProviderMessage::Failure {
                sequence: response_sequence,
                code,
            } if response_sequence == sequence && frame.secret.is_empty() => {
                Err(self.child_failure(code, Some(session.session_id), true))
            }
            _ => Err(self.fatal_failure(
                ProcessVaultProviderError::ProtocolViolation,
                Some(session.session_id),
            )),
        }
    }

    fn finish(
        &mut self,
        session: Self::Session,
        outcome: ProviderSessionOutcome,
    ) -> Result<(), ProviderFailure> {
        if self.state == ProviderState::TerminatedAbortable(session.session_id)
            && outcome == ProviderSessionOutcome::Aborted
        {
            self.state = ProviderState::Finished;
            return Ok(());
        }
        if self.state != ProviderState::Active(session.session_id) {
            return Err(self.fatal_failure(ProcessVaultProviderError::InvalidState, None));
        }
        let sequence = match self.allocate_sequence() {
            Ok(sequence) => sequence,
            Err(error) => return Err(self.fatal_failure(error, None)),
        };
        let frame = match self.exchange(&HostMessage::Finish { sequence, outcome }) {
            Ok(frame) => frame,
            Err(error) => return Err(self.fatal_failure(error, None)),
        };
        if !frame.secret.is_empty() {
            return Err(self.fatal_failure(ProcessVaultProviderError::ProtocolViolation, None));
        }
        match frame.message {
            ProviderMessage::Finished {
                sequence: response_sequence,
            } if response_sequence == sequence => self
                .graceful_shutdown()
                .map(|_| ())
                .map_err(|error| self.fatal_failure(error, None)),
            ProviderMessage::Failure {
                sequence: response_sequence,
                code,
            } if response_sequence == sequence => Err(self.child_failure(code, None, false)),
            _ => Err(self.fatal_failure(ProcessVaultProviderError::ProtocolViolation, None)),
        }
    }
}

impl Drop for ProcessVaultProvider {
    fn drop(&mut self) {
        if self.state != ProviderState::Finished {
            self.terminate_process(ProviderState::Faulted);
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

pub fn sha256_file(path: &Path) -> Result<String, ProcessVaultProviderError> {
    let metadata = fs::metadata(path).map_err(|_| ProcessVaultProviderError::IoFailure)?;
    if !metadata.is_file() {
        return Err(ProcessVaultProviderError::ExecutableNotRegularFile);
    }
    if metadata.len() == 0 || metadata.len() > MAX_PROCESS_EXECUTABLE_BYTES {
        return Err(ProcessVaultProviderError::ExecutableTooLarge);
    }
    let mut file = File::open(path).map_err(|_| ProcessVaultProviderError::IoFailure)?;
    let mut digest = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0_u8; 64 * 1024]);
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| ProcessVaultProviderError::IoFailure)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(lower_hex(&digest.finalize()))
}

fn validate_config(config: &ProcessVaultProviderConfig) -> Result<(), ProcessVaultProviderError> {
    if !valid_sha256(&config.executable_sha256) {
        return Err(ProcessVaultProviderError::InvalidConfiguration(
            "executable_sha256",
        ));
    }
    config
        .expected_identity
        .validate()
        .map_err(|_| ProcessVaultProviderError::InvalidConfiguration("expected_identity"))?;
    if config.expected_identity.provider_instance_sha256 != config.executable_sha256 {
        return Err(ProcessVaultProviderError::InvalidConfiguration(
            "provider_instance_sha256",
        ));
    }
    if config.operation_timeout.is_zero()
        || config.operation_timeout > Duration::from_secs(MAX_PROCESS_OPERATION_SECONDS)
    {
        return Err(ProcessVaultProviderError::InvalidConfiguration(
            "operation_timeout",
        ));
    }
    Ok(())
}

fn validate_executable_path(path: &Path) -> Result<PathBuf, ProcessVaultProviderError> {
    if !path.is_absolute() {
        return Err(ProcessVaultProviderError::ExecutablePathNotAbsolute);
    }
    let link_metadata = fs::symlink_metadata(path)
        .map_err(|_| ProcessVaultProviderError::ExecutableNotRegularFile)?;
    if link_metadata.file_type().is_symlink() {
        return Err(ProcessVaultProviderError::ExecutableSymlinkDenied);
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| ProcessVaultProviderError::ExecutableNotRegularFile)?;
    let metadata = fs::metadata(&canonical)
        .map_err(|_| ProcessVaultProviderError::ExecutableNotRegularFile)?;
    if !metadata.is_file() {
        return Err(ProcessVaultProviderError::ExecutableNotRegularFile);
    }
    if metadata.len() == 0 || metadata.len() > MAX_PROCESS_EXECUTABLE_BYTES {
        return Err(ProcessVaultProviderError::ExecutableTooLarge);
    }
    Ok(canonical)
}

fn spawn_reader(
    stdout: ChildStdout,
    sender: SyncSender<Result<ReceivedFrame, ProcessVaultProviderError>>,
) -> Result<JoinHandle<()>, ProcessVaultProviderError> {
    thread::Builder::new()
        .name("nxb-vault-provider-reader".into())
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let result = read_frame::<ProviderMessage, _>(&mut reader)
                    .map(|(message, secret)| ReceivedFrame { message, secret });
                let terminal = result.is_err();
                if sender.send(result).is_err() || terminal {
                    break;
                }
            }
        })
        .map_err(|_| ProcessVaultProviderError::ReaderSpawnFailed)
}

fn write_frame<T: Serialize, W: Write>(
    writer: &mut W,
    message: &T,
    secret: &[u8],
) -> Result<(), ProcessVaultProviderError> {
    let metadata = Zeroizing::new(
        serde_json::to_vec(message).map_err(|_| ProcessVaultProviderError::ProtocolViolation)?,
    );
    if metadata.is_empty()
        || metadata.len() > MAX_PROCESS_METADATA_BYTES
        || secret.len() > MAX_SECRET_BYTES
    {
        return Err(ProcessVaultProviderError::ProtocolViolation);
    }
    let metadata_len =
        u32::try_from(metadata.len()).map_err(|_| ProcessVaultProviderError::ProtocolViolation)?;
    let secret_len =
        u32::try_from(secret.len()).map_err(|_| ProcessVaultProviderError::ProtocolViolation)?;
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    header[..4].copy_from_slice(&FRAME_MAGIC);
    header[4..8].copy_from_slice(&metadata_len.to_be_bytes());
    header[8..12].copy_from_slice(&secret_len.to_be_bytes());
    writer
        .write_all(&header)
        .and_then(|_| writer.write_all(&metadata))
        .and_then(|_| writer.write_all(secret))
        .and_then(|_| writer.flush())
        .map_err(|_| ProcessVaultProviderError::IoFailure)
}

fn read_frame<T: DeserializeOwned, R: Read>(
    reader: &mut R,
) -> Result<(T, Zeroizing<Vec<u8>>), ProcessVaultProviderError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(ProcessVaultProviderError::ProcessClosed);
        }
        Err(_) => return Err(ProcessVaultProviderError::IoFailure),
    }
    if header[..4] != FRAME_MAGIC {
        return Err(ProcessVaultProviderError::ProtocolViolation);
    }
    let metadata_len = u32::from_be_bytes(header[4..8].try_into().expect("fixed slice")) as usize;
    let secret_len = u32::from_be_bytes(header[8..12].try_into().expect("fixed slice")) as usize;
    if metadata_len == 0
        || metadata_len > MAX_PROCESS_METADATA_BYTES
        || secret_len > MAX_SECRET_BYTES
    {
        return Err(ProcessVaultProviderError::ProtocolViolation);
    }
    let mut metadata = Zeroizing::new(vec![0_u8; metadata_len]);
    reader
        .read_exact(&mut metadata)
        .map_err(|_| ProcessVaultProviderError::IoFailure)?;
    let mut secret = Zeroizing::new(vec![0_u8; secret_len]);
    reader
        .read_exact(&mut secret)
        .map_err(|_| ProcessVaultProviderError::IoFailure)?;
    let message = serde_json::from_slice(&metadata)
        .map_err(|_| ProcessVaultProviderError::ProtocolViolation)?;
    Ok((message, secret))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_failure_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
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

#[cfg(feature = "fixture")]
pub mod fixture {
    use super::*;

    const FIXTURE_PROVIDER_ID: &str = "fixture-provider";
    const FIXTURE_CAPABILITY: &[u8] = b"nxb140-read-only-process-fixture";
    const FIXTURE_VERSION_ID: &str = "fixture-version-1";
    const FIXTURE_SECRET: &[u8] = b"nxb140-test-secret";

    pub fn expected_capability_sha256() -> String {
        sha256_hex(FIXTURE_CAPABILITY)
    }

    pub fn run() -> Result<(), ProcessVaultProviderError> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut reader = stdin.lock();
        let mut writer = BufWriter::new(stdout.lock());

        let (hello, secret) = read_frame::<HostMessage, _>(&mut reader)?;
        if !secret.is_empty() {
            return Err(ProcessVaultProviderError::ProtocolViolation);
        }
        let nonce_hex = match hello {
            HostMessage::Hello {
                protocol_version,
                nonce_hex,
                maximum_metadata_bytes,
                maximum_secret_bytes,
            } if protocol_version == PROCESS_PROVIDER_PROTOCOL_VERSION
                && maximum_metadata_bytes == MAX_PROCESS_METADATA_BYTES as u64
                && maximum_secret_bytes == MAX_SECRET_BYTES as u64 =>
            {
                nonce_hex
            }
            _ => return Err(ProcessVaultProviderError::ProtocolViolation),
        };
        let executable = std::env::current_exe()
            .map_err(|_| ProcessVaultProviderError::ExecutableNotRegularFile)?;
        let identity = ProviderIdentity {
            provider_id: FIXTURE_PROVIDER_ID.into(),
            provider_instance_sha256: sha256_file(&executable)?,
            capability_sha256: expected_capability_sha256(),
        };
        write_frame(
            &mut writer,
            &ProviderMessage::Hello {
                protocol_version: PROCESS_PROVIDER_PROTOCOL_VERSION,
                nonce_sha256: sha256_hex(nonce_hex.as_bytes()),
                identity,
            },
            &[],
        )?;

        let mut active = false;
        loop {
            let (message, secret) = read_frame::<HostMessage, _>(&mut reader)?;
            if !secret.is_empty() {
                return Err(ProcessVaultProviderError::ProtocolViolation);
            }
            match message {
                HostMessage::Begin { sequence, .. } if !active => {
                    active = true;
                    write_frame(&mut writer, &ProviderMessage::Begun { sequence }, &[])?;
                }
                HostMessage::Fetch { sequence, request } if active => {
                    match request.provider_handle.as_str() {
                        "fixture/bearer" => {
                            if request.maximum_value_bytes < FIXTURE_SECRET.len() as u64 {
                                write_frame(
                                    &mut writer,
                                    &ProviderMessage::Failure {
                                        sequence,
                                        code: "secret_too_large".into(),
                                    },
                                    &[],
                                )?;
                                continue;
                            }
                            let secret = Zeroizing::new(FIXTURE_SECRET.to_vec());
                            write_frame(
                                &mut writer,
                                &ProviderMessage::Secret {
                                    sequence,
                                    version_id: FIXTURE_VERSION_ID.into(),
                                    expires_at_epoch_seconds: 2_100_000_000,
                                    value_bytes: secret.len() as u64,
                                },
                                &secret,
                            )?;
                        }
                        "fixture/stall" => {
                            thread::sleep(Duration::from_secs(15));
                            write_frame(
                                &mut writer,
                                &ProviderMessage::Failure {
                                    sequence,
                                    code: "stall_complete".into(),
                                },
                                &[],
                            )?;
                        }
                        "fixture/failure" => {
                            write_frame(
                                &mut writer,
                                &ProviderMessage::Failure {
                                    sequence,
                                    code: "fixture_fetch_denied".into(),
                                },
                                &[],
                            )?;
                        }
                        _ => {
                            write_frame(
                                &mut writer,
                                &ProviderMessage::Failure {
                                    sequence,
                                    code: "fixture_secret_missing".into(),
                                },
                                &[],
                            )?;
                        }
                    }
                }
                HostMessage::Finish { sequence, .. } if active => {
                    write_frame(&mut writer, &ProviderMessage::Finished { sequence }, &[])?;
                    return Ok(());
                }
                _ => return Err(ProcessVaultProviderError::ProtocolViolation),
            }
        }
    }
}
