#![forbid(unsafe_code)]

use std::{
    io::{self, BufWriter},
    thread,
    time::Duration,
};

use nxb_vault::MAX_SECRET_BYTES;
use nxb_vault_provider::ProviderIdentity;
use nxb_vault_provider_process::{
    protocol::{read_host_message, write_provider_message},
    sha256_file, sha256_hex, HostMessage, ProviderMessage, MAX_PROCESS_METADATA_BYTES,
    PROCESS_PROVIDER_PROTOCOL_VERSION,
};
use zeroize::Zeroizing;

const FIXTURE_PROVIDER_ID: &str = "fixture-evidence-key-provider";
const FIXTURE_CAPABILITY: &[u8] = b"nxb150-pinned-process-evidence-key-fixture";
const FIXTURE_VERSION_ID: &str = "fixture-evidence-key-version-1";
const FIXTURE_KEY_BYTES: usize = 32;

fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}

fn run() -> Result<(), nxb_vault_provider_process::ProcessVaultProviderError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = BufWriter::new(stdout.lock());

    let (hello, secret) = read_host_message(&mut reader)?;
    if !secret.is_empty() {
        return Err(nxb_vault_provider_process::ProcessVaultProviderError::ProtocolViolation);
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
        _ => return Err(nxb_vault_provider_process::ProcessVaultProviderError::ProtocolViolation),
    };
    let executable = std::env::current_exe().map_err(|_| {
        nxb_vault_provider_process::ProcessVaultProviderError::ExecutableNotRegularFile
    })?;
    let identity = ProviderIdentity {
        provider_id: FIXTURE_PROVIDER_ID.into(),
        provider_instance_sha256: sha256_file(&executable)?,
        capability_sha256: sha256_hex(FIXTURE_CAPABILITY),
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

    let mut active = false;
    loop {
        let (message, secret) = read_host_message(&mut reader)?;
        if !secret.is_empty() {
            return Err(nxb_vault_provider_process::ProcessVaultProviderError::ProtocolViolation);
        }
        match message {
            HostMessage::Begin { sequence, .. } if !active => {
                active = true;
                write_provider_message(&mut writer, &ProviderMessage::Begun { sequence }, &[])?;
            }
            HostMessage::Fetch { sequence, request } if active => {
                match request.provider_handle.as_str() {
                    "fixture/evidence-key" => {
                        let key = Zeroizing::new(vec![0x5a_u8; FIXTURE_KEY_BYTES]);
                        write_provider_message(
                            &mut writer,
                            &ProviderMessage::Secret {
                                sequence,
                                version_id: FIXTURE_VERSION_ID.into(),
                                expires_at_epoch_seconds: 2_100_000_000,
                                value_bytes: key.len() as u64,
                            },
                            &key,
                        )?;
                    }
                    "fixture/short-key" => {
                        let key = Zeroizing::new(vec![0x5a_u8; FIXTURE_KEY_BYTES - 1]);
                        write_provider_message(
                            &mut writer,
                            &ProviderMessage::Secret {
                                sequence,
                                version_id: FIXTURE_VERSION_ID.into(),
                                expires_at_epoch_seconds: 2_100_000_000,
                                value_bytes: key.len() as u64,
                            },
                            &key,
                        )?;
                    }
                    "fixture/failure" => {
                        write_provider_message(
                            &mut writer,
                            &ProviderMessage::Failure {
                                sequence,
                                code: "fixture_fetch_denied".into(),
                            },
                            &[],
                        )?;
                    }
                    "fixture/stall" => {
                        thread::sleep(Duration::from_secs(15));
                        write_provider_message(
                            &mut writer,
                            &ProviderMessage::Failure {
                                sequence,
                                code: "stall_complete".into(),
                            },
                            &[],
                        )?;
                    }
                    _ => {
                        write_provider_message(
                            &mut writer,
                            &ProviderMessage::Failure {
                                sequence,
                                code: "fixture_key_missing".into(),
                            },
                            &[],
                        )?;
                    }
                }
            }
            HostMessage::Finish { sequence, .. } if active => {
                write_provider_message(&mut writer, &ProviderMessage::Finished { sequence }, &[])?;
                return Ok(());
            }
            _ => {
                return Err(
                    nxb_vault_provider_process::ProcessVaultProviderError::ProtocolViolation,
                )
            }
        }
    }
}
