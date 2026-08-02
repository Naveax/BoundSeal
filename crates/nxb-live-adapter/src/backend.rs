use std::{
    fmt,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

use nxb_destination::is_public_destination;
use nxb_executor::{
    BackendReport, ExecutionControl, ExecutionLimits, PermitBackend, PermitEndpoint,
};
use nxb_stream::{
    BackendReadReport, BackendReadStatus, BackendWriteReport, BackendWriteStatus, ByteStreamBackend,
};
use nxb_transport::TransportScheme;
use rustls::{
    client::Resumption,
    pki_types::ServerName,
    version::{TLS12, TLS13},
    ClientConfig, ClientConnection, HandshakeKind, ProtocolVersion, RootCertStore, StreamOwned,
};

use crate::model::{live_hash_bytes, LiveAdapterError, LiveTlsObservation};

const HTTP11_ALPN: &[u8] = b"http/1.1";
const TLS_BUFFER_LIMIT_BYTES: usize = 512 * 1024;

pub struct LiveTlsByteStream {
    stream: StreamOwned<ClientConnection, TcpStream>,
    closed: bool,
}

impl fmt::Debug for LiveTlsByteStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveTlsByteStream")
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl LiveTlsByteStream {
    fn new(stream: StreamOwned<ClientConnection, TcpStream>) -> Self {
        Self {
            stream,
            closed: false,
        }
    }
}

impl ByteStreamBackend for LiveTlsByteStream {
    fn read(&mut self, maximum_bytes: u64, deadline_milliseconds: u64) -> BackendReadReport {
        let started = Instant::now();
        if self.closed {
            return BackendReadReport {
                elapsed_milliseconds: 0,
                status: BackendReadStatus::Eof,
            };
        }

        let timeout = Duration::from_millis(deadline_milliseconds.max(1));
        if self.stream.sock.set_read_timeout(Some(timeout)).is_err() {
            return BackendReadReport {
                elapsed_milliseconds: elapsed_milliseconds(started),
                status: BackendReadStatus::Failure("socket_read_timeout_config".into()),
            };
        }

        let maximum = usize::try_from(maximum_bytes).unwrap_or(usize::MAX);
        let mut buffer = vec![0_u8; maximum];
        let status = match self.stream.read(&mut buffer) {
            Ok(0) => BackendReadStatus::Eof,
            Ok(read) => {
                buffer.truncate(read);
                BackendReadStatus::Data(buffer)
            }
            Err(error) => classify_read_error(&error),
        };
        BackendReadReport {
            elapsed_milliseconds: elapsed_milliseconds(started),
            status,
        }
    }

    fn write(&mut self, bytes: &[u8], deadline_milliseconds: u64) -> BackendWriteReport {
        let started = Instant::now();
        if self.closed {
            return BackendWriteReport {
                elapsed_milliseconds: 0,
                status: BackendWriteStatus::Closed,
            };
        }

        let timeout = Duration::from_millis(deadline_milliseconds.max(1));
        if self.stream.sock.set_write_timeout(Some(timeout)).is_err() {
            return BackendWriteReport {
                elapsed_milliseconds: elapsed_milliseconds(started),
                status: BackendWriteStatus::Failure("socket_write_timeout_config".into()),
            };
        }

        let status = match self.stream.write(bytes) {
            Ok(0) => BackendWriteStatus::Closed,
            Ok(written) => match self.stream.flush() {
                Ok(()) => BackendWriteStatus::Written(written as u64),
                Err(error) => classify_write_error(&error),
            },
            Err(error) => classify_write_error(&error),
        };
        BackendWriteReport {
            elapsed_milliseconds: elapsed_milliseconds(started),
            status,
        }
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.stream.conn.send_close_notify();
        let _ = self.stream.flush();
        let _ = self.stream.sock.shutdown(Shutdown::Both);
        self.closed = true;
    }
}

pub struct LiveConnectBackend {
    client_config: Arc<ClientConfig>,
    connected_stream: Option<LiveTlsByteStream>,
    last_observation: Option<LiveTlsObservation>,
    allow_non_public_for_tests: bool,
}

impl fmt::Debug for LiveConnectBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveConnectBackend")
            .field("connected_stream_ready", &self.connected_stream.is_some())
            .field("last_observation_ready", &self.last_observation.is_some())
            .finish_non_exhaustive()
    }
}

impl LiveConnectBackend {
    pub fn with_mozilla_roots() -> Result<Self, LiveAdapterError> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::from_root_store(roots, false)
    }

    #[cfg(test)]
    pub(crate) fn with_test_roots(roots: RootCertStore) -> Result<Self, LiveAdapterError> {
        Self::from_root_store(roots, true)
    }

    fn from_root_store(
        roots: RootCertStore,
        allow_non_public_for_tests: bool,
    ) -> Result<Self, LiveAdapterError> {
        if roots.is_empty() {
            return Err(LiveAdapterError::TlsConfiguration(
                "root certificate store is empty".into(),
            ));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13, &TLS12])
            .map_err(|_| {
                LiveAdapterError::TlsConfiguration(
                    "ring provider rejected TLS 1.2/1.3 configuration".into(),
                )
            })?;
        let mut client_config = builder.with_root_certificates(roots).with_no_client_auth();
        client_config.alpn_protocols = vec![HTTP11_ALPN.to_vec()];
        client_config.resumption = Resumption::disabled();
        client_config.enable_early_data = false;
        client_config.send_ticket_request = None;

        Ok(Self {
            client_config: Arc::new(client_config),
            connected_stream: None,
            last_observation: None,
            allow_non_public_for_tests,
        })
    }

    pub fn take_stream(&mut self) -> Option<LiveTlsByteStream> {
        self.connected_stream.take()
    }

    pub fn last_observation(&self) -> Option<&LiveTlsObservation> {
        self.last_observation.as_ref()
    }

    fn connect(
        &mut self,
        endpoint: PermitEndpoint<'_>,
        limits: &ExecutionLimits,
        control: &ExecutionControl,
    ) -> Result<BackendReport, BackendReport> {
        self.last_observation = None;
        if self.connected_stream.is_some() {
            return Err(failure_report(None, 0, 0, 0, "previous_stream_not_taken"));
        }
        if control.emergency_stop_requested {
            return Err(failure_report(None, 0, 0, 0, "emergency_stop"));
        }
        if control.cancel_requested {
            return Err(failure_report(None, 0, 0, 0, "cancelled"));
        }
        if endpoint.scheme != TransportScheme::Https {
            return Err(failure_report(None, 0, 0, 0, "https_required"));
        }
        if endpoint.port != 443 || endpoint.redirect_depth != 0 {
            return Err(failure_report(None, 0, 0, 0, "permit_boundary_rejected"));
        }
        if !self.allow_non_public_for_tests && !is_public_destination(endpoint.remote_ip) {
            return Err(failure_report(None, 0, 0, 0, "non_public_destination"));
        }

        let Some(server_name_text) = endpoint.sni else {
            return Err(failure_report(None, 0, 0, 0, "missing_sni"));
        };
        if !authority_matches_sni(endpoint.http_host, server_name_text) {
            return Err(failure_report(None, 0, 0, 0, "authority_sni_mismatch"));
        }
        let server_name = match ServerName::try_from(server_name_text.to_owned()) {
            Ok(value) => value,
            Err(_) => return Err(failure_report(None, 0, 0, 0, "invalid_server_name")),
        };

        let started = Instant::now();
        let socket_address = SocketAddr::new(endpoint.remote_ip, endpoint.port);
        let tcp_started = Instant::now();
        let tcp_stream = match TcpStream::connect_timeout(
            &socket_address,
            Duration::from_millis(limits.connect_timeout_milliseconds),
        ) {
            Ok(stream) => stream,
            Err(error) => {
                return Err(failure_report(
                    None,
                    elapsed_milliseconds(started),
                    0,
                    0,
                    connect_error_code(&error),
                ))
            }
        };
        let connected_after = elapsed_milliseconds(tcp_started);
        let _ = tcp_stream.set_nodelay(true);
        let total_timeout = Duration::from_millis(limits.total_timeout_milliseconds);
        if tcp_stream.set_read_timeout(Some(total_timeout)).is_err()
            || tcp_stream.set_write_timeout(Some(total_timeout)).is_err()
        {
            return Err(failure_report(
                Some(connected_after),
                elapsed_milliseconds(started),
                0,
                0,
                "socket_timeout_config",
            ));
        }

        let mut connection = match ClientConnection::new(self.client_config.clone(), server_name) {
            Ok(connection) => connection,
            Err(_) => {
                return Err(failure_report(
                    Some(connected_after),
                    elapsed_milliseconds(started),
                    0,
                    0,
                    "tls_client_init",
                ))
            }
        };
        connection.set_buffer_limit(Some(TLS_BUFFER_LIMIT_BYTES));
        let mut tcp_stream = tcp_stream;
        let mut tls_read_bytes = 0_u64;
        let mut tls_written_bytes = 0_u64;

        while connection.is_handshaking() {
            if started.elapsed() >= total_timeout {
                return Err(failure_report(
                    Some(connected_after),
                    elapsed_milliseconds(started),
                    tls_read_bytes,
                    tls_written_bytes,
                    "tls_handshake_timeout",
                ));
            }
            match connection.complete_io(&mut tcp_stream) {
                Ok((read, written)) => {
                    tls_read_bytes = tls_read_bytes.saturating_add(read as u64);
                    tls_written_bytes = tls_written_bytes.saturating_add(written as u64);
                }
                Err(error) => {
                    return Err(failure_report(
                        Some(connected_after),
                        elapsed_milliseconds(started),
                        tls_read_bytes,
                        tls_written_bytes,
                        tls_io_error_code(&error),
                    ))
                }
            }
        }

        let protocol_version = match connection.protocol_version() {
            Some(ProtocolVersion::TLSv1_2) => "tls_1_2",
            Some(ProtocolVersion::TLSv1_3) => "tls_1_3",
            _ => {
                return Err(failure_report(
                    Some(connected_after),
                    elapsed_milliseconds(started),
                    tls_read_bytes,
                    tls_written_bytes,
                    "tls_protocol_rejected",
                ))
            }
        };
        let alpn_protocol = connection.alpn_protocol().map(|value| value.to_vec());
        if let Some(alpn) = &alpn_protocol {
            if alpn.as_slice() != HTTP11_ALPN {
                return Err(failure_report(
                    Some(connected_after),
                    elapsed_milliseconds(started),
                    tls_read_bytes,
                    tls_written_bytes,
                    "alpn_rejected",
                ));
            }
        }
        if matches!(connection.handshake_kind(), Some(HandshakeKind::Resumed)) {
            return Err(failure_report(
                Some(connected_after),
                elapsed_milliseconds(started),
                tls_read_bytes,
                tls_written_bytes,
                "tls_resumption_rejected",
            ));
        }
        let Some(certificates) = connection.peer_certificates() else {
            return Err(failure_report(
                Some(connected_after),
                elapsed_milliseconds(started),
                tls_read_bytes,
                tls_written_bytes,
                "missing_peer_certificate",
            ));
        };
        let Some(leaf) = certificates.first() else {
            return Err(failure_report(
                Some(connected_after),
                elapsed_milliseconds(started),
                tls_read_bytes,
                tls_written_bytes,
                "empty_peer_certificate_chain",
            ));
        };
        let cipher_suite = connection
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite()))
            .unwrap_or_else(|| "unknown".into());
        let handshake_kind = connection
            .handshake_kind()
            .map(|kind| format!("{kind:?}").to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".into());
        let handshake_elapsed = elapsed_milliseconds(started);
        let observation = LiveTlsObservation {
            remote_ip: endpoint.remote_ip.to_string(),
            server_name: server_name_text.into(),
            protocol_version: protocol_version.into(),
            alpn_protocol: alpn_protocol.map(|value| String::from_utf8_lossy(&value).into_owned()),
            cipher_suite,
            handshake_kind,
            certificate_chain_length: certificates.len() as u64,
            leaf_certificate_sha256: live_hash_bytes(leaf.as_ref()),
            connected_after_milliseconds: connected_after,
            handshake_elapsed_milliseconds: handshake_elapsed,
            tls_read_bytes,
            tls_written_bytes,
        };
        self.last_observation = Some(observation);
        self.connected_stream = Some(LiveTlsByteStream::new(StreamOwned::new(
            connection, tcp_stream,
        )));

        Ok(BackendReport {
            connected_after_milliseconds: Some(connected_after),
            elapsed_milliseconds: handshake_elapsed,
            read_bytes: tls_read_bytes,
            written_bytes: tls_written_bytes,
            failure_code: None,
        })
    }
}

impl PermitBackend for LiveConnectBackend {
    fn execute(
        &mut self,
        endpoint: PermitEndpoint<'_>,
        limits: &ExecutionLimits,
        control: &ExecutionControl,
    ) -> BackendReport {
        match self.connect(endpoint, limits, control) {
            Ok(report) | Err(report) => report,
        }
    }
}

fn authority_matches_sni(authority: &str, sni: &str) -> bool {
    authority.eq_ignore_ascii_case(sni)
        || authority
            .strip_suffix(":443")
            .is_some_and(|host| host.eq_ignore_ascii_case(sni))
}

fn failure_report(
    connected_after_milliseconds: Option<u64>,
    elapsed_milliseconds: u64,
    read_bytes: u64,
    written_bytes: u64,
    failure_code: &str,
) -> BackendReport {
    BackendReport {
        connected_after_milliseconds,
        elapsed_milliseconds,
        read_bytes,
        written_bytes,
        failure_code: Some(failure_code.into()),
    }
}

fn elapsed_milliseconds(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn connect_error_code(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "connect_timeout",
        io::ErrorKind::ConnectionRefused => "connect_refused",
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => "connect_unreachable",
        io::ErrorKind::PermissionDenied => "connect_permission_denied",
        _ => "connect_io_failure",
    }
}

fn tls_io_error_code(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "tls_handshake_timeout",
        io::ErrorKind::InvalidData => "tls_certificate_or_protocol_rejected",
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => "tls_connection_reset",
        io::ErrorKind::UnexpectedEof => "tls_truncated",
        _ => "tls_handshake_io_failure",
    }
}

fn classify_read_error(error: &io::Error) -> BackendReadStatus {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => BackendReadStatus::Timeout,
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => BackendReadStatus::Reset,
        io::ErrorKind::UnexpectedEof => BackendReadStatus::Truncated(Vec::new()),
        io::ErrorKind::InvalidData => BackendReadStatus::Failure("tls_record_invalid".into()),
        _ => BackendReadStatus::Failure("tls_read_failure".into()),
    }
}

fn classify_write_error(error: &io::Error) -> BackendWriteStatus {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => BackendWriteStatus::Timeout,
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => BackendWriteStatus::Reset,
        io::ErrorKind::NotConnected => BackendWriteStatus::Closed,
        io::ErrorKind::InvalidData => BackendWriteStatus::Failure("tls_record_invalid".into()),
        _ => BackendWriteStatus::Failure("tls_write_failure".into()),
    }
}
