#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedirectAuditEvent {
    pub chain_id: String,
    pub step: u8,
    pub status: String,
    pub reason: String,
    pub response_status: u16,
    pub from_origin: String,
    pub to_origin: String,
    pub from_target_sha256: String,
    pub to_target_sha256: String,
    pub location_sha256: String,
    pub method_before: String,
    pub method_after: String,
    pub body_disposition: String,
    pub origin_transition: String,
    pub secret_disposition: String,
    pub session_identity_sha256: String,
    pub session_generation: u64,
    pub dns_context_id: String,
    pub gateway_decision_id: String,
    pub gateway_outcome: String,
    pub gateway_decision_sha256: String,
    pub gateway_audit_anchor: String,
    pub ticket_id: Option<String>,
    pub ticket_binding_hash: Option<String>,
    pub transport_audit_anchor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedirectAuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: RedirectAuditEvent,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct RedirectAuditChain {
    genesis_hash: String,
    records: Vec<RedirectAuditRecord>,
    tail_hash: String,
}

impl RedirectAuditChain {
    pub fn new(chain_id: &str, transport_anchor: &str) -> Self {
        let genesis_hash = hash(format!("bsl-redirect:{chain_id}:{transport_anchor}").as_bytes());
        Self {
            tail_hash: genesis_hash.clone(),
            genesis_hash,
            records: Vec::new(),
        }
    }

    pub fn append(&mut self, event: RedirectAuditEvent) -> Result<(), RedirectAuditError> {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self.tail_hash.clone();
        let bytes = serde_json::to_vec(&(sequence, &previous_hash, &event))
            .map_err(|error| RedirectAuditError::Serialization(error.to_string()))?;
        let record_hash = hash(&bytes);
        self.records.push(RedirectAuditRecord {
            sequence,
            previous_hash,
            event,
            record_hash: record_hash.clone(),
        });
        self.tail_hash = record_hash;
        Ok(())
    }

    pub fn records(&self) -> &[RedirectAuditRecord] {
        &self.records
    }

    pub fn tail_hash(&self) -> &str {
        &self.tail_hash
    }

    pub fn verify(&self) -> Result<(), RedirectAuditError> {
        let mut previous = self.genesis_hash.clone();
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 + 1 {
                return Err(RedirectAuditError::SequenceMismatch {
                    record_index: index,
                });
            }
            if record.previous_hash != previous {
                return Err(RedirectAuditError::PreviousHashMismatch {
                    record_index: index,
                });
            }
            let bytes =
                serde_json::to_vec(&(record.sequence, &record.previous_hash, &record.event))
                    .map_err(|error| RedirectAuditError::Serialization(error.to_string()))?;
            let expected = hash(&bytes);
            if record.record_hash != expected {
                return Err(RedirectAuditError::RecordHashMismatch {
                    record_index: index,
                });
            }
            previous = expected;
        }
        if self.tail_hash != previous {
            return Err(RedirectAuditError::TailHashMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RedirectAuditError {
    #[error("redirect audit material could not be serialized: {0}")]
    Serialization(String),
    #[error("redirect audit sequence mismatch at record {record_index}")]
    SequenceMismatch { record_index: usize },
    #[error("redirect audit previous-hash mismatch at record {record_index}")]
    PreviousHashMismatch { record_index: usize },
    #[error("redirect audit record-hash mismatch at record {record_index}")]
    RecordHashMismatch { record_index: usize },
    #[error("redirect audit tail hash mismatch")]
    TailHashMismatch,
}

#[derive(Debug, Error)]
pub enum RedirectError {
    #[error("redirect limits are outside the supported range")]
    InvalidLimits,
    #[error("redirect chain identifier is invalid")]
    InvalidChainId,
    #[error("redirect session identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("redirect session generation must be greater than zero")]
    InvalidSessionGeneration,
    #[error("redirect request method is invalid")]
    InvalidMethod,
    #[error("redirect digest is invalid: {0}")]
    InvalidDigest(String),
    #[error("URL is not an absolute HTTP(S) URL")]
    InvalidUrl,
    #[error("URL contains user information")]
    UserInfoForbidden,
    #[error("URL does not contain a host")]
    MissingHost,
    #[error("URL does not have a known port")]
    MissingPort,
    #[error("response status is not a supported redirect")]
    NotRedirect,
    #[error("redirect response is missing Location")]
    MissingLocation,
    #[error("redirect response contains multiple Location fields")]
    MultipleLocations,
    #[error("Location is invalid: {0}")]
    InvalidLocation(String),
    #[error("HTTPS to HTTP redirect downgrade is forbidden")]
    HttpsDowngrade,
    #[error("redirect limit was exceeded")]
    RedirectLimitExceeded,
    #[error("redirect loop was detected")]
    RedirectLoop,
    #[error("redirect DNS context was already used")]
    DnsContextReused,
    #[error("redirect session identity changed across the chain")]
    SessionIdentityMismatch,
    #[error("redirect session generation regressed or skipped its declared transition")]
    SessionGenerationMismatch,
    #[error("cross-origin redirect would replay a request body")]
    CrossOriginBodyReplayDenied,
    #[error("redirect chain is terminal")]
    ChainTerminated,
    #[error("gateway authorized redirect without issuing a transport ticket")]
    MissingTransportTicket,
    #[error("pinned transport rejected redirect authorization: {0}")]
    Transport(#[from] PinnedTransportError),
    #[error("redirect audit chain is invalid: {0}")]
    Audit(#[from] RedirectAuditError),
}

struct RedirectAuditInput<'a> {
    response_status: u16,
    from_origin: &'a Origin,
    to_origin: &'a Origin,
    location_sha256: &'a str,
    to_target_sha256: &'a str,
    method_after: &'a str,
    body_disposition: RedirectBodyDisposition,
    origin_transition: OriginTransition,
    secret_disposition: RedirectSecretDisposition,
    session: &'a RedirectSessionSnapshot,
    dns_context_id: &'a str,
    decision: &'a GatewayDecision,
    ticket_id: Option<String>,
    ticket_binding_hash: Option<String>,
}

#[derive(Debug)]
pub struct RedirectCoordinator {
    chain_id: String,
    limits: RedirectLimits,
    transport: PinnedTransportCoordinator,
    current: RedirectRequestState,
    seen_requests: BTreeSet<String>,
    used_dns_contexts: BTreeSet<String>,
    redirect_count: u8,
    terminal: bool,
    audit: RedirectAuditChain,
}
