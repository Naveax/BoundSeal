use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use bsl_session::{SessionBroker, SessionError, SessionMetadata, SessionProfile};
use bsl_vault::{
    CookieMetadata, InMemorySecretVault, SecretBinding, SecretDelivery, SecretHandle, SecretInput,
    SecretKind, VaultError, MAX_SECRET_BYTES,
};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const EXTERNAL_VAULT_PLAN_VERSION: u32 = 1;
pub const EXTERNAL_VAULT_ACTIVATION_VERSION: u32 = 1;
pub const EXTERNAL_VAULT_RECEIPT_VERSION: u32 = 1;
pub const EXTERNAL_VAULT_TEARDOWN_VERSION: u32 = 1;
pub const MAX_EXTERNAL_VAULT_PLAN_SECONDS: i64 = 15 * 60;
pub const MAX_EXTERNAL_SESSION_SECONDS: i64 = 60 * 60;
pub const MAX_EXTERNAL_SECRET_COUNT: usize = 64;
pub const MAX_PROVIDER_PREFIX_BYTES: usize = 256;

const PROTOCOL_MANAGED_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "cookie",
    "expect",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

include!("model.inc.rs");
include!("activation.inc.rs");
include!("provider.inc.rs");
include!("lifecycle.inc.rs");
include!("validation.inc.rs");
include!("tests.rs");
