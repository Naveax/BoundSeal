use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use nxb_session::{SessionMetadata, SessionStatus, SessionUseContext};
use nxb_vault::{
    CookieMetadata, InMemorySecretVault, SecretDeliveryMetadata, SecretHandle, SecretKind,
};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SESSION_INJECTION_MANIFEST_VERSION: u32 = 1;
pub const SESSION_INJECTION_ACTIVATION_VERSION: u32 = 1;
pub const MAX_SESSION_INJECTION_LIFETIME_SECONDS: i64 = 60 * 60;
pub const MAX_SESSION_INJECTION_ACTIVATION_SECONDS: i64 = 15 * 60;
pub const MAX_SESSION_INJECTION_LEASE_SECONDS: i64 = 30;
pub const MAX_SESSION_INJECTION_HANDLES: usize = 64;
pub const MAX_SESSION_INJECTION_PATH_PREFIXES: usize = 32;
pub const MAX_SESSION_INJECTION_HEADER_NAMES: usize = 32;
pub const MAX_SESSION_INJECTION_COOKIE_NAMES: usize = 64;
pub const MAX_SESSION_INJECTION_CSRF_BINDINGS: usize = 16;

const DENIED_PATH_TOKENS: &[&str] = &[
    "delete",
    "destroy",
    "disable",
    "drop",
    "logoff",
    "logout",
    "remove",
    "reset",
    "revoke",
    "shutdown",
    "signout",
    "terminate",
    "unsubscribe",
];

const FORBIDDEN_SECRET_HEADERS: &[&str] = &[
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

include!("manifest.inc.rs");
include!("activation.inc.rs");
include!("authorization.inc.rs");
include!("validation.inc.rs");
include!("error.inc.rs");

#[cfg(test)]
mod tests;
