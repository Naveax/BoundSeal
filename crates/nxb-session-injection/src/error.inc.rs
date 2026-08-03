#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionInjectionError {
    #[error("unsupported session-injection manifest version")]
    UnsupportedManifestVersion,
    #[error("unsupported session-injection activation version")]
    UnsupportedActivationVersion,
    #[error("session-injection identifier is invalid: {0}")]
    InvalidIdentifier(String),
    #[error("session-injection digest is invalid: {0}")]
    InvalidDigest(String),
    #[error("session-injection origin is invalid")]
    InvalidOrigin,
    #[error("session-injection origin digest does not match")]
    OriginDigestMismatch,
    #[error("session-injection manifest validity window is invalid")]
    InvalidManifestWindow,
    #[error("session-injection manifest is outside its validity window")]
    ManifestExpired,
    #[error("session-injection manifest digest mismatch")]
    ManifestDigestMismatch,
    #[error("session-injection lease duration is invalid")]
    InvalidLeaseDuration,
    #[error("session-injection lease expired before use")]
    LeaseExpired,
    #[error("session-injection secret handle set is invalid")]
    InvalidSecretHandleSet,
    #[error("session-injection path scope is invalid")]
    InvalidPathScope,
    #[error("session-injection allowlist is too large")]
    AllowlistTooLarge,
    #[error("session-injection header allowlist is invalid")]
    InvalidHeaderAllowlist,
    #[error("session-injection cookie allowlist is invalid")]
    InvalidCookieAllowlist,
    #[error("session-injection contains too many CSRF bindings")]
    TooManyCsrfBindings,
    #[error("session-injection CSRF binding is invalid")]
    InvalidCsrfBinding,
    #[error("session-injection activation public key is invalid")]
    InvalidActivationPublicKey,
    #[error("session-injection activation window is invalid")]
    InvalidActivationWindow,
    #[error("session-injection activation key does not match")]
    ActivationKeyMismatch,
    #[error("session-injection activation does not match the manifest")]
    ActivationBindingMismatch,
    #[error("session-injection activation is outside its validity window")]
    ActivationExpired,
    #[error("session-injection signature is invalid")]
    InvalidSignature,
    #[error("session-injection does not match the discovery session")]
    DiscoverySessionBindingMismatch,
    #[error("session-injection request origin does not match")]
    RequestOriginMismatch,
    #[error("session-injection method is denied")]
    MethodDenied,
    #[error("session-injection request path is denied")]
    RequestPathDenied,
    #[error("session is revoked")]
    SessionRevoked,
    #[error("session identity does not match injection identity")]
    SessionIdentityMismatch,
    #[error("session is expired or expires before the injection manifest")]
    SessionExpired,
    #[error("session authority is broader than the injection origin")]
    SessionAuthorityTooBroad,
    #[error("session generation regressed")]
    SessionGenerationRegression,
    #[error("session contains duplicate secret handles")]
    DuplicateSessionHandle,
    #[error("secret handle is unknown or revoked")]
    UnknownSecretHandle,
    #[error("secret identity or authority binding does not match")]
    SecretBindingMismatch,
    #[error("secret expired before injection authorization")]
    SecretExpired,
    #[error("session contains a header secret outside the manifest")]
    HeaderDenied,
    #[error("session contains a cookie outside the manifest")]
    CookieDenied,
    #[error("session cookie is expired")]
    CookieExpired,
    #[error("required static secret is missing")]
    RequiredStaticSecretMissing,
    #[error("CSRF cookie is missing")]
    CsrfCookieMissing,
    #[error("CSRF cookie does not apply to the request path")]
    CsrfCookiePathMismatch,
    #[error("session-injection authorization is invalid")]
    InvalidAuthorization,
    #[error("session-injection authorization digest mismatch")]
    AuthorizationDigestMismatch,
    #[error("session-injection serialization failed: {0}")]
    Serialization(String),
    #[error("session-injection state operation failed: {0}")]
    StateIo(String),
}
