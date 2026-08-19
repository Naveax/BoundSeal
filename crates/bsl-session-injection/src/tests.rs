use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use bsl_session::{SessionProfile, SessionStatus};
use bsl_vault::{CookieMetadata, SameSitePolicy, SecretBinding, SecretDelivery, SecretInput};
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::*;

const NOW: i64 = 1_900_000_000;

fn binding() -> SecretBinding {
    SecretBinding {
        run_id: "run-138".into(),
        worker_id: "worker-138".into(),
        account_id: "account-a".into(),
        tenant_id: "tenant-a".into(),
        role_id: "admin".into(),
        allowed_hosts: BTreeSet::from(["app.example.com".into()]),
        allowed_schemes: BTreeSet::from(["https".into()]),
    }
}

fn insert_header(
    vault: &mut InMemorySecretVault,
    kind: SecretKind,
    name: &str,
    value: &[u8],
    expires_at: i64,
) -> SecretHandle {
    vault
        .insert(
            SecretInput {
                kind,
                value: value.to_vec(),
                binding: binding(),
                delivery: SecretDelivery::Header {
                    name: name.into(),
                    prefix: if name.eq_ignore_ascii_case("authorization") {
                        b"Bearer ".to_vec()
                    } else {
                        Vec::new()
                    },
                },
                expires_at_epoch_seconds: Some(expires_at),
            },
            NOW,
        )
        .unwrap()
}

fn insert_cookie(
    vault: &mut InMemorySecretVault,
    name: &str,
    path: &str,
    value: &[u8],
) -> SecretHandle {
    vault
        .insert(
            SecretInput {
                kind: SecretKind::Cookie,
                value: value.to_vec(),
                binding: binding(),
                delivery: SecretDelivery::Cookie(CookieMetadata {
                    name: name.into(),
                    domain: "app.example.com".into(),
                    path: path.into(),
                    expires_at_epoch_seconds: Some(NOW + 3_600),
                    secure: true,
                    http_only: true,
                    same_site: SameSitePolicy::Strict,
                }),
                expires_at_epoch_seconds: Some(NOW + 3_600),
            },
            NOW,
        )
        .unwrap()
}

fn session(handles: Vec<SecretHandle>) -> SessionMetadata {
    SessionMetadata {
        session_id: "session-138".into(),
        profile: SessionProfile {
            run_id: "run-138".into(),
            worker_id: "worker-138".into(),
            account_id: "account-a".into(),
            tenant_id: "tenant-a".into(),
            role_id: "admin".into(),
            allowed_hosts: BTreeSet::from(["app.example.com".into()]),
            allowed_schemes: BTreeSet::from(["https".into()]),
            secret_handles: handles,
            expires_at_epoch_seconds: NOW + 1_800,
        },
        status: SessionStatus::Active,
        created_at_epoch_seconds: NOW,
        generation: 1,
        cookie_jar_audit_tail: "a".repeat(64),
    }
}

fn manifest(
    key: &[u8],
    handles: Vec<SecretHandle>,
    csrf: SecretHandle,
) -> SessionInjectionManifest {
    SessionInjectionManifest::build(SessionInjectionManifestParameters {
        injection_id: "injection-138".into(),
        discovery_plan_sha256: "b".repeat(64),
        target_origin_sha256: hash_bytes(b"https://app.example.com:443"),
        authority: "app.example.com".into(),
        session_id: "session-138".into(),
        run_id: "run-138".into(),
        worker_id: "worker-138".into(),
        account_id: "account-a".into(),
        tenant_id: "tenant-a".into(),
        role_id: "admin".into(),
        bootstrap_secret_handles: handles,
        allowed_path_prefixes: BTreeSet::from(["/app".into()]),
        allowed_header_names: BTreeSet::from(["authorization".into(), "x-csrf-token".into()]),
        allowed_cookie_names: BTreeSet::from(["sid".into()]),
        csrf_bindings: vec![CsrfBinding {
            cookie_name: "sid".into(),
            header_name: "x-csrf-token".into(),
            token_handle: csrf,
        }],
        maximum_lease_seconds: 10,
        created_at_epoch_seconds: NOW,
        expires_at_epoch_seconds: NOW + 600,
        activation_public_key: key.to_vec(),
    })
    .unwrap()
}

fn signed(
    manifest: &SessionInjectionManifest,
    key_pair: &Ed25519KeyPair,
) -> SessionInjectionActivationCertificate {
    let payload =
        SessionInjectionActivationPayload::template("activation-138", manifest, NOW, NOW + 300)
            .unwrap();
    let signature = key_pair.sign(&payload.signing_bytes().unwrap());
    SessionInjectionActivationCertificate {
        payload,
        signature_hex: lower_hex(signature.as_ref()),
    }
}

fn unique_state_directory(label: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    env::temp_dir().join(format!(
        "bsl-session-injection-{label}-{}-{unique}",
        std::process::id()
    ))
}

fn fixture() -> (
    InMemorySecretVault,
    SessionMetadata,
    SessionInjectionManifest,
    SessionInjectionActivationCertificate,
    Ed25519KeyPair,
) {
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[31_u8; 32]).unwrap();
    let mut vault = InMemorySecretVault::new("vault-138").unwrap();
    let bearer = insert_header(
        &mut vault,
        SecretKind::BearerToken,
        "Authorization",
        b"bearer-secret",
        NOW + 3_600,
    );
    let csrf = insert_header(
        &mut vault,
        SecretKind::CsrfToken,
        "X-CSRF-Token",
        b"csrf-secret",
        NOW + 3_600,
    );
    let cookie = insert_cookie(&mut vault, "sid", "/app", b"cookie-secret");
    let handles = vec![bearer, csrf.clone(), cookie];
    let session = session(handles.clone());
    let manifest = manifest(key_pair.public_key().as_ref(), handles, csrf);
    let certificate = signed(&manifest, &key_pair);
    (vault, session, manifest, certificate, key_pair)
}

#[allow(clippy::too_many_arguments)]
fn bind_for_test(
    manifest: SessionInjectionManifest,
    certificate: &SessionInjectionActivationCertificate,
    public_key: &[u8],
    expected_discovery_plan_sha256: &str,
    expected_target_origin_sha256: &str,
    session: &SessionMetadata,
    vault: &InMemorySecretVault,
    now_epoch_seconds: i64,
) -> Result<BoundSessionInjection, SessionInjectionError> {
    let directory = unique_state_directory("bind");
    let consumed = consume_activation_once(
        &directory,
        &manifest,
        certificate,
        public_key,
        now_epoch_seconds,
    )?;
    let result = BoundSessionInjection::bind(
        manifest,
        consumed,
        expected_discovery_plan_sha256,
        expected_target_origin_sha256,
        session,
        vault,
        now_epoch_seconds,
    );
    if directory.exists() {
        fs::remove_dir_all(directory).unwrap();
    }
    result
}

#[test]
fn exact_manifest_authorizes_only_bounded_get_and_head_requests() {
    let (vault, session, manifest, certificate, key_pair) = fixture();
    let bound = bind_for_test(
        manifest,
        &certificate,
        key_pair.public_key().as_ref(),
        &"b".repeat(64),
        &hash_bytes(b"https://app.example.com:443"),
        &session,
        &vault,
        NOW + 1,
    )
    .unwrap();
    let authorization = bound
        .authorize_request(
            &session,
            &vault,
            "app.example.com",
            "https",
            "/app/api/me",
            "GET",
            NOW + 2,
        )
        .unwrap();
    authorization.verify().unwrap();
    assert_eq!(authorization.static_secret_count, 2);
    assert_eq!(authorization.cookie_secret_count, 1);
    for (path, method) in [
        ("/application", "GET"),
        ("/app/api/me", "POST"),
        ("/app/../admin", "GET"),
        ("/app//admin", "GET"),
        ("/app/logout.json", "GET"),
    ] {
        assert!(bound
            .authorize_request(
                &session,
                &vault,
                "app.example.com",
                "https",
                path,
                method,
                NOW + 2,
            )
            .is_err());
    }
}

#[test]
fn tenant_mismatch_and_static_secret_broadening_fail_closed() {
    let (mut vault, mut session, manifest, certificate, key_pair) = fixture();
    let bound = bind_for_test(
        manifest,
        &certificate,
        key_pair.public_key().as_ref(),
        &"b".repeat(64),
        &hash_bytes(b"https://app.example.com:443"),
        &session,
        &vault,
        NOW + 1,
    )
    .unwrap();
    session.profile.tenant_id = "tenant-b".into();
    assert!(matches!(
        bound.authorize_request(
            &session,
            &vault,
            "app.example.com",
            "https",
            "/app/api/me",
            "GET",
            NOW + 2,
        ),
        Err(SessionInjectionError::SessionIdentityMismatch)
    ));
    session.profile.tenant_id = "tenant-a".into();
    let extra = insert_header(
        &mut vault,
        SecretKind::ApiKey,
        "X-Extra-Key",
        b"extra-secret",
        NOW + 3_600,
    );
    session.profile.secret_handles.push(extra);
    assert!(matches!(
        bound.authorize_request(
            &session,
            &vault,
            "app.example.com",
            "https",
            "/app/api/me",
            "GET",
            NOW + 2,
        ),
        Err(SessionInjectionError::HeaderDenied)
    ));
}

#[test]
fn allowlisted_cookie_rotation_is_accepted() {
    let (mut vault, mut session, manifest, certificate, key_pair) = fixture();
    let bound = bind_for_test(
        manifest,
        &certificate,
        key_pair.public_key().as_ref(),
        &"b".repeat(64),
        &hash_bytes(b"https://app.example.com:443"),
        &session,
        &vault,
        NOW + 1,
    )
    .unwrap();
    let old_cookie = session
        .profile
        .secret_handles
        .iter()
        .find(|handle| {
            matches!(
                vault.metadata(handle).unwrap().delivery,
                SecretDeliveryMetadata::Cookie { .. }
            )
        })
        .cloned()
        .unwrap();
    let rotated = insert_cookie(&mut vault, "sid", "/app", b"rotated-cookie");
    session
        .profile
        .secret_handles
        .retain(|handle| handle != &old_cookie);
    session.profile.secret_handles.push(rotated);
    session.generation += 1;
    bound
        .authorize_request(
            &session,
            &vault,
            "app.example.com",
            "https",
            "/app/api/me",
            "HEAD",
            NOW + 2,
        )
        .unwrap();
}

#[test]
fn csrf_cookie_must_apply_to_the_current_path() {
    let (mut vault, mut session, manifest, certificate, key_pair) = fixture();
    let old_cookie = session
        .profile
        .secret_handles
        .iter()
        .find(|handle| {
            matches!(
                vault.metadata(handle).unwrap().delivery,
                SecretDeliveryMetadata::Cookie { .. }
            )
        })
        .cloned()
        .unwrap();
    session
        .profile
        .secret_handles
        .retain(|handle| handle != &old_cookie);
    session.profile.secret_handles.push(insert_cookie(
        &mut vault,
        "sid",
        "/app/admin",
        b"admin-cookie",
    ));
    let bound = bind_for_test(
        manifest,
        &certificate,
        key_pair.public_key().as_ref(),
        &"b".repeat(64),
        &hash_bytes(b"https://app.example.com:443"),
        &session,
        &vault,
        NOW + 1,
    )
    .unwrap();
    assert!(matches!(
        bound.authorize_request(
            &session,
            &vault,
            "app.example.com",
            "https",
            "/app/profile",
            "GET",
            NOW + 2,
        ),
        Err(SessionInjectionError::CsrfCookiePathMismatch)
    ));
}

#[test]
fn activation_is_signature_bound_and_atomically_single_use() {
    let (vault, session, manifest, certificate, key_pair) = fixture();
    let directory = unique_state_directory("single-use");
    let consumed = consume_activation_once(
        &directory,
        &manifest,
        &certificate,
        key_pair.public_key().as_ref(),
        NOW + 1,
    )
    .unwrap();
    BoundSessionInjection::bind(
        manifest.clone(),
        consumed,
        &"b".repeat(64),
        &hash_bytes(b"https://app.example.com:443"),
        &session,
        &vault,
        NOW + 1,
    )
    .unwrap();
    assert!(consume_activation_once(
        &directory,
        &manifest,
        &certificate,
        key_pair.public_key().as_ref(),
        NOW + 1,
    )
    .is_err());
    let mut tampered = manifest;
    tampered.maximum_lease_seconds += 1;
    tampered.manifest_sha256 = tampered.calculate_sha256().unwrap();
    assert!(certificate
        .verify(&tampered, key_pair.public_key().as_ref(), NOW + 1)
        .is_err());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn broad_authority_and_expired_secrets_are_denied() {
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[41_u8; 32]).unwrap();
    let mut vault = InMemorySecretVault::new("vault-broad").unwrap();
    let mut broad_binding = binding();
    broad_binding
        .allowed_hosts
        .insert("other.example.com".into());
    let broad = vault
        .insert(
            SecretInput {
                kind: SecretKind::BearerToken,
                value: b"broad-secret".to_vec(),
                binding: broad_binding,
                delivery: SecretDelivery::Header {
                    name: "Authorization".into(),
                    prefix: b"Bearer ".to_vec(),
                },
                expires_at_epoch_seconds: Some(NOW + 3_600),
            },
            NOW,
        )
        .unwrap();
    let csrf = insert_header(
        &mut vault,
        SecretKind::CsrfToken,
        "X-CSRF-Token",
        b"csrf-secret",
        NOW + 3_600,
    );
    let cookie = insert_cookie(&mut vault, "sid", "/app", b"cookie-secret");
    let handles = vec![broad, csrf.clone(), cookie];
    let broad_session = session(handles.clone());
    let broad_manifest = manifest(key_pair.public_key().as_ref(), handles, csrf);
    let certificate = signed(&broad_manifest, &key_pair);
    assert!(matches!(
        bind_for_test(
            broad_manifest,
            &certificate,
            key_pair.public_key().as_ref(),
            &"b".repeat(64),
            &hash_bytes(b"https://app.example.com:443"),
            &broad_session,
            &vault,
            NOW + 1,
        ),
        Err(SessionInjectionError::SecretBindingMismatch)
    ));

    let mut vault = InMemorySecretVault::new("vault-expired").unwrap();
    let expired = insert_header(
        &mut vault,
        SecretKind::BearerToken,
        "Authorization",
        b"expired-secret",
        NOW + 1,
    );
    let csrf = insert_header(
        &mut vault,
        SecretKind::CsrfToken,
        "X-CSRF-Token",
        b"csrf-secret",
        NOW + 3_600,
    );
    let cookie = insert_cookie(&mut vault, "sid", "/app", b"cookie-secret");
    let handles = vec![expired, csrf.clone(), cookie];
    let session = session(handles.clone());
    let manifest = manifest(key_pair.public_key().as_ref(), handles, csrf);
    let certificate = signed(&manifest, &key_pair);
    assert!(matches!(
        bind_for_test(
            manifest,
            &certificate,
            key_pair.public_key().as_ref(),
            &"b".repeat(64),
            &hash_bytes(b"https://app.example.com:443"),
            &session,
            &vault,
            NOW + 2,
        ),
        Err(SessionInjectionError::SecretExpired)
    ));
}

#[test]
fn secret_values_never_enter_serialized_or_debug_material() {
    let (vault, session, manifest, certificate, key_pair) = fixture();
    let bound = bind_for_test(
        manifest,
        &certificate,
        key_pair.public_key().as_ref(),
        &"b".repeat(64),
        &hash_bytes(b"https://app.example.com:443"),
        &session,
        &vault,
        NOW + 1,
    )
    .unwrap();
    let material = format!(
        "{:?}{}{}",
        bound,
        serde_json::to_string(bound.manifest()).unwrap(),
        serde_json::to_string(&certificate).unwrap()
    );
    for secret in ["bearer-secret", "csrf-secret", "cookie-secret"] {
        assert!(!material.contains(secret));
    }
}
