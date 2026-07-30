use crate::{audit::hex_sha256, model::TlsRejectionReason};

pub(crate) struct IdentityMatch {
    pub normalized_sni: String,
    pub matched_san_sha256: String,
}

pub(crate) fn normalize_dns_name(value: &str) -> Result<String, TlsRejectionReason> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || !normalized.is_ascii()
        || normalized.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(TlsRejectionReason::InvalidSni);
    }
    let labels = normalized.split('.').collect::<Vec<_>>();
    if labels.len() < 2 || labels.iter().any(|label| !valid_label(label)) {
        return Err(TlsRejectionReason::InvalidSni);
    }
    Ok(normalized)
}

pub(crate) fn expected_http_authority(sni: &str, port: u16) -> String {
    if port == 443 {
        sni.to_string()
    } else {
        format!("{sni}:{port}")
    }
}

pub(crate) fn match_dns_san(
    expected_sni: &str,
    sans: &[String],
    maximum_dns_sans: usize,
) -> Result<IdentityMatch, TlsRejectionReason> {
    if sans.is_empty() {
        return Err(TlsRejectionReason::MissingDnsSubjectAlternativeName);
    }
    if sans.len() > maximum_dns_sans {
        return Err(TlsRejectionReason::TooManyDnsSubjectAlternativeNames);
    }

    for san in sans {
        let normalized = normalize_san_pattern(san)?;
        if san_matches(expected_sni, &normalized) {
            return Ok(IdentityMatch {
                normalized_sni: expected_sni.to_string(),
                matched_san_sha256: hex_sha256(normalized.as_bytes()),
            });
        }
    }
    Err(TlsRejectionReason::HostnameMismatch)
}

fn normalize_san_pattern(value: &str) -> Result<String, TlsRejectionReason> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 || !normalized.is_ascii() {
        return Err(TlsRejectionReason::InvalidDnsSubjectAlternativeName);
    }
    if let Some(base) = normalized.strip_prefix("*.") {
        if base.contains('*') || !valid_dns_name(base) || wildcard_base_is_too_broad(base) {
            return Err(TlsRejectionReason::InvalidDnsSubjectAlternativeName);
        }
        return Ok(normalized);
    }
    if normalized.contains('*') || !valid_dns_name(&normalized) {
        return Err(TlsRejectionReason::InvalidDnsSubjectAlternativeName);
    }
    Ok(normalized)
}

fn san_matches(expected: &str, san: &str) -> bool {
    let Some(base) = san.strip_prefix("*.") else {
        return expected == san;
    };
    let expected_labels = expected.split('.').collect::<Vec<_>>();
    let base_labels = base.split('.').collect::<Vec<_>>();
    expected_labels.len() == base_labels.len() + 1
        && expected.ends_with(&format!(".{base}"))
        && !expected_labels[0].is_empty()
}

fn valid_dns_name(value: &str) -> bool {
    let labels = value.split('.').collect::<Vec<_>>();
    labels.len() >= 2 && labels.iter().all(|label| valid_label(label))
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn wildcard_base_is_too_broad(base: &str) -> bool {
    const PUBLIC_SUFFIX_LIKE: &[&str] = &[
        "com", "net", "org", "edu", "gov", "mil", "int", "io", "dev", "app",
        "co.uk", "org.uk", "ac.uk", "co.jp", "com.tr", "com.au", "co.nz",
    ];
    PUBLIC_SUFFIX_LIKE.contains(&base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matches_exactly_one_label() {
        assert!(san_matches("api.example.com", "*.example.com"));
        assert!(!san_matches("deep.api.example.com", "*.example.com"));
        assert!(!san_matches("example.com", "*.example.com"));
    }

    #[test]
    fn broad_wildcards_are_rejected() {
        assert!(normalize_san_pattern("*.com").is_err());
        assert!(normalize_san_pattern("*.co.uk").is_err());
    }
}
