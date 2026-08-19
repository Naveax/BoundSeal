fn parse_html_attributes(input: &str) -> Result<BTreeMap<String, String>, ContentError> {
    let mut output = BTreeMap::new();
    let mut index = input
        .find(char::is_whitespace)
        .unwrap_or(input.len());
    let bytes = input.as_bytes();
    while index < input.len() {
        while index < input.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= input.len() || bytes[index] == b'/' {
            break;
        }
        let name_start = index;
        while index < input.len()
            && !bytes[index].is_ascii_whitespace()
            && !matches!(bytes[index], b'=' | b'/' )
        {
            index += 1;
        }
        let name = input[name_start..index].to_ascii_lowercase();
        if name.is_empty() || !valid_html_attribute_name(&name) {
            return Err(ContentError::InvalidStructuredContent(
                "HTML attribute name is invalid".into(),
            ));
        }
        while index < input.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let value = if index < input.len() && bytes[index] == b'=' {
            index += 1;
            while index < input.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index >= input.len() {
                return Err(ContentError::InvalidStructuredContent(
                    "HTML attribute value is missing".into(),
                ));
            }
            if matches!(bytes[index], b'"' | b'\'') {
                let quote = bytes[index];
                index += 1;
                let start = index;
                while index < input.len() && bytes[index] != quote {
                    index += 1;
                }
                if index >= input.len() {
                    return Err(ContentError::InvalidStructuredContent(
                        "HTML quoted attribute is unterminated".into(),
                    ));
                }
                let value = input[start..index].to_string();
                index += 1;
                value
            } else {
                let start = index;
                while index < input.len()
                    && !bytes[index].is_ascii_whitespace()
                    && bytes[index] != b'/'
                {
                    index += 1;
                }
                input[start..index].to_string()
            }
        } else {
            String::new()
        };
        if value.len() > 8192 {
            return Err(ContentError::ResourceLimit("HTML attribute bytes".into()));
        }
        output.entry(name).or_insert(value);
    }
    Ok(output)
}

fn valid_html_attribute_name(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

fn canonicalize_candidate(base: &Url, raw: &str) -> Result<Url, ContentError> {
    if raw.is_empty()
        || raw.len() > 16 * 1024
        || raw
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(ContentError::InvalidDiscoveredUrl(
            "target is empty, oversized or contains controls".into(),
        ));
    }
    let mut url = base
        .join(raw)
        .map_err(|_| ContentError::InvalidDiscoveredUrl("URL resolution failed".into()))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ContentError::InvalidDiscoveredUrl(
            "only credential-free HTTP(S) URLs are accepted".into(),
        ));
    }
    url.set_fragment(None);
    Ok(url)
}

fn origin(url: &Url) -> Result<String, ContentError> {
    let host = url
        .host_str()
        .ok_or_else(|| ContentError::InvalidDiscoveredUrl("URL lacks host".into()))?
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| ContentError::InvalidDiscoveredUrl("URL lacks effective port".into()))?;
    Ok(format!("{}://{}:{}", url.scheme(), host, port))
}

fn validate_sha256(value: &str) -> Result<(), ContentError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContentError::InvalidEncoding(
            "digest must be lowercase SHA-256".into(),
        ));
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
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

