use crate::{
    Http1Error, Http1Framing, Http1Header, Http1Limits, Http1Response, Http1Version,
};

pub(crate) enum ParseProgress {
    Incomplete,
    Complete(ParsedResponse),
}

pub(crate) struct ParsedResponse {
    pub response: Http1Response,
    pub consumed_wire_bytes: usize,
}

pub(crate) fn parse_response(
    bytes: &[u8],
    eof: bool,
    request_method: &str,
    limits: &Http1Limits,
) -> Result<ParseProgress, Http1Error> {
    let mut offset = 0usize;
    let mut interim_responses = 0u64;

    loop {
        let relative_end = match find_double_crlf(&bytes[offset..]) {
            Some(value) => value,
            None => {
                if bytes.len().saturating_sub(offset)
                    > limits.maximum_response_header_bytes as usize
                {
                    return Err(Http1Error::InvalidResponse(
                        "response header block exceeds configured limit".into(),
                    ));
                }
                if eof {
                    return Err(Http1Error::TruncatedResponse(
                        "response header block ended before CRLFCRLF".into(),
                    ));
                }
                return Ok(ParseProgress::Incomplete);
            }
        };
        let head_end = offset
            .checked_add(relative_end)
            .ok_or_else(|| Http1Error::InvalidResponse("header offset overflow".into()))?;
        let head = &bytes[offset..head_end];
        if head.len() > limits.maximum_response_header_bytes as usize {
            return Err(Http1Error::InvalidResponse(
                "response header block exceeds configured limit".into(),
            ));
        }
        validate_crlf_block(head)?;
        let lines = split_crlf(&head[..head.len() - 4]);
        let status_line = lines
            .first()
            .ok_or_else(|| Http1Error::InvalidResponse("missing status line".into()))?;
        let (version, status_code, reason) = parse_status_line(status_line)?;
        let headers = parse_header_lines(&lines[1..], limits, false)?;

        if (100..200).contains(&status_code) {
            if status_code == 101 {
                return Err(Http1Error::InvalidResponse(
                    "protocol upgrades are not supported".into(),
                ));
            }
            interim_responses = interim_responses.saturating_add(1);
            if interim_responses > limits.maximum_interim_responses {
                return Err(Http1Error::InvalidResponse(
                    "interim response count exceeds configured limit".into(),
                ));
            }
            offset = head_end;
            if offset >= bytes.len() {
                if eof {
                    return Err(Http1Error::TruncatedResponse(
                        "stream ended after interim response".into(),
                    ));
                }
                return Ok(ParseProgress::Incomplete);
            }
            continue;
        }

        let framing = determine_framing(request_method, version, status_code, &headers)?;
        let body_start = head_end;
        let parsed_body = match framing {
            Http1Framing::NoBody => ParsedBody {
                body: Vec::new(),
                trailers: Vec::new(),
                consumed: 0,
            },
            Http1Framing::ContentLength(length) => {
                if length > limits.maximum_response_body_bytes {
                    return Err(Http1Error::InvalidResponse(
                        "Content-Length exceeds configured body limit".into(),
                    ));
                }
                let length = usize::try_from(length).map_err(|_| {
                    Http1Error::InvalidResponse("Content-Length cannot fit in memory".into())
                })?;
                let available = bytes.len().saturating_sub(body_start);
                if available < length {
                    if eof {
                        return Err(Http1Error::TruncatedResponse(format!(
                            "Content-Length promised {length} bytes but only {available} arrived"
                        )));
                    }
                    return Ok(ParseProgress::Incomplete);
                }
                ParsedBody {
                    body: bytes[body_start..body_start + length].to_vec(),
                    trailers: Vec::new(),
                    consumed: length,
                }
            }
            Http1Framing::Chunked => match parse_chunked(&bytes[body_start..], eof, limits)? {
                Some(value) => value,
                None => return Ok(ParseProgress::Incomplete),
            },
            Http1Framing::ConnectionClose => {
                if !eof {
                    return Ok(ParseProgress::Incomplete);
                }
                let body = bytes[body_start..].to_vec();
                if body.len() as u64 > limits.maximum_response_body_bytes {
                    return Err(Http1Error::InvalidResponse(
                        "connection-close body exceeds configured limit".into(),
                    ));
                }
                ParsedBody {
                    consumed: body.len(),
                    body,
                    trailers: Vec::new(),
                }
            }
        };

        let consumed_wire_bytes = body_start
            .checked_add(parsed_body.consumed)
            .ok_or_else(|| Http1Error::InvalidResponse("response length overflow".into()))?;
        return Ok(ParseProgress::Complete(ParsedResponse {
            consumed_wire_bytes,
            response: Http1Response {
                version,
                status_code,
                reason,
                headers,
                trailers: parsed_body.trailers,
                body: parsed_body.body,
                framing,
                interim_responses,
            },
        }));
    }
}

struct ParsedBody {
    body: Vec<u8>,
    trailers: Vec<Http1Header>,
    consumed: usize,
}

fn parse_status_line(line: &[u8]) -> Result<(Http1Version, u16, Vec<u8>), Http1Error> {
    if line.contains(&b'\t') {
        return Err(Http1Error::InvalidResponse(
            "status line contains horizontal tab".into(),
        ));
    }
    let first_space = line
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or_else(|| Http1Error::InvalidResponse("status line is missing status code".into()))?;
    let version = match &line[..first_space] {
        b"HTTP/1.0" => Http1Version::Http10,
        b"HTTP/1.1" => Http1Version::Http11,
        _ => {
            return Err(Http1Error::InvalidResponse(
                "unsupported or malformed HTTP version".into(),
            ))
        }
    };
    let remainder = &line[first_space + 1..];
    if remainder.len() < 3 || !remainder[..3].iter().all(u8::is_ascii_digit) {
        return Err(Http1Error::InvalidResponse(
            "status code must contain exactly three digits".into(),
        ));
    }
    if remainder.len() > 3 && remainder[3] != b' ' {
        return Err(Http1Error::InvalidResponse(
            "status code must be followed by a single space".into(),
        ));
    }
    let status_code = ((remainder[0] - b'0') as u16) * 100
        + ((remainder[1] - b'0') as u16) * 10
        + (remainder[2] - b'0') as u16;
    if !(100..=999).contains(&status_code) {
        return Err(Http1Error::InvalidResponse(
            "status code is outside the supported range".into(),
        ));
    }
    let reason = if remainder.len() > 3 {
        let value = remainder[4..].to_vec();
        validate_reason_phrase(&value)?;
        value
    } else {
        Vec::new()
    };
    Ok((version, status_code, reason))
}

fn validate_reason_phrase(value: &[u8]) -> Result<(), Http1Error> {
    if value
        .iter()
        .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(Http1Error::InvalidResponse(
            "reason phrase contains prohibited control bytes".into(),
        ));
    }
    Ok(())
}

fn parse_header_lines(
    lines: &[&[u8]],
    limits: &Http1Limits,
    trailers: bool,
) -> Result<Vec<Http1Header>, Http1Error> {
    if lines.len() as u64 > if trailers {
        limits.maximum_trailer_count
    } else {
        limits.maximum_header_count
    } {
        return Err(Http1Error::InvalidResponse(if trailers {
            "trailer count exceeds configured limit".into()
        } else {
            "header count exceeds configured limit".into()
        }));
    }

    let mut output = Vec::with_capacity(lines.len());
    for line in lines {
        if line.is_empty() {
            return Err(Http1Error::InvalidResponse(
                "unexpected empty header line".into(),
            ));
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(Http1Error::InvalidResponse(
                "obsolete folded headers are prohibited".into(),
            ));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| Http1Error::InvalidResponse("header is missing colon".into()))?;
        if colon == 0 {
            return Err(Http1Error::InvalidResponse(
                "header name is empty".into(),
            ));
        }
        let name = &line[..colon];
        if name.len() as u64 > limits.maximum_header_name_bytes {
            return Err(Http1Error::InvalidResponse(
                "header name exceeds configured limit".into(),
            ));
        }
        if !name.iter().copied().all(is_token_byte) {
            return Err(Http1Error::InvalidResponse(
                "header name contains invalid bytes or whitespace before colon".into(),
            ));
        }
        let name = ascii_lower(name);
        if trailers && is_prohibited_trailer(&name) {
            return Err(Http1Error::InvalidResponse(format!(
                "prohibited trailer field: {name}"
            )));
        }
        let value = trim_ows(&line[colon + 1..]);
        if value.len() as u64 > limits.maximum_header_value_bytes {
            return Err(Http1Error::InvalidResponse(
                "header value exceeds configured limit".into(),
            ));
        }
        validate_field_value(value)?;
        output.push(Http1Header {
            name,
            value: value.to_vec(),
        });
    }
    Ok(output)
}

fn determine_framing(
    request_method: &str,
    version: Http1Version,
    status_code: u16,
    headers: &[Http1Header],
) -> Result<Http1Framing, Http1Error> {
    if request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status_code)
        || matches!(status_code, 204 | 304)
    {
        return Ok(Http1Framing::NoBody);
    }

    let content_length = parse_content_length(headers)?;
    let transfer_encoding = parse_transfer_encoding(headers)?;
    if content_length.is_some() && transfer_encoding {
        return Err(Http1Error::InvalidResponse(
            "Transfer-Encoding and Content-Length cannot coexist".into(),
        ));
    }
    if transfer_encoding {
        if version != Http1Version::Http11 {
            return Err(Http1Error::InvalidResponse(
                "chunked transfer coding requires HTTP/1.1".into(),
            ));
        }
        return Ok(Http1Framing::Chunked);
    }
    if let Some(length) = content_length {
        return Ok(Http1Framing::ContentLength(length));
    }
    Ok(Http1Framing::ConnectionClose)
}

fn parse_content_length(headers: &[Http1Header]) -> Result<Option<u64>, Http1Error> {
    let mut values = Vec::new();
    for header in headers
        .iter()
        .filter(|header| header.name == "content-length")
    {
        let text = std::str::from_utf8(&header.value).map_err(|_| {
            Http1Error::InvalidResponse("Content-Length must contain ASCII digits".into())
        })?;
        for component in text.split(',') {
            let component = component.trim_matches([' ', '\t']);
            if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(Http1Error::InvalidResponse(
                    "Content-Length contains a non-decimal value".into(),
                ));
            }
            let value = component.parse::<u64>().map_err(|_| {
                Http1Error::InvalidResponse("Content-Length integer overflow".into())
            })?;
            values.push(value);
        }
    }
    let Some(first) = values.first().copied() else {
        return Ok(None);
    };
    if values.iter().any(|value| *value != first) {
        return Err(Http1Error::InvalidResponse(
            "conflicting Content-Length values".into(),
        ));
    }
    Ok(Some(first))
}

fn parse_transfer_encoding(headers: &[Http1Header]) -> Result<bool, Http1Error> {
    let mut tokens = Vec::new();
    for header in headers
        .iter()
        .filter(|header| header.name == "transfer-encoding")
    {
        let text = std::str::from_utf8(&header.value).map_err(|_| {
            Http1Error::InvalidResponse("Transfer-Encoding must be ASCII".into())
        })?;
        for component in text.split(',') {
            let token = component.trim_matches([' ', '\t']).to_ascii_lowercase();
            if token.is_empty() || !token.bytes().all(is_token_byte) {
                return Err(Http1Error::InvalidResponse(
                    "Transfer-Encoding contains an invalid token".into(),
                ));
            }
            tokens.push(token);
        }
    }
    if tokens.is_empty() {
        return Ok(false);
    }
    if tokens.len() != 1 || tokens[0] != "chunked" {
        return Err(Http1Error::InvalidResponse(
            "only one final chunked transfer coding is supported".into(),
        ));
    }
    Ok(true)
}

fn parse_chunked(
    bytes: &[u8],
    eof: bool,
    limits: &Http1Limits,
) -> Result<Option<ParsedBody>, Http1Error> {
    let mut cursor = 0usize;
    let mut decoded = Vec::new();
    let mut chunks = 0u64;

    loop {
        let line_end = match find_crlf(&bytes[cursor..]) {
            Some(value) => cursor + value,
            None => {
                if bytes.len().saturating_sub(cursor) > 128 {
                    return Err(Http1Error::InvalidResponse(
                        "chunk-size line exceeds 128 bytes".into(),
                    ));
                }
                if eof {
                    return Err(Http1Error::TruncatedResponse(
                        "chunk-size line ended before CRLF".into(),
                    ));
                }
                return Ok(None);
            }
        };
        let line = &bytes[cursor..line_end];
        if line.contains(&b';') {
            return Err(Http1Error::InvalidResponse(
                "chunk extensions are intentionally unsupported".into(),
            ));
        }
        if line.is_empty() || line.len() > 16 || !line.iter().all(u8::is_ascii_hexdigit) {
            return Err(Http1Error::InvalidResponse(
                "chunk size must be 1-16 hexadecimal digits".into(),
            ));
        }
        let line_text = std::str::from_utf8(line).map_err(|_| {
            Http1Error::InvalidResponse("chunk size must be ASCII".into())
        })?;
        let chunk_size = u64::from_str_radix(line_text, 16)
            .map_err(|_| Http1Error::InvalidResponse("chunk size overflow".into()))?;
        cursor = line_end + 2;

        if chunk_size == 0 {
            if bytes.len().saturating_sub(cursor) < 2 {
                if eof {
                    return Err(Http1Error::TruncatedResponse(
                        "zero chunk was not followed by a trailer terminator".into(),
                    ));
                }
                return Ok(None);
            }
            if &bytes[cursor..cursor + 2] == b"\r\n" {
                cursor += 2;
                return Ok(Some(ParsedBody {
                    body: decoded,
                    trailers: Vec::new(),
                    consumed: cursor,
                }));
            }
            let trailer_end = match find_double_crlf(&bytes[cursor..]) {
                Some(value) => cursor + value,
                None => {
                    if bytes.len().saturating_sub(cursor)
                        > limits.maximum_trailer_bytes as usize
                    {
                        return Err(Http1Error::InvalidResponse(
                            "trailer block exceeds configured limit".into(),
                        ));
                    }
                    if eof {
                        return Err(Http1Error::TruncatedResponse(
                            "trailer block ended before CRLFCRLF".into(),
                        ));
                    }
                    return Ok(None);
                }
            };
            let trailer_block = &bytes[cursor..trailer_end];
            if trailer_block.len() > limits.maximum_trailer_bytes as usize {
                return Err(Http1Error::InvalidResponse(
                    "trailer block exceeds configured limit".into(),
                ));
            }
            validate_crlf_block(trailer_block)?;
            let trailer_lines = split_crlf(&trailer_block[..trailer_block.len() - 4]);
            let trailers = parse_header_lines(&trailer_lines, limits, true)?;
            cursor = trailer_end;
            return Ok(Some(ParsedBody {
                body: decoded,
                trailers,
                consumed: cursor,
            }));
        }

        chunks = chunks.saturating_add(1);
        if chunks > limits.maximum_chunk_count {
            return Err(Http1Error::InvalidResponse(
                "chunk count exceeds configured limit".into(),
            ));
        }
        if chunk_size > limits.maximum_chunk_bytes {
            return Err(Http1Error::InvalidResponse(
                "chunk size exceeds configured limit".into(),
            ));
        }
        if (decoded.len() as u64).saturating_add(chunk_size)
            > limits.maximum_response_body_bytes
        {
            return Err(Http1Error::InvalidResponse(
                "decoded chunked body exceeds configured limit".into(),
            ));
        }
        let chunk_size = usize::try_from(chunk_size)
            .map_err(|_| Http1Error::InvalidResponse("chunk size cannot fit in memory".into()))?;
        let chunk_end = cursor
            .checked_add(chunk_size)
            .ok_or_else(|| Http1Error::InvalidResponse("chunk offset overflow".into()))?;
        let suffix_end = chunk_end
            .checked_add(2)
            .ok_or_else(|| Http1Error::InvalidResponse("chunk suffix overflow".into()))?;
        if bytes.len() < suffix_end {
            if eof {
                return Err(Http1Error::TruncatedResponse(
                    "chunk data ended before declared size or CRLF".into(),
                ));
            }
            return Ok(None);
        }
        if &bytes[chunk_end..suffix_end] != b"\r\n" {
            return Err(Http1Error::InvalidResponse(
                "chunk data is not followed by CRLF".into(),
            ));
        }
        decoded.extend_from_slice(&bytes[cursor..chunk_end]);
        cursor = suffix_end;
    }
}

fn find_double_crlf(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

fn validate_crlf_block(bytes: &[u8]) -> Result<(), Http1Error> {
    for (index, byte) in bytes.iter().enumerate() {
        match *byte {
            b'\n' if index == 0 || bytes[index - 1] != b'\r' => {
                return Err(Http1Error::InvalidResponse(
                    "bare LF is prohibited".into(),
                ));
            }
            b'\r' if index + 1 >= bytes.len() || bytes[index + 1] != b'\n' => {
                return Err(Http1Error::InvalidResponse(
                    "bare CR is prohibited".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn split_crlf(mut bytes: &[u8]) -> Vec<&[u8]> {
    let mut output = Vec::new();
    loop {
        match find_crlf(bytes) {
            Some(index) => {
                output.push(&bytes[..index]);
                bytes = &bytes[index + 2..];
            }
            None => {
                output.push(bytes);
                break;
            }
        }
    }
    output
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn validate_field_value(value: &[u8]) -> Result<(), Http1Error> {
    if value
        .iter()
        .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(Http1Error::InvalidResponse(
            "header value contains prohibited control bytes".into(),
        ));
    }
    Ok(())
}

fn ascii_lower(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| (*byte as char).to_ascii_lowercase())
        .collect()
}

pub(crate) fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_prohibited_trailer(name: &str) -> bool {
    matches!(
        name,
        "content-length"
            | "transfer-encoding"
            | "host"
            | "connection"
            | "trailer"
            | "upgrade"
            | "proxy-connection"
    )
}
