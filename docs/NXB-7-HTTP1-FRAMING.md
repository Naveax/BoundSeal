# NXB-7 — Bounded HTTP/1 Framing Contract

## Purpose

NXB-7 introduces a deterministic HTTP/1.1 codec above `BoundedByteStream`. It does not resolve names, choose destinations, create sockets, negotiate TLS, follow redirects, manage sessions, or run scanners.

The codec accepts only an already-open bounded stream. The HTTP `Host` authority is derived from the immutable `StreamGrant`; callers cannot provide or override it.

## Request contract

The request encoder supports bounded origin-form requests and deliberately excludes ambiguous connection semantics.

- methods must be uppercase HTTP tokens
- `CONNECT` and absolute-form targets are unsupported
- fragments, whitespace and control bytes are rejected from targets
- caller-provided `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `TE`, `Trailer`, `Expect`, `Upgrade`, and `Proxy-Connection` are rejected
- the codec injects exactly one `Host`, one decimal `Content-Length`, and `Connection: close`
- request headers and bodies are bounded before the first stream write
- partial writes and backpressure are handled through bounded retry counters

## Response framing order

The parser performs the following checks before a response body is accepted:

1. exact CRLF framing; bare CR and bare LF are rejected
2. bounded status line and header block
3. token-only header names with no whitespace before `:`
4. no obsolete folded header lines
5. bounded header names, values and count
6. identical-only duplicate `Content-Length` values
7. a single final `chunked` transfer coding only
8. unconditional rejection of `Transfer-Encoding` plus `Content-Length`
9. method/status no-body rules
10. bounded Content-Length, chunked, or connection-close body handling

## Chunked contract

- chunk size is 1–16 hexadecimal digits
- chunk extensions are intentionally unsupported
- every chunk must end in CRLF
- chunk count, individual chunk size and decoded body size are bounded
- zero chunk is mandatory
- trailers are separately bounded
- framing-sensitive trailer fields are prohibited

## Stream and connection behavior

One codec instance performs one exchange. The request includes `Connection: close`, and the bounded stream is closed after the response is framed. Extra bytes after the framed response are rejected rather than interpreted as a second response.

Interim responses are supported up to a configured limit. `101 Switching Protocols` is rejected because protocol upgrades are outside this contract.

## Audit contract

The HTTP audit chain is anchored to the stream audit tail present when the codec is constructed. Each exchange records:

- stream and execution identity
- request method
- hashes of request target, wire bytes and body
- request header/body counts
- hashes of response wire bytes and decoded body
- response status, version and framing type
- response header/trailer/body counts
- interim response count
- stream audit hash before and after the exchange

Raw request bodies, response bodies, cookies, tokens and header values are not fields in the HTTP audit schema.

## Explicit exclusions

NXB-7 does not add:

- real TCP, UDP or QUIC I/O
- TLS handshakes or certificate verification
- HTTP/2 or HTTP/3
- redirects
- proxies
- cookies or session vaults
- decompression
- WebSocket or upgrade support
- scanner adapters
- public-network execution
