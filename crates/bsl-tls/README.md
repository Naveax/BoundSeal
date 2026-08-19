# nxb-tls

`nxb-tls` is a networkless TLS peer-identity contract. It verifies synthetic handshake and certificate-chain metadata only after a permit-bound `BoundedByteStream` exists.

The crate enforces HTTPS/SNI binding, TLS 1.2 or 1.3, `http/1.1` ALPN, bounded handshake resources, SAN-only DNS identity, conservative wildcard matching, certificate validity, CA/key-usage linkage and explicit root trust.

It does not parse X.509 DER, perform cryptographic signatures, open sockets, negotiate TLS or access the public network. A future TLS backend must produce observations that satisfy this frozen contract before any HTTP codec can consume a TLS session grant.
