# nxb-channel-contracts

Networkless contracts for NXB-12 through NXB-15: TLS-gated HTTP channel authority, typed request construction, bounded body sources and immutable response envelopes.

The crate opens no sockets, performs no DNS, negotiates no TLS and sends no requests. It converts already-authorized stream/TLS metadata into one-use channel capabilities and bounded request/response receipts.
