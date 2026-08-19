# bsl-redirect

Strict, audit-bound redirect planning for BSL.

The crate resolves one `Location` field at a time, applies explicit HTTP method/body transformation rules, rejects HTTPS downgrades and loops, requires a fresh DNS context for every hop, and re-enters `ScopeGateway` through `PinnedTransportCoordinator` before returning a usable next step.

Cross-origin hops never forward an existing credential header batch. They permit only fresh cookie rematerialization from the latest session generation. The crate contains no resolver, socket, HTTP client, browser, proxy, scanner, or public-network implementation.
