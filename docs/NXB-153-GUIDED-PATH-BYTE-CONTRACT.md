# NXB-153 Guided Path Byte Contract

## Status

This document records the source-staged path-byte boundary for NXB-153 guided target setup. It does **not** claim that the current feature head has passed the required Rust/Linux/Windows validation.

## Problem

The legacy target path validator defines structural path-prefix rules such as leading `/`, no traversal, no repeated separators, no percent syntax and no query/fragment syntax. That generic contract historically did not require ASCII.

For an authorization-bound guided workflow, accepting raw Unicode path text introduces an avoidable representation ambiguity. The same human-visible path can be represented by different Unicode normalization forms and URL request layers commonly convert non-ASCII path text into UTF-8 percent-encoded bytes. A preview/profile prefix must not depend on an unspecified future normalization policy.

## NXB-153 guided boundary

NXB-153 therefore uses a narrower path-byte contract than legacy `target create`:

- every guided include/exclude prefix must use literal ASCII bytes;
- the ordinary canonical path checks still apply after this restriction;
- percent syntax remains rejected, so the guided layer does not accept an encoded alternate spelling of a non-ASCII path;
- manual setup, bounded import, preview and activation all pass through the same guided persistence/admission preflight;
- non-ASCII scope is rejected before a setup preview can be admitted and before activation persistence can occur;
- the legacy generic target path validator is not broadened or silently rewritten by this Pass E hardening.

The conservative rule is intentional. Future Unicode path support requires one documented byte-level normalization contract shared by scope admission, URL construction, request execution, redirects and evidence verification. Until that exists, literal ASCII is the fail-closed product boundary.

## Acceptance staged in source

`target_unicode_path_failclosed_cli` stages two negative controls:

1. manual guided `/café` scope must fail with the NXB-153 setup diagnostic and leave target/state mutation empty;
2. bounded import using a decomposed Unicode path form must fail through the same guided boundary and leave target/state mutation empty.

The exact final feature head must still pass the complete Linux + Windows NXB-153 validation closure before issue #97 or the milestone can be admitted.
