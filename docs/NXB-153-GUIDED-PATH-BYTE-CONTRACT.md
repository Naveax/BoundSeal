# NXB-153 Guided Path Byte Contract

## Status

This document records the source-staged path-byte boundary for NXB-153 guided target setup. It does **not** claim that the current feature head has passed the required Rust/Linux/Windows validation.

## Problem

The legacy target path validator defines structural path-prefix rules such as leading `/`, no traversal, no repeated separators, no percent syntax and no query/fragment syntax. That generic contract historically did not define one narrow literal URL-byte alphabet.

For an authorization-bound guided workflow, two ambiguity classes are avoidable and therefore rejected:

1. raw Unicode path text can have multiple normalization forms and request layers commonly convert it to UTF-8 percent-encoded bytes;
2. ASCII characters outside RFC3986 path `pchar` syntax, such as `"`, `[`, `]`, `{`, `}`, `|`, `^`, backtick and angle brackets, require parser/serializer encoding decisions before becoming request-path bytes.

A preview/profile prefix must not depend on any unspecified future URL normalization policy.

## NXB-153 guided boundary

NXB-153 therefore uses a narrower path-byte contract than legacy `target create`.

Every guided include/exclude prefix must first satisfy the inherited structural path validator. The guided layer then requires each literal byte to be one of:

- ASCII letters or digits;
- `/` as the path-segment separator;
- RFC3986 unreserved punctuation: `- . _ ~`;
- admitted RFC3986 `pchar` punctuation: `! $ & ' ( ) + , ; = : @`.

The guided layer intentionally continues to reject `%` and `*` even though percent-encoded triplets and `*` can appear in broader URI grammars. NXB-153 does not accept alternate encoded spellings or wildcard-like scope syntax.

Therefore the effective guided grammar is a literal, already-decoded, RFC3986-safe ASCII path-prefix representation. Manual setup, bounded import, preview and activation all pass through the same guided admission/preflight. Non-ASCII or non-literal path syntax is rejected before preview admission and before activation persistence.

The legacy generic target path validator is not silently rewritten by this Pass E hardening.

## Why this is fail-closed

Later request/session work must compare scope and actual request paths under one explicit byte contract. Accepting characters that first require IDNA-like, Unicode, percent-encoding or URL-parser normalization would make the authorization preview and request boundary representation-dependent.

Future Unicode or percent-encoded path support therefore requires one documented byte-level normalization contract shared by scope admission, URL construction, redirect handling, request execution and evidence verification. Until that exists, literal RFC3986-safe ASCII is the guided product boundary.

## Acceptance staged in source

`target_unicode_path_failclosed_cli` now stages:

1. manual guided Unicode path rejection;
2. manual rejection of ASCII characters outside the admitted RFC3986-safe set;
3. bounded-import rejection for both Unicode and non-literal ASCII path forms;
4. a positive control proving the documented admitted punctuation remains usable;
5. empty `targets/` and `state/` mutation surfaces after every rejected setup.

`target_persistence_envelope_cli` no longer uses invalid quote-heavy paths to exercise serialization growth. Its oversized fixture uses 61 include/exclude pairs made only from admitted literal path bytes, remains below the 64 KiB import parser cap, and is expected to exceed the 60 KiB guided persistence envelope.

The exact final feature head must still pass the complete Linux + Windows NXB-153 validation closure before issue #97 or the milestone can be admitted.
