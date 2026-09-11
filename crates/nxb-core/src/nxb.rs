#![forbid(unsafe_code)]

mod diagnostic;
mod directory_authority;
mod release_manifest;
mod target;
#[path = "workspace/mod.rs"]
mod workspace_impl;
#[path = "workspace_authority.rs"]
mod workspace;
mod workspace_authority_receipts;
mod workspace_authority_records;

include!("main.rs");