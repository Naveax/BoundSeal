#![forbid(unsafe_code)]

mod diagnostic;
mod directory_authority;
mod prepared_file_authority;
mod release_manifest;
mod target;
#[path = "workspace/mod.rs"]
mod workspace_impl;
#[path = "workspace_authority.rs"]
mod workspace_authority_base;
#[path = "workspace_authority_entry.rs"]
mod workspace;
mod workspace_authority_publication;
mod workspace_authority_receipts;
mod workspace_authority_records;
#[cfg(target_os = "linux")]
mod workspace_authority_replacement;

include!("main.rs");