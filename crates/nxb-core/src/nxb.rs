#![forbid(unsafe_code)]

mod diagnostic;
mod directory_authority;
mod prepared_file_authority;
mod release_manifest;
mod target;
#[cfg(not(windows))]
#[path = "workspace/mod.rs"]
mod workspace_impl;
#[cfg(windows)]
#[path = "workspace_windows_entry.rs"]
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
#[cfg(windows)]
mod workspace_authority_replacement_windows;
mod workspace_doctor_probe;

include!("main.rs");