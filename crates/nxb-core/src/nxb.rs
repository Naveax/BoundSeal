#![forbid(unsafe_code)]

mod diagnostic;
#[allow(dead_code, unused_imports)] // NXB-153/#108 staging; remove when target wiring lands.
mod directory_authority;
mod release_manifest;
mod target;
mod workspace;

include!("main.rs");