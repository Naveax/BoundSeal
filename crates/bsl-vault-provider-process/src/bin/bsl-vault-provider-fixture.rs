#![forbid(unsafe_code)]

fn main() {
    if bsl_vault_provider_process::fixture::run().is_err() {
        std::process::exit(1);
    }
}
