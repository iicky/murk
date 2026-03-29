#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    // Vault parsing must never panic on arbitrary input.
    let _ = murk_cli::vault::parse(data);
});
