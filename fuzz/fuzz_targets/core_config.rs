//! `Config::from_toml_str` on arbitrary text (the config file is user-writable input).
#![no_main]

use libfuzzer_sys::fuzz_target;
use petschaft_core::Config;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(config) = Config::from_toml_str(s) {
            // Deterministic: the same text always gives the same config.
            assert_eq!(Config::from_toml_str(s).expect("re-parse"), config);
        }
    }
});
