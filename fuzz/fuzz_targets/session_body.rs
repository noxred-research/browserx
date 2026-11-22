//! `session_body` fuzz target: libFuzzer entry under `cargo fuzz`, stdin replay
//! otherwise. The body lives in `browserx_fuzz::session_body`.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| browserx_fuzz::session_body(data));

#[cfg(not(fuzzing))]
fn main() {
    browserx_fuzz::run_stdin(browserx_fuzz::session_body);
}
