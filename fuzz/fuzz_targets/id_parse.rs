//! `id_parse` fuzz target: libFuzzer entry under `cargo fuzz`, stdin replay
//! otherwise. The body lives in `browserx_fuzz::id_parse`.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| browserx_fuzz::id_parse(data));

#[cfg(not(fuzzing))]
fn main() {
    browserx_fuzz::run_stdin(browserx_fuzz::id_parse);
}
