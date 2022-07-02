#![no_main]
use libfuzzer_sys::fuzz_target;

extern crate rdig;

fuzz_target!(|data: &[u8]| {
    let _ = rdig::Message::deserialize(data);
});
