#![no_main]

use chksum_hash_sha2_256 as sha2_256;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sha2_256::hash(data);
});
