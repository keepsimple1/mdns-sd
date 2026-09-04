//! Fuzzes the mDNS packet parser.
//!
//! `ServiceDaemon` hands `DnsIncoming` the bytes it reads off a UDP socket
//! without inspecting them first, so every byte here is reachable by any host on
//! the link. Malformed input is expected; the target looks for panics, hangs,
//! and self-contradictory results.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run parse_packet
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    mdns_sd::fuzz_api::parse_packet(data);
});
