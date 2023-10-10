# mdns-sd

[![Build](https://github.com/keepsimple1/mdns-sd/actions/workflows/build.yml/badge.svg)](https://github.com/keepsimple1/mdns-sd/actions)
[![Cargo](https://img.shields.io/crates/v/mdns-sd.svg)](https://crates.io/crates/mdns-sd)
[![docs.rs](https://img.shields.io/docsrs/mdns-sd)](https://docs.rs/mdns-sd/latest/mdns_sd/)

This is a small implementation of mDNS (Multicast DNS) based service discovery in safe Rust, with a small set of dependencies. Some highlights:

- supports both the client (querier) and the server (responder) uses.
- supports macOS, Linux and Windows.
- supports IPv4 and IPv6.
- works with both sync and async code.
- no dependency on any async runtimes.

## Approach

We are not using async/.await internally, instead we create a new thread to run a mDNS daemon.

The API interacts with the daemon via [`flume`](https://crates.io/crates/flume) channels that work easily with both sync and async code. For more details, please see the [documentation](https://docs.rs/mdns-sd).

## Compatibility and Limitations

This implementation is based on the following RFCs:
- mDNS:   [RFC 6762](https://tools.ietf.org/html/rfc6762)
- DNS-SD: [RFC 6763](https://tools.ietf.org/html/rfc6763)
- DNS:    [RFC 1035](https://tools.ietf.org/html/rfc1035)

This is still beta software. We focus on the common use cases at hand. And we tested with some existing common tools (e.g. `Avahi` on Linux, `dns-sd` on MacOS, and `Bonjour` library on iOS) to verify the basic compatibility.

Currently this library has the following limitations:
- Only support multicast, no unicast send/recv.

## Minimum Rust version

Tested against Rust 1.60.0

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Contributions are welcome! Please open an issue in GitHub if any questions.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the above license(s), shall be
dual licensed as above, without any additional terms or conditions.
