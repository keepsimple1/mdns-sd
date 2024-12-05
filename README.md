# mdns-sd

[![Build](https://github.com/keepsimple1/mdns-sd/actions/workflows/build.yml/badge.svg)](https://github.com/keepsimple1/mdns-sd/actions)
[![Cargo](https://img.shields.io/crates/v/mdns-sd.svg)](https://crates.io/crates/mdns-sd)
[![docs.rs](https://img.shields.io/docsrs/mdns-sd)](https://docs.rs/mdns-sd/latest/mdns_sd/)
[![Rust version: 1.70+](https://img.shields.io/badge/rust%20version-1.70+-orange)](https://blog.rust-lang.org/2022/08/11/Rust-1.70.0.html)

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

The following table shows how much this implementation is compliant with RFCs regarding major features:

| Feature | RFC section | Compliance | Notes |
| ------- | ----------- | ---------- | ----- |
| One-Shot Multicast DNS Queries (i.e. Legacy Unicast Responses) | RFC 6762 [section 5.1][ref1] [section 6.7][ref9] | ❌ | because we don't support Unicast yet. |
| Unicast Responses | RFC 6762 [section 5.4][ref2] | ❌ |
| Known-Answer Suppression | RFC 6762 [section 7.1][ref3] | ✅ |
| Multipacket Known Answer Suppression querier | RFC 6762 [section 7.2][ref4] | ✅ |
| Multipacket Known Answer Suppression responder | RFC 6762 [section 7.2][ref4] | ❌ | because we don't support Unicast yet. |
| Probing | RFC 6762 [section 8.1][ref5] | ✅ |
| Simultaneous Probe Tiebreaking | RFC 6762 [section 8.2][ref6] | ✅ |
| Conflict Resolution | RFC 6762 [section 9][ref7] | ✅ | see `DnsNameChange` type |
| Goodbye Packets | RFC 6762 [section 10.1][ref10] | ✅ |
| Announcements to Flush Outdated Cache Entries | RFC 6762 [section 10.2][ref11] | ✅ | i.e. `cache-flush` bit |
| Cache Flush on Failure Indication | RFC 6762 [section 10.4][ref8] | ✅ | API: `ServiceDaemon::verify()` |

[ref1]: https://datatracker.ietf.org/doc/html/rfc6762#section-5.1
[ref2]: https://datatracker.ietf.org/doc/html/rfc6762#section-5.4
[ref3]: https://datatracker.ietf.org/doc/html/rfc6762#section-7.1
[ref4]: https://datatracker.ietf.org/doc/html/rfc6762#section-7.2
[ref5]: https://datatracker.ietf.org/doc/html/rfc6762#section-8.1
[ref6]: https://datatracker.ietf.org/doc/html/rfc6762#section-8.2
[ref7]: https://datatracker.ietf.org/doc/html/rfc6762#section-9
[ref8]: https://datatracker.ietf.org/doc/html/rfc6762#section-10.4
[ref9]: https://datatracker.ietf.org/doc/html/rfc6762#section-6.7
[ref10]: https://datatracker.ietf.org/doc/html/rfc6762#section-10.1
[ref11]: https://datatracker.ietf.org/doc/html/rfc6762#section-10.2

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
