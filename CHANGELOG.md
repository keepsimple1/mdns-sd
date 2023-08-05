# Version 0.7.4

* Not to use link-local addrs if routable addrs exist (#117)

# Version 0.7.3

## Highlights

- Internal refactoring: always use DnsCache to resolve Servive Instances. When processing incoming packets,
we used to update the cache one record at a time and also build separate service info structs to resolve. Now we finish the cache updates first, and then resolve instances from the cache.

- Added env_logger for the examples code and enhanced the examples as well.

## What's Changed

* Support updating instances after they are resolved by @keepsimple1 in https://github.com/keepsimple1/mdns-sd/pull/104
* add optional "unregister" in example code by @keepsimple1 in https://github.com/keepsimple1/mdns-sd/pull/107
* Returns an error with logging for read_name invalid offset by @keepsimple1 in https://github.com/keepsimple1/mdns-sd/pull/109
* register example should keep running by @keepsimple1 in https://github.com/keepsimple1/mdns-sd/pull/110
* Refactoring DnsCache and how to resolve Service Instance by @keepsimple1 in https://github.com/keepsimple1/mdns-sd/pull/108
* add sanity check in reading a record data RDATA by @keepsimple1 in https://github.com/keepsimple1/mdns-sd/pull/111
* Enable logging for the examples by @keepsimple1 in https://github.com/keepsimple1/mdns-sd/pull/112
* register example: a simpler input for the service type by @keepsimple1 in https://github.com/keepsimple1/mdns-sd/pull/113


# Version 0.7.2

Highlights:

- Implemented `Display` trait for `TxtProperty`: print using
`key=value` format, where `value` is same as `.get_property_val_str()`.

- Implemented `Debug` trait for `TxtProperty`: print using
a struct format, where `value` prints as a string if it is UTF-8, or
prints as hex if it is not UTF-8.

# Version 0.7.1

Highlights:

- A bug fix: remove duplicated keys in TXT records received.

# Version 0.7.0

Breaking Changes:

- Allow non-standard max length for a service name. The check for
the length of a service name is moved to the daemon. If a service
name is too long, there will be an error log and an error event sent
to the monitors.

- `ServiceInfo.get_property_val()` returns `Option<Option<&[u8]>>`
instead of `Option<&str>`. Now a new `ServiceInfo.get_property_val_str()`
returns `Option<&str>`.

In other words, migrate to `get_property_val_str()` if you don't
want to worry about non-UTF8 values.

Highlights:

- Allow non-standard max length for a service name: A new method
`ServiceDaemon.set_service_name_len_max()` is added to support that.
Only use it when you really need to.
- Support non-UTF-8 value for TXT properties.
- Support `no value` for a TXT property, i.e. boolean keys.
- Added checks for ASCII keys in a TXT property.

# Version 0.6.1

Highlights:

- Fixs a bug: missing TXT records in received responses.

# Version 0.6.0

Breaking Changes:

- `ServiceInfo::new()` takes `IntoTxtProperties` trait instead of a
`HashMap` of properties. It is also backward-compatiable: the trait
is implemented for `HashMap` and `Option<HashMap>`.
- `ServiceInfo::get_properties()` returns `&TxtProperties` instead of
a `HashMap` of properties. It is also mostly backward-compatiable:
support `iter()`, `get()` methods.

Highlights:

- TXT properties' names are now case insensitive. And the original user input
order is kept.
- A new method `ServiceInfo::enable_addr_auto()`: automatically fill in IP
addresses for published services.
- Detect IP changes.
- A new `ServiceDaemon::monitor()` method to return a `Receiver` handle to
monitor the daemon events, such as IP changes.

# Version 0.5.10

- skip interfaces that failed to bind (#79) (re-apply fix in v0.5.6)

# Version 0.5.9

- Ignore duplicate keys (#74)
- update error msg for send_packet (#69)

# Version 0.5.8

- call check_service_name before sending the cmd to the daemon. (#60)
- Changed dependency on 'log' crate to be optional (#64)
- configure mDNS daemon thread a name (#66)
- log an error if socket read returns 0 and reset the socket (#67)

# Version 0.5.7

- Allow service names with trailing '.' (#56)
- query unresolved instances (#58)

# Verison 0.5.6

- handle join_multicast_v4 error gracefully (#53)

# Version 0.5.5

- track IPv4 interfaces with sockets to support multiple LANs (#48)

# Version 0.5.4

- Fix a bug in resolving multiple IPs for a host.
- Code reorg: separate modules out of lib.rs.
- Listening socket joins multicast on all interfaces.

# Version 0.5.3

- Support subtypes.
- Bind every valid IPv4 interface for outgoing sockets.
- Include Windows and macOS in GitHub Actions.

# Version 0.5.2

- Add support for Windows platform.

# Version 0.5.1

- Fix missing info in the license files.
- Add docs.rs badge.
- Make Error implement std::error::Error.

# Version 0.5.0

- Allow multiple formats for host_ipv4 to create ServiceInfo.
- A breaking change: change `ServiceInfo::new()` to return a `Result<>`.
- Update `nix` dependency to version 0.24.1.

# Version 0.4.3

- Fix a bug in stop-browse

# Version 0.4.2

- New feature: support meta-query `_services._dns-sd._udp` per RFC 6763.

# Version 0.4.1

- Update docs.

# Version 0.4.0

- Replace `crossbeam-channel` with `flume`.

# Version 0.3.0

- Add "get_metrics" in API.
- Fixed a bug in cache refresh.
- Fixed a bug in retransmission.

# Version 0.2.2

- Add the first example code. Thanks @lu-zero! (#5)

# Version 0.2.1

- mDNS daemon respond socket to be blocking for simpler send.

# Version 0.2.0

- Public API internally to use the unblocking try_send() to replace send().
- Add `Again` in Error type to support retry.

# Version 0.1.0

- Initial version
