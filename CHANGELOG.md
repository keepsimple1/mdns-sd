# Version 0.13.2 (2025-02-02)

This is a bugfix release.

## All changes

* 4288190 check any match for address records in conflict handler (#294) (keepsimple1)
* b51f67d unit test: fix a timing issue (#292) (keepsimple1)
* 7afed98 bugfix: check data len for NSEC record (#291) (keepsimple1)

# Version 0.13.1 (2024-12-16)

This is a bugfix release. Fixed a bug where upper case service names failed to publish.

## All changes

* 71647a1 test: cover upper case in service name (#288) (keepsimple1)
* 6ff9b52 fix: service keys must be lowercase (#286) (Jesper L. Nielsen)

# Version 0.13.0 (2024-12-15)

There are no breaking changes in API. Bump the minor version due to the change of rustc version to Rust 1.70.0.

## Highlights

* Use `mio` instead of `polling` to poll sockets.
* New API `set_multicast_loop_v4` and `set_multicast_loop_v6` of `ServiceDaemon`.
* All logging are updated to be `debug` or `trace` levels only.

## All changes

* 489ef5a test: fix a flaky test (#283) (keepsimple1)
* 1ddae63 feat: new API to set multicast loop for ServiceDaemon (#281) (keepsimple1)
* fcd31f3 dependency: use mio to replace polling (#280) (keepsimple1)
* 99483b7 reduce logging levels (#277) (keepsimple1)

# Version 0.12.0 (2024-11-24)

There are no breaking changes in API. Bump the minor version due to new features and the change of rustc version.

## Highlights

* Support name probing and conflict resolution [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762#section-8)
* Support service liveness checking via `verify` API. [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762#section-10.4)
* rustc version changed to 1.65.0
* performance improvements and doc updates.

## All changes

* 7f6c5e9 perf: avoid cloning in filtering ptr (#272) (CosminPerRam)
* e185d6f refactoring: define an enum for DNS resource record types (#274) (keepsimple1)
* d117f4f refactoring: move exec_command into Zeroconf (#273) (keepsimple1)
* 39acd80 feat: replace remaining Box<dyn DnsRecordExt> with type (#271) (CosminPerRam)
* b50fe8c perf: optimize u8_slice_to_hex by replacing Vec with String (#270) (CosminPerRam)
* db545b1 doc: some spelling fixes (#269) (CosminPerRam)
* 7328f45 doc: add a table of RFC compliance details (#268) (keepsimple1)
* 1ade666 feat: verify to support Cache Flush on Failure Indication (#267) (keepsimple1)
* 8b63fd7 feat: support name probing and conflict resolution (#265) (keepsimple1)
* 429ecde dev-test: enhance test case for ipv4 only auto addr (#263) (keepsimple1)
* f902cf2 register service: apply interface selection for auto IP addr (#262) (keepsimple1)
* 0381e30 dns_cache: address record should only flush on the same network  (#261) (keepsimple1)

# Version 0.11.5 (2024-09-28)

This is a bugfix release.

## All changes

* 2829d8e tests: fix remove addr test (#258) (keepsimple1)
* 4f58e2f dns_parser: check against potential name compression loop (#257) (keepsimple1)

# Version 0.11.4 (2024-09-10)

Bugfixes. Added checks for corrupted RR data to prevent unnecessary panics. Thanks for new 
contributor @rise0chen !

Sorry that this release has a few merged small commits as I didn't know how to properly
merge in a PR that targets a fetaure branch used in another PR, instead of `main` branch.

## All changes

* e54485e add --verbose in CI test run (#254) (keepsimple1)
* f0c4c27 remove fastrand dependency from dev-test (#252) (keepsimple1)
* dff1596 Merge pull request #250 from keepsimple1/rdata-check (keepsimple1)
* 659e684 fix cargo clippy warning (keepsimple1)
* 90a2f12 Merge pull request #251 from rise0chen/rdata-check (keepsimple1)
* 6d51f55 Merge branch 'rdata-check' into rdata-check (keepsimple1)
* 1b2cf40 add a check for rr data len (keepsimple1)
* a5de799 feat: test random data (rise0chen)
* 40698a3 add test case and simplify DnsTxt::new (keepsimple1)
* fc489bd refactoring error log (keepsimple1)
* a3fad8e add a check for rr data len (keepsimple1)

# Version 0.11.3 (2024-08-23)

A release of bugfixes and refactorings.

## All changes

* 3292110 DnsTxt debug print: make its text field human-readable (#247) (keepsimple1) (2024-08-21)
* 5567c1f Send SearchStarted events with addrs as `ip (intf-name)`  (#245) (hrzlgnm) (2024-08-22)
* 9a91a53 cache flush: add the missing timer for updated expires (#244) (keepsimple1) (2024-08-19)
* c1d7efa Change intf_socks to a map of (Interface, Socket) (#242) (keepsimple1) (2024-08-18)
* 404100d refactor out a common method for DnsRecordExt (#241) (keepsimple1) (2024-08-18)
* f055c78 Refresh A and AAAA records of active `.browse` queriers (#240) (hrzlgnm) (2024-08-17)
* 0453030 Avoid redundant query, announcement and unregistration overhaul (#239) (hrzlgnm) (2024-08-16)

# Version 0.11.2 (2024-08-06)

Mostly a bugfix and refactoring release, with limited support added for:
- Known Answer Suppression (RFC 6762 section 7.1 and 7.2):
    - single packet for querier and responder,
    - multi-packet for querier.

## All changes

* 92eae74 add support for Known Answer Suppression part 2: multi-packet: querier side (#232) (keepsimple1)
* ada3486 fix test integration_success: respond count or known answer suppression count (#237) (keepsimple1)
* 8106d07 Skip link local addresses while checking for redundant announcements or query packets (#235) (hrzlgnm)
* b1a173a check data length in read_u16 (#234) (keepsimple1)
* d1c9157 Add sanity check for service type domain suffix in browse (#231) (keepsimple1)
* 736bec6 enable DEBUG logging for a failed test in CI (#229) (keepsimple1)
* fd00210 add logs in test to debug CI failure (#228) (keepsimple1)
* 5e0f1d3 add support for Known Answer Suppression part 1 (#227) (keepsimple1)
* 5ae18a6 refactoring: remove Send for DnsRecordBox (#226) (keepsimple1)
* d7d4867 fix integration_success test (#223) (keepsimple1)
* 6f34f1c move DnsCache into its own module (#221) (keepsimple1)
* bcdc2f9 add welcome to our new contributor (#220) (keepsimple1)

# Version 0.11.1 (2024-05-13)

## Highlights

- Start to honor cache flush bit.
- Improved cache refresh logic.
- Code refactorings.
- And a few bugfixes.

## All changes

* 098f2df move unit tests into integration test (#218)
* 80291ba refresh PTR records (#217)
* 5eb74b5 refactoring: extract details from exec_command into own functions (#215)
* 551ed4d Bugfix: AddressesRemoved missing actual addrs (#210)
* 3c924f4 Bugfix: cache flush properly (#211)
* ccdae2d Bugfix: logging feature cannot be disabled (#212)
* 626f9fa refresh SRV records and send out ServiceRemoved for expired SRV (#180)
* 06e2cf7 feat: merge match same arms (#209)
* bf5cea3 perf: in adding answers, use static dispatch instead of dynamic dispatch (#207)
* 19d2161 feat: extract match addr to type as a function (#205)
* 5bdcdd6 feat: remove clone derive from counter (#208)
* e7fc0e0 feat: replace box dns with declared type (#206)
* 5732665 feat: apply nursery lints (#202)
* 16cb5cd feat: honor cache flush (#201)

Welcome our new contributor: @lyager ! Thanks!

# Version 0.11.0 (2024-04-21)

## Breaking changes

* Now `ServiceDaemon::register()` requires `hostname` to end with ".local."

## New features

* Support resolving hostnames directly: `ServiceDaemon::resolve_hostname()`

## All changes

* example code: refactor the query output prints and the register hostname (#189)
* support multiple questions in send_query_vec (#194)
* CI: fix a test waiting for IPv6 addr (#195)
* Add support for resolving non-service hostnames (#192)
* zeroconf: use min heap for timers (#196)
* Fix flaky test (#198)
* enable logging for examples and add doc for logging (#199)

Welcome our new contributor: @oysteintveit-nordicsemi ! Thanks!

# Version 0.10.5 (2024-03-24)

## Notes

* Port 0 is now considered valid in ServiceInfo (#181)

## Changes

* reduce SearchStopped notification send error to warn (#178)
* refactoring: extract handle_poller_events() (#177)
* Do not consider port 0 as a missing info (#181)
* query TYPE_A and TYPE_AAAA via Command::Resolve (#185)
* bump socket2 version (#174)
* add NSEC record to debug resolve issue (#183)

Welcome our new contributors: @hrzlgnm and @irvingoujAtDevolution ! Thanks!

# Version 0.10.4 (2024-02-10)

This is a bug fix release.

## Changes

* Add sanity checks in DNS message decoding (#169)
* fine-tune MAX_MSG_ABSOLUTE (#170)

# Version 0.10.3 (2024-01-14)

This is a bug fix release.

## Changes

* netmask -> subnet (#164)

Welcome our new contributor @amfaber ! Thanks!

# Version 0.10.2 (2023-12-28)

This is a bug fix release.

## Changes

* use human-readable address in error log of send_packet (#155)
* query for unresolved instances only when needed (#157)
* Fix panic due to range out of bounds in txt record parsing (#159)
* Sanity check for empty service type name (#160)
* Added comment for updating service info by re-registering.

Welcome our new contributor @Raphiiko ! Thanks!

Happy new year 2024!

# Version 0.10.1 (2023-12-2)

This is a bug fix release.

## Changes

* update flume to 0.11 (#152)
* bugfix: signal event key is possible to overlap with socket poll ids (#153)

# Version 0.10.0 (2023-11-28)

## Breaking changes

* `ServiceDaemon::shutdown()` return type changed from `Result<()>` to `Result<Receiver<DaemonStatus>>` (#149)

## Other changes

* Related to the breaking change, a client can receive `DaemonStatus` to be sure the daemon is shutdown.
* A new enum `DaemonStatus` and a new API `ServiceDaemon::status()` are introduced.
* Updated CI in GitHub Actions: replace `actions-rs` with `dtolnay/rust-toolchain`.

# Version 0.9.3

This is a bugfix release.

* apply interface selections when IP addresses change (#142)
* Remove un-necessary panic (#144)
* Always include subtype info if exists (#146)

p.s. Happy Halloween!

# Version 0.9.2

The release includes a bugfix, thanks to @Mornix !

* fix PTR expiration from preventing later service resolution (#140)
* updated doc comments for `DnsCache::add_or_update`.

# Version 0.9.1

There are no breaking changes.

*  support interface selection (#137)

Added two new methods for `ServiceDaemon`: `enable_interface` and `disable_interface`, and some refactoring.

# Version 0.9.0

* Ssupports IPv6 (#130) (Thanks to @izissise)
* ServiceInfo: support get_addresses_v4 (#132)
* bugfix: set address type correctly (#134)

This is a breaking change, including:

- Trait `AsIpv4Addrs` changes to `AsIpAddrs` to support both IPv4 and IPv6.
- `ServiceInfo::new()` uses the new `AsIpAddrs` trait.
- `ServiceInfo::get_addresses()` returns both IPv4 and IPv6 addresses, while a new convenience method `get_addresses_v4` returns IPv4 only.

But in general, because the trait hides away details, the user code is likely keeping working without code changes.

Improvements:

* avoid redundant annoucement or query packets (#135)

# Version 0.8.1

* Remove env_logger in dev-dependencies and lower MSRV to 1.60.0. (#128)

# Version 0.8.0

No breaking changes in API. This release brings two potential user-visible changes:

* use UDP socket to signal the daemon for commands. (#125)

This change reduces CPU utilization of the daemon thread as well as its latency to
the user commands. Internally it uses local UDP sockets to signal the daemon.

* Added the link-local feature to if_addrs in Cargo.toml to enable link-local interfaces in Windows. (#126)

This change makes link-local interfaces visible to users in Windows where they didn't show up previously.

# Version 0.7.5

* Revert the changes in v0.7.4 and support link-local addrs alongside routable addrs. (#122)

# Version 0.7.4 (deprecated)

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
