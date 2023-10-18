//! A small and safe library for Multicast DNS-SD (Service Discovery).
//!
//! This library creates one new thread to run a mDNS daemon, and exposes
//! its API that interacts with the daemon via a
//! [`flume`](https://crates.io/crates/flume) channel. The channel supports
//! both `recv()` and `recv_async()`.
//!
//! For example, a client querying (browsing) a service behaves like this:
//!```text
//!  Client       <channel>       mDNS daemon thread
//!    |                             | starts its run-loop.
//!    |       --- Browse -->        |
//!    |                             | detects services
//!    |                             | finds service instance A
//!    |       <-- Found A --        |
//!    |           ...               | resolves service A
//!    |       <-- Resolved A --     |
//!    |           ...               |
//!```
//! All commands in the public API are sent to the daemon using the unblocking `try_send()`
//! so that the caller can use it with both sync and async code, with no dependency on any
//! particular async runtimes.
//!
//! # Usage
//!
//! The user starts with creating a daemon by calling [`ServiceDaemon::new()`].
//! Then as a mDNS querier, the user would call [`browse`](`ServiceDaemon::browse`) to
//! search for services, and/or as a mDNS responder, call [`register`](`ServiceDaemon::register`)
//! to publish (i.e. announce) its own service. And, the daemon type can be cloned and passed
//! around between threads.
//!
//! ## Example: a client querying for a service type.
//!
//! ```rust
//! use mdns_sd::{ServiceDaemon, ServiceEvent};
//!
//! // Create a daemon
//! let mdns = ServiceDaemon::new().expect("Failed to create daemon");
//!
//! // Browse for a service type.
//! let service_type = "_mdns-sd-my-test._udp.local.";
//! let receiver = mdns.browse(service_type).expect("Failed to browse");
//!
//! // Receive the browse events in sync or async. Here is
//! // an example of using a thread. Users can call `receiver.recv_async().await`
//! // if running in async environment.
//! std::thread::spawn(move || {
//!     while let Ok(event) = receiver.recv() {
//!         match event {
//!             ServiceEvent::ServiceResolved(info) => {
//!                 println!("Resolved a new service: {}", info.get_fullname());
//!             }
//!             other_event => {
//!                 println!("Received other event: {:?}", &other_event);
//!             }
//!         }
//!     }
//! });
//!
//! // Gracefully shutdown the daemon.
//! std::thread::sleep(std::time::Duration::from_secs(1));
//! mdns.shutdown().unwrap();
//! ```
//!
//! ## Example: a server publishs a service and responds to queries.
//!
//! ```rust
//! use mdns_sd::{ServiceDaemon, ServiceInfo};
//! use std::collections::HashMap;
//!
//! // Create a daemon
//! let mdns = ServiceDaemon::new().expect("Failed to create daemon");
//!
//! // Create a service info.
//! let service_type = "_mdns-sd-my-test._udp.local.";
//! let instance_name = "my_instance";
//! let ip = "192.168.1.12";
//! let host_name = "192.168.1.12.local.";
//! let port = 5200;
//! let properties = [("property_1", "test"), ("property_2", "1234")];
//!
//! let my_service = ServiceInfo::new(
//!     service_type,
//!     instance_name,
//!     host_name,
//!     ip,
//!     port,
//!     &properties[..],
//! ).unwrap();
//!
//! // Register with the daemon, which publishes the service.
//! mdns.register(my_service).expect("Failed to register our service");
//!
//! // Gracefully shutdown the daemon
//! std::thread::sleep(std::time::Duration::from_secs(1));
//! mdns.shutdown().unwrap();
//! ```
//!
//! # Limitations
//!
//! This implementation is based on the following RFCs:
//! - mDNS:   [RFC 6762](https://tools.ietf.org/html/rfc6762)
//! - DNS-SD: [RFC 6763](https://tools.ietf.org/html/rfc6763)
//! - DNS:    [RFC 1035](https://tools.ietf.org/html/rfc1035)
//!
//! We focus on the common use cases at first, and currently have the following limitations:
//! - Only support multicast, not unicast send/recv.
//! - Only support 32-bit or bigger platforms, not 16-bit platforms.

#![forbid(unsafe_code)]
#![allow(clippy::single_component_path_imports)]

// log for logging (optional).
#[cfg(feature = "logging")]
use log;

#[cfg(not(feature = "logging"))]
#[macro_use]
mod log {
    macro_rules! trace    ( ($($tt:tt)*) => {{}} );
    macro_rules! debug    ( ($($tt:tt)*) => {{}} );
    macro_rules! info     ( ($($tt:tt)*) => {{}} );
    macro_rules! warn     ( ($($tt:tt)*) => {{}} );
    macro_rules! error    ( ($($tt:tt)*) => {{}} );
}

mod dns_parser;
mod error;
mod service_daemon;
mod service_info;

pub use error::{Error, Result};
pub use service_daemon::{
    DaemonEvent, IfKind, Metrics, ServiceDaemon, ServiceEvent, UnregisterStatus,
    SERVICE_NAME_LEN_MAX_DEFAULT,
};
pub use service_info::{AsIpAddrs, IntoTxtProperties, ServiceInfo, TxtProperties, TxtProperty};

/// A handler to receive messages from [ServiceDaemon]. Re-export from `flume` crate.
pub use flume::Receiver;
