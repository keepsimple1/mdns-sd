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
//! let host_ipv4 = "192.168.1.12";
//! let host_name = "192.168.1.12.local.";
//! let port = 5200;
//! let mut properties = HashMap::new();
//! properties.insert("property_1".to_string(), "test".to_string());
//! properties.insert("property_2".to_string(), "1234".to_string());
//!
//! let my_service = ServiceInfo::new(
//!     service_type,
//!     instance_name,
//!     host_name,
//!     host_ipv4,
//!     port,
//!     Some(properties),
//! ).unwrap();
//!
//! // Register with the daemon, which publishes the service.
//! mdns.register(my_service).expect("Failed to register our service");
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
//! - Only support IPv4, not IPv6.
//! - Only support multicast, not unicast send/recv.
//! - Only tested on Linux and MacOS, not on Windows or other OSes.

#![forbid(unsafe_code)]

// What DNS-based Service Discovery works in a nutshell:
//
// (excerpt from RFC 6763)
// .... that a particular service instance can be
//    described using a DNS SRV [RFC2782] and DNS TXT [RFC1035] record.
//    The SRV record has a name of the form "<Instance>.<Service>.<Domain>"
//    and gives the target host and port where the service instance can be
//    reached.  The DNS TXT record of the same name gives additional
//    information about this instance, in a structured form using key/value
//    pairs, described in Section 6.  A client discovers the list of
//    available instances of a given service type using a query for a DNS
//    PTR [RFC1035] record with a name of the form "<Service>.<Domain>",
//    which returns a set of zero or more names, which are the names of the
//    aforementioned DNS SRV/TXT record pairs.
//
// Some naming conventions in this source code:
//
// `ty_domain` refers to service type together with domain name, i.e. <service>.<domain>.
// Every <service> consists of two labels: service itself and "_udp." or "_tcp".
// See RFC 6763 section 7 Service Names.
//     for example: `_my-service._udp.local.`
//
// `fullname` refers to a full Service Instance Name, i.e. <instance>.<service>.<domain>
//     for example: `my_home._my-service._udp.local.`
//
// In mDNS and DNS, the basic data structure is "Resource Record" (RR), where
// in Service Discovery, the basic data structure is "Service Info". One Service Info
// corresponds to a set of DNS Resource Records.
use flume::{bounded, Sender, TrySendError};
use log::{debug, error};
use nix::{
    errno, fcntl,
    sys::{
        select::{select, FdSet},
        socket::{
            bind, recvfrom, sendto, setsockopt, socket, sockopt, AddressFamily, InetAddr, IpAddr,
            IpMembershipRequest, Ipv4Addr, MsgFlags, SockAddr, SockFlag, SockType,
        },
        time::{TimeVal, TimeValLike},
    },
};
use std::{
    any::Any,
    cmp,
    collections::{HashMap, HashSet},
    convert::TryInto,
    fmt,
    os::unix::io::RawFd,
    str::{self, FromStr},
    thread,
    time::SystemTime,
    vec,
};

/// A basic error type from this library.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Like a classic EAGAIN. The receiver should retry.
    Again,

    /// A generic error message.
    Msg(String),

    /// Error during parsing of ip address
    ParseIpAddr(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Msg(s) => write!(f, "{}", s),
            Error::ParseIpAddr(s) => write!(f, "parsing of ip addr failed, reason: {}", s),
            Error::Again => write!(f, "try again"),
        }
    }
}

/// One and only `Result` type from this library crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Re-export from `flume`.
pub use flume::Receiver;

/// A simple macro to report all kinds of errors.
macro_rules! e_fmt {
  ($($arg:tt)+) => {
      Error::Msg(format!($($arg)+))
  };
}

const TYPE_A: u16 = 1; // IPv4 address
const TYPE_CNAME: u16 = 5;
const TYPE_PTR: u16 = 12;
const TYPE_HINFO: u16 = 13;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28; // IPv6 address
const TYPE_SRV: u16 = 33;
const TYPE_ANY: u16 = 255;

const CLASS_IN: u16 = 1;
const CLASS_MASK: u16 = 0x7FFF;
const CLASS_UNIQUE: u16 = 0x8000;

const MAX_MSG_ABSOLUTE: usize = 8966;
const MDNS_PORT: u16 = 5353;

// Definitions for DNS message header "flags" field
//
// The "flags" field is 16-bit long, in this format:
// (RFC 1035 section 4.1.1)
//
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//
const FLAGS_QR_MASK: u16 = 0x8000; // mask for query/response bit
const FLAGS_QR_QUERY: u16 = 0x0000;
const FLAGS_QR_RESPONSE: u16 = 0x8000;
const FLAGS_AA: u16 = 0x0400; // mask for Authoritative answer bit

/// Default TTL values in seconds
const DNS_HOST_TTL: u32 = 120; // 2 minutes for host records (A, SRV etc) per RFC6762
const DNS_OTHER_TTL: u32 = 4500; // 75 minutes for non-host records (PTR, TXT etc) per RFC6762

/// Response status code for the service `unregister` call.
#[derive(Debug)]
pub enum UnregisterStatus {
    /// Unregister was successful.
    OK,
    /// The service was not found in the registration.
    NotFound,
}

/// Different counters included in the metrics.
/// Currently all counters are for outgoing packets.
#[derive(Hash, Eq, PartialEq, Clone)]
enum Counter {
    Register,
    RegisterResend,
    Unregister,
    UnregisterResend,
    Browse,
    Respond,
    CacheRefreshQuery,
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Counter::Register => write!(f, "register"),
            Counter::RegisterResend => write!(f, "register-resend"),
            Counter::Unregister => write!(f, "unregister"),
            Counter::UnregisterResend => write!(f, "unregister-resend"),
            Counter::Browse => write!(f, "browse"),
            Counter::Respond => write!(f, "respond"),
            Counter::CacheRefreshQuery => write!(f, "cache-refresh"),
        }
    }
}

/// The metrics is a HashMap of (name_key, i64_value).
/// The main purpose is to help monitoring the mDNS packet traffic.
pub type Metrics = HashMap<String, i64>;

/// A daemon thread for mDNS
///
/// This struct provides a handle and an API to the daemon. It is cloneable.
#[derive(Clone)]
pub struct ServiceDaemon {
    /// Sender handle of the channel to the daemon.
    sender: Sender<Command>,
}

impl ServiceDaemon {
    /// Creates a new daemon and spawns a thread to run the daemon.
    ///
    /// The daemon (re)uses the default mDNS port 5353. To keep it simple, we don't
    /// ask callers to set the port.
    pub fn new() -> Result<Self> {
        let udp_port = MDNS_PORT;
        let zc = Zeroconf::new(udp_port)?;
        let (sender, receiver) = bounded(100);

        // Spawn the daemon thread
        thread::spawn(move || Self::run(zc, receiver));

        Ok(Self { sender })
    }

    /// Starts browsing for a specific service type.
    ///
    /// Returns a channel `Receiver` to receive events about the service. The caller
    /// can call `.recv_async().await` on this receiver to handle events in an
    /// async environment or call `.recv()` in a sync environment.
    ///
    /// When a new instance is found, the daemon automatically tries to resolve, i.e.
    /// finding more details, i.e. SRV records and TXT records.
    pub fn browse(&self, service_type: &str) -> Result<Receiver<ServiceEvent>> {
        let (resp_s, resp_r) = bounded(10);
        self.sender
            .try_send(Command::Browse(service_type.to_string(), 1, resp_s))
            .map_err(|e| match e {
                TrySendError::Full(_) => Error::Again,
                e => e_fmt!("flume::channel::send failed: {}", e),
            })?;
        Ok(resp_r)
    }

    /// Stops searching for a specific service type.
    ///
    /// When an error is returned, the caller should retry only when
    /// the error is `Error::Again`, otherwise should log and move on.
    pub fn stop_browse(&self, ty_domain: &str) -> Result<()> {
        self.sender
            .try_send(Command::StopBrowse(ty_domain.to_string()))
            .map_err(|e| match e {
                TrySendError::Full(_) => Error::Again,
                e => e_fmt!("flume::channel::send failed: {}", e),
            })?;
        Ok(())
    }

    /// Registers a service provided by this host.
    pub fn register(&self, service_info: ServiceInfo) -> Result<()> {
        self.sender
            .try_send(Command::Register(service_info))
            .map_err(|e| match e {
                TrySendError::Full(_) => Error::Again,
                e => e_fmt!("flume::channel::send failed: {}", e),
            })?;
        Ok(())
    }

    /// Unregisters a service. This is a graceful shutdown of a service.
    ///
    /// Returns a channel receiver that is used to receive the status code
    /// of the unregister.
    ///
    /// When an error is returned, the caller should retry only when
    /// the error is `Error::Again`, otherwise should log and move on.
    pub fn unregister(&self, fullname: &str) -> Result<Receiver<UnregisterStatus>> {
        let (resp_s, resp_r) = bounded(1);
        self.sender
            .try_send(Command::Unregister(fullname.to_lowercase(), resp_s))
            .map_err(|e| match e {
                TrySendError::Full(_) => Error::Again,
                e => e_fmt!("flume::channel::send failed: {}", e),
            })?;
        Ok(resp_r)
    }

    /// Shuts down the daemon thread.
    ///
    /// When an error is returned, the caller should retry only when
    /// the error is `Error::Again`, otherwise should log and move on.
    pub fn shutdown(&self) -> Result<()> {
        self.sender.try_send(Command::Exit).map_err(|e| match e {
            TrySendError::Full(_) => Error::Again,
            e => e_fmt!("flume::channel::send failed: {}", e),
        })
    }

    /// Returns a channel receiver for the metrics, e.g. input/output counters.
    ///
    /// The metrics returned is a snapshot. Hence the caller should call
    /// this method repeatedly if they want to monitor the metrics continuously.
    pub fn get_metrics(&self) -> Result<Receiver<Metrics>> {
        let (resp_s, resp_r) = bounded(1);
        self.sender
            .try_send(Command::GetMetrics(resp_s))
            .map_err(|e| match e {
                TrySendError::Full(_) => Error::Again,
                e => e_fmt!("flume::channel::try_send failed: {}", e),
            })?;
        Ok(resp_r)
    }

    /// The main event loop of the daemon thread
    ///
    /// In each round, it will:
    /// 1. select the listening sockets with a timeout.
    /// 2. process the incoming packets if any.
    /// 3. try_recv on its channel and execute commands.
    /// 4. announce its registered services.
    /// 5. process retransmissions if any.
    fn run(mut zc: Zeroconf, receiver: Receiver<Command>) {
        loop {
            let mut read_fds = FdSet::new();
            read_fds.insert(zc.listen_socket);

            // read incoming packets with a small timeout
            let mut timeout = TimeVal::milliseconds(10);

            // From POSIX select():
            // If the readfds argument is not a null pointer,
            // it points to an object of type fd_set that on input
            // specifies the file descriptors to be checked for
            // being ready to read, and on output indicates which
            // file descriptors are ready to read.
            match select(None, Some(&mut read_fds), None, None, Some(&mut timeout)) {
                Ok(_) => {
                    for fd in read_fds.fds(None) {
                        // Read from `fd` until no more packets available.
                        loop {
                            let rc = zc.handle_read(fd);
                            if !rc {
                                break;
                            }
                        }
                    }
                }
                Err(e) => error!("failed to select from sockets: {}", e),
            }

            // process commands from the command channel
            match receiver.try_recv() {
                Ok(Command::Exit) => {
                    debug!("Exit from daemon");
                    break;
                }
                Ok(command) => Self::exec_command(&mut zc, command, false),
                _ => {}
            }

            // check for repeated commands and run them if their time is up.
            let now = current_time_millis();
            let mut i = 0;
            while i < zc.retransmissions.len() {
                if now >= zc.retransmissions[i].next_time {
                    let rerun = zc.retransmissions.remove(i);
                    Self::exec_command(&mut zc, rerun.command, true);
                } else {
                    i += 1;
                }
            }

            // Refresh cache records with active queriers
            let mut query_count = 0;
            for (ty_domain, _sender) in zc.queriers.iter() {
                for instance in zc.cache.refresh_due(ty_domain).iter() {
                    zc.send_query(instance, TYPE_ANY);
                    query_count += 1;
                }
            }
            zc.increase_counter(Counter::CacheRefreshQuery, query_count);

            // check and evict expired records in our cache
            let now = current_time_millis();
            let map = zc.queriers.clone();
            zc.cache.evict_expired(now, |expired| {
                if let Some(dns_ptr) = expired.any().downcast_ref::<DnsPointer>() {
                    let ty_domain = dns_ptr.get_name();
                    call_listener(
                        &map,
                        ty_domain,
                        ServiceEvent::ServiceRemoved(ty_domain.to_string(), dns_ptr.alias.clone()),
                    );
                }
            });
        }
    }

    /// The entry point that executes all commands received by the daemon.
    ///
    /// `repeating`: whether this is a retransmission.
    fn exec_command(zc: &mut Zeroconf, command: Command, repeating: bool) {
        match command {
            Command::Browse(ty, next_delay, listener) => {
                if let Err(e) = listener.send(ServiceEvent::SearchStarted(ty.clone())) {
                    error!("Failed to send SearchStarted: {}", e);
                    return;
                }
                if !repeating {
                    zc.add_querier(ty.clone(), listener.clone());
                    // if we already have the records in our cache, just send them
                    zc.query_cache(&ty, listener.clone());
                }

                zc.send_query(&ty, TYPE_PTR);
                zc.increase_counter(Counter::Browse, 1);

                let next_time = current_time_millis() + (next_delay * 1000) as u64;
                let max_delay = 60 * 60;
                let delay = cmp::min(next_delay * 2, max_delay);
                zc.retransmissions.push(ReRun {
                    next_time,
                    command: Command::Browse(ty, delay, listener),
                });
            }

            Command::Register(service_info) => {
                debug!("register service {:?}", &service_info);
                zc.register_service(service_info);
                zc.increase_counter(Counter::Register, 1);
            }

            Command::RegisterResend(fullname) => {
                debug!("announce service: {}", &fullname);
                match zc.my_services.get(&fullname) {
                    Some(info) => {
                        zc.broadcast_service(info);
                        zc.increase_counter(Counter::RegisterResend, 1);
                    }
                    None => debug!("announce: cannot find such service {}", &fullname),
                }
            }

            Command::Unregister(fullname, resp_s) => {
                debug!("unregister service {} repeat {}", &fullname, &repeating);
                let response = match zc.my_services.remove_entry(&fullname) {
                    None => {
                        error!("unregister: cannot find such service {}", &fullname);
                        UnregisterStatus::NotFound
                    }
                    Some((_k, info)) => {
                        let packet = zc.unregister_service(&info);
                        zc.increase_counter(Counter::Unregister, 1);
                        // repeat for one time just in case some peers miss the message
                        if !repeating && !packet.is_empty() {
                            let next_time = current_time_millis() + 120;
                            zc.retransmissions.push(ReRun {
                                next_time,
                                command: Command::UnregisterResend(packet),
                            });
                        }
                        UnregisterStatus::OK
                    }
                };
                if let Err(e) = resp_s.send(response) {
                    error!("unregister: failed to send response: {}", e);
                }
            }

            Command::UnregisterResend(packet) => {
                debug!("Send a packet length of {}", packet.len());
                zc.send_packet(&packet[..], &zc.broadcast_addr);
                zc.increase_counter(Counter::UnregisterResend, 1);
            }

            Command::StopBrowse(ty_domain) => match zc.queriers.remove_entry(&ty_domain) {
                None => error!("StopBrowse: cannot find querier for {}", &ty_domain),
                Some((ty, sender)) => {
                    // Remove pending browse commands in the reruns.
                    let mut i = 0;
                    while i < zc.retransmissions.len() {
                        if let Command::Browse(t, _, _) = &zc.retransmissions[i].command {
                            if t == &ty {
                                zc.retransmissions.remove(i);
                                continue;
                            }
                        }
                        i += 1;
                    }

                    // Notify the client.
                    match sender.send(ServiceEvent::SearchStopped(ty_domain)) {
                        Ok(()) => debug!("Sent SearchStopped to the listener"),
                        Err(e) => error!("Failed to send SearchStopped: {}", e),
                    }
                }
            },

            Command::GetMetrics(resp_s) => match resp_s.send(zc.counters.clone()) {
                Ok(()) => debug!("Sent metrics to the client"),
                Err(e) => error!("Failed to send metrics: {}", e),
            },

            _ => {
                error!("unexpected command: {:?}", &command);
            }
        }
    }
}

/// Creates a new UDP socket to bind to `port` with REUSEPORT option.
/// `non_block` indicates whether to set O_NONBLOCK for the socket.
fn new_socket(port: u16, non_block: bool) -> Result<RawFd> {
    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| e_fmt!("nix::sys::socket failed: {}", e))?;

    setsockopt(fd, sockopt::ReuseAddr, &true)
        .map_err(|e| e_fmt!("nix::sys::setsockopt ReuseAddr failed: {}", e))?;
    setsockopt(fd, sockopt::ReusePort, &true)
        .map_err(|e| e_fmt!("nix::sys::setsockopt ReusePort failed: {}", e))?;

    if non_block {
        fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFL(fcntl::OFlag::O_NONBLOCK))
            .map_err(|e| e_fmt!("nix::fcntl O_NONBLOCK: {}", e))?;
    }

    let ipv4_any = IpAddr::new_v4(0, 0, 0, 0);
    let inet_addr = InetAddr::new(ipv4_any, port);
    bind(fd, &SockAddr::Inet(inet_addr))
        .map_err(|e| e_fmt!("nix::sys::socket::bind failed: {}", e))?;

    debug!("new socket {} bind to {}", &fd, &inet_addr);
    Ok(fd)
}

fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("failed to get current UNIX time")
        .as_millis() as u64
}

type DnsRecordBox = Box<dyn DnsRecordExt + Send>;

struct ReRun {
    next_time: u64,
    command: Command,
}

/// A struct holding the state. It was inspired by `zeroconf` package in Python.
struct Zeroconf {
    /// One socket to receive all mDNS packets incoming, regardless interface.
    /// This socket will not be able to read unicast packets.
    listen_socket: RawFd,

    /// Sockets for outgoing packets.
    /// NOTE: For now we only support multicast and this Vec has only one socket.
    /// If we support unicast, we will have one respond socket for each
    /// valid interface, and read unicast packets from these sockets.
    respond_sockets: Vec<RawFd>,

    /// Local registered services
    my_services: HashMap<String, ServiceInfo>,

    /// Well-known mDNS IPv4 address and port
    broadcast_addr: SockAddr,

    cache: DnsCache,

    /// Active "Browse" commands.
    queriers: HashMap<String, Sender<ServiceEvent>>, // <ty_domain, channel::sender>

    /// Active queriers interested instances
    instances_to_resolve: HashMap<String, ServiceInfo>,

    /// All repeating transmissions.
    retransmissions: Vec<ReRun>,

    counters: Metrics,
}

impl Zeroconf {
    fn new(udp_port: u16) -> Result<Self> {
        let listen_socket = new_socket(udp_port, true)?;
        debug!("created listening socket: {}", &listen_socket);

        let group_addr = Ipv4Addr::new(224, 0, 0, 251);
        let request = IpMembershipRequest::new(group_addr, None);
        setsockopt(listen_socket, sockopt::IpAddMembership, &request)
            .map_err(|e| e_fmt!("nix::sys::setsockopt failed: {}", e))?;

        // We are not setting specific outgoing interface for this socket.
        // It will use the default outgoing interface set by the OS.
        let mut respond_sockets = Vec::new();
        let respond_socket = new_socket(udp_port, false)?;
        respond_sockets.push(respond_socket);

        let broadcast_addr =
            SockAddr::new_inet(InetAddr::new(IpAddr::new_v4(224, 0, 0, 251), MDNS_PORT));

        Ok(Self {
            listen_socket,
            respond_sockets,
            my_services: HashMap::new(),
            broadcast_addr,
            cache: DnsCache::new(),
            queriers: HashMap::new(),
            instances_to_resolve: HashMap::new(),
            retransmissions: Vec::new(),
            counters: HashMap::new(),
        })
    }

    /// Registers a service.
    ///
    /// RFC 6762 section 8.3.
    /// ...the Multicast DNS responder MUST send
    ///    an unsolicited Multicast DNS response containing, in the Answer
    ///    Section, all of its newly registered resource records
    ///
    /// Zeroconf will then respond to requests for information about this service.
    fn register_service(&mut self, info: ServiceInfo) {
        if let Err(e) = check_service_name(&info.fullname) {
            error!("check service name failed: {}", e);
            return;
        }

        self.broadcast_service(&info);

        // RFC 6762 section 8.3.
        // ..The Multicast DNS responder MUST send at least two unsolicited
        //    responses, one second apart.
        let next_time = current_time_millis() + 1000;

        // The key has to be lower case letter as DNS record name is case insensitive.
        // The info will have the original name.
        let service_fullname = info.fullname.to_lowercase();
        self.retransmissions.push(ReRun {
            next_time,
            command: Command::RegisterResend(service_fullname.clone()),
        });
        self.my_services.insert(service_fullname, info);
    }

    /// Send an unsolicited response for owned service
    fn broadcast_service(&self, info: &ServiceInfo) {
        debug!("broadcast service {}", &info.fullname);
        let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
        out.add_answer_at_time(
            Box::new(DnsPointer::new(
                &info.ty_domain,
                TYPE_PTR,
                CLASS_IN,
                info.other_ttl,
                info.fullname.clone(),
            )),
            0,
        );

        out.add_answer_at_time(
            Box::new(DnsSrv::new(
                &info.fullname,
                CLASS_IN | CLASS_UNIQUE,
                info.host_ttl,
                info.priority,
                info.weight,
                info.port,
                info.server.clone(),
            )),
            0,
        );
        out.add_answer_at_time(
            Box::new(DnsTxt::new(
                &info.fullname,
                TYPE_TXT,
                CLASS_IN | CLASS_UNIQUE,
                info.other_ttl,
                info.generate_txt(),
            )),
            0,
        );

        for addr in &info.addresses {
            out.add_answer_at_time(
                Box::new(DnsAddress::new(
                    &info.server,
                    TYPE_A,
                    CLASS_IN | CLASS_UNIQUE,
                    info.host_ttl,
                    *addr,
                )),
                0,
            );
        }

        self.send(&out, &self.broadcast_addr);
    }

    fn unregister_service(&self, info: &ServiceInfo) -> Vec<u8> {
        let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
        out.add_answer_at_time(
            Box::new(DnsPointer::new(
                &info.ty_domain,
                TYPE_PTR,
                CLASS_IN,
                0,
                info.fullname.clone(),
            )),
            0,
        );

        out.add_answer_at_time(
            Box::new(DnsSrv::new(
                &info.fullname,
                CLASS_IN | CLASS_UNIQUE,
                0,
                info.priority,
                info.weight,
                info.port,
                info.server.clone(),
            )),
            0,
        );
        out.add_answer_at_time(
            Box::new(DnsTxt::new(
                &info.fullname,
                TYPE_TXT,
                CLASS_IN | CLASS_UNIQUE,
                0,
                info.generate_txt(),
            )),
            0,
        );

        for addr in &info.addresses {
            out.add_answer_at_time(
                Box::new(DnsAddress::new(
                    &info.server,
                    TYPE_A,
                    CLASS_IN | CLASS_UNIQUE,
                    0,
                    *addr,
                )),
                0,
            );
        }

        self.send(&out, &self.broadcast_addr)
    }

    /// Binds a channel `listener` to querying mDNS domain type `ty`.
    ///
    /// If there is already a `listener`, it will be updated, i.e. overwritten.
    fn add_querier(&mut self, ty: String, listener: Sender<ServiceEvent>) {
        self.queriers.insert(ty, listener);
    }

    /// Sends an outgoing packet, and returns the packet bytes.
    fn send(&self, out: &DnsOutgoing, addr: &SockAddr) -> Vec<u8> {
        let qtype = if out.is_query() { "query" } else { "response" };
        debug!(
            "Sending {} to {}: {} questions {} answers {} authorities {} additional",
            qtype,
            addr,
            out.questions.len(),
            out.answers.len(),
            out.authorities.len(),
            out.additionals.len()
        );
        let packet = out.to_packet().data.concat();
        if packet.len() > MAX_MSG_ABSOLUTE {
            error!("Drop over-sized packet ({})", packet.len());
            return Vec::new();
        }

        self.send_packet(&packet[..], addr);
        packet
    }

    fn send_packet(&self, packet: &[u8], addr: &SockAddr) {
        for s in self.respond_sockets.iter() {
            match sendto(*s, packet, addr, MsgFlags::empty()) {
                Ok(sz) => debug!("sent out {} bytes on socket {}", sz, s),
                Err(e) => error!("send failed: {}", e),
            }
        }
    }

    fn send_query(&self, name: &str, qtype: u16) {
        debug!("Sending multicast query for {}", name);
        let mut out = DnsOutgoing::new(FLAGS_QR_QUERY);
        out.add_question(name, qtype);
        self.send(&out, &self.broadcast_addr);
    }

    /// Returns false if failed to receive a packet,
    /// otherwise returns true.
    /// `sockfd` is expected to be connectionless (i.e. UDP socket).
    fn handle_read(&mut self, sockfd: RawFd) -> bool {
        let mut buf = vec![0; MAX_MSG_ABSOLUTE];
        let (sz, src_addr) = match recvfrom(sockfd, &mut buf) {
            Ok((sz, Some(addr))) => (sz, addr),
            Ok((_, None)) => {
                error!("recvfrom could not find source address");
                return false;
            }
            Err(errno::Errno::EAGAIN) => {
                // Simply means the fd has no more packets to read.
                // No need to log an error.
                return false;
            }
            Err(e) => {
                error!("recvfrom failed: {}", e);
                return false;
            }
        };

        debug!(
            "socket fd {} received {} bytes from {}",
            &sockfd, sz, src_addr
        );

        match DnsIncoming::new(buf) {
            Ok(msg) => {
                if msg.is_query() {
                    self.handle_query(msg, &src_addr);
                } else if msg.is_response() {
                    self.handle_response(msg, &src_addr);
                } else {
                    error!("Invalid message: not query and not response");
                }
            }
            Err(e) => error!("Invalid incoming message: {}", e),
        }

        true
    }

    /// Checks if `ty_domain` has records in the cache. If yes, sends the
    /// cached records via `sender`.
    fn query_cache(&mut self, ty_domain: &str, sender: Sender<ServiceEvent>) {
        if let Some(records) = self.cache.get_records_by_name(ty_domain) {
            for record in records.iter() {
                if let Some(ptr) = record.any().downcast_ref::<DnsPointer>() {
                    let info = self.create_service_info_from_cache(ty_domain, &ptr.alias);
                    let info = match info {
                        Ok(ok) => ok,
                        Err(err) => {
                            error!("Error while creating service info from cache: {}", err);
                            continue;
                        }
                    };

                    match sender.send(ServiceEvent::ServiceFound(
                        ty_domain.to_string(),
                        ptr.alias.clone(),
                    )) {
                        Ok(()) => debug!("send service found {}", &ptr.alias),
                        Err(e) => {
                            error!("failed to send service found: {}", e);
                            continue;
                        }
                    }

                    if info.is_ready() {
                        match sender.send(ServiceEvent::ServiceResolved(info)) {
                            Ok(()) => debug!("sent service resolved"),
                            Err(e) => error!("failed to send service resolved: {}", e),
                        }
                    } else if !self.instances_to_resolve.contains_key(&info.fullname) {
                        self.instances_to_resolve
                            .insert(ty_domain.to_string(), info);
                    }
                }
            }
        }
    }

    fn create_service_info_from_cache(
        &self,
        ty_domain: &str,
        fullname: &str,
    ) -> Result<ServiceInfo> {
        let my_name = fullname
            .trim_end_matches(&ty_domain)
            .trim_end_matches('.')
            .to_string();

        let mut info = ServiceInfo::new(ty_domain, &my_name, "", (), 0, None)?;

        // resolve SRV and TXT records
        if let Some(records) = self.cache.map.get(fullname) {
            for answer in records.iter() {
                if let Some(dns_srv) = answer.any().downcast_ref::<DnsSrv>() {
                    info.server = dns_srv.host.clone();
                    info.port = dns_srv.port;
                } else if let Some(dns_txt) = answer.any().downcast_ref::<DnsTxt>() {
                    info.set_properties_from_txt(&dns_txt.text);
                }
            }
        }

        if let Some(records) = self.cache.map.get(&info.server) {
            for answer in records.iter() {
                if let Some(dns_a) = answer.any().downcast_ref::<DnsAddress>() {
                    info.addresses.insert(dns_a.address);
                }
            }
        }

        Ok(info)
    }

    /// Try to resolve some instances based on a record (answer),
    /// and return a list of instances that got resolved.
    fn resolve_by_answer(
        instances_to_resolve: &mut HashMap<String, ServiceInfo>,
        answer: &DnsRecordBox,
    ) -> Vec<String> {
        let mut resolved = Vec::new();
        if let Some(dns_srv) = answer.any().downcast_ref::<DnsSrv>() {
            if let Some(info) = instances_to_resolve.get_mut(answer.get_name()) {
                debug!("setting server and port for service info");
                info.server = dns_srv.host.clone();
                info.port = dns_srv.port;
                if info.is_ready() {
                    resolved.push(answer.get_name().to_string());
                }
            }
        } else if let Some(dns_txt) = answer.any().downcast_ref::<DnsTxt>() {
            if let Some(info) = instances_to_resolve.get_mut(answer.get_name()) {
                debug!("setting text for service info");
                info.set_properties_from_txt(&dns_txt.text);
                if info.is_ready() {
                    resolved.push(answer.get_name().to_string());
                }
            }
        } else if let Some(dns_a) = answer.any().downcast_ref::<DnsAddress>() {
            for (_k, info) in instances_to_resolve.iter_mut() {
                if info.server == answer.get_name() {
                    debug!("setting address in server {}", &info.server);
                    info.addresses.insert(dns_a.address);
                    if info.is_ready() {
                        resolved.push(info.fullname.clone());
                    }
                }
            }
        }
        resolved
    }

    fn handle_answer(&mut self, record: DnsRecordBox) {
        let (record_ext, existing) = self.cache.add_or_update(record);
        let dns_entry = &record_ext.get_record().entry;
        let mut resolved = Vec::new();
        debug!("add_or_update record name: {:?}", &dns_entry.name);

        if let Some(dns_ptr) = record_ext.any().downcast_ref::<DnsPointer>() {
            let service_type = dns_entry.name.clone();
            let instance = dns_ptr.alias.clone();

            if !self.queriers.contains_key(&service_type) {
                debug!("Not interested for any querier");
                return;
            }

            // Insert into services_to_resolve if this is a new instance
            if !self.instances_to_resolve.contains_key(&instance) {
                if existing {
                    debug!("already knew: {}", &instance);
                    return;
                }

                let my_name = instance
                    .trim_end_matches(&service_type)
                    .trim_end_matches('.')
                    .to_string();

                let service_info = ServiceInfo::new(&service_type, &my_name, "", (), 0, None);

                match service_info {
                    Ok(service_info) => {
                        debug!("Inserting service info: {:?}", &service_info);
                        self.instances_to_resolve
                            .insert(instance.clone(), service_info);
                    }
                    Err(err) => {
                        error!("Malformed service info while inserting: {:?}", err);
                    }
                }
            }

            call_listener(
                &self.queriers,
                &dns_entry.name,
                ServiceEvent::ServiceFound(service_type, instance),
            );
        } else {
            resolved = Self::resolve_by_answer(&mut self.instances_to_resolve, record_ext);
        }

        for instance in resolved.iter() {
            let info = self.instances_to_resolve.remove(instance).unwrap();
            if let Some(listener) = self.queriers.get(&info.ty_domain) {
                match listener.send(ServiceEvent::ServiceResolved(info)) {
                    Ok(()) => debug!("sent service info successfully"),
                    Err(e) => println!("failed to send service info: {}", e),
                }
            }
        }
    }

    /// Deal with incoming response packets.  All answers
    /// are held in the cache, and listeners are notified.
    fn handle_response(&mut self, mut msg: DnsIncoming, src: &SockAddr) {
        debug!(
            "handle_response from {}: {} answers {} authorities {} additionals",
            src, &msg.num_answers, &msg.num_authorities, &msg.num_additionals
        );
        let now = current_time_millis();

        while !msg.answers.is_empty() {
            let record = msg.answers.remove(0);
            if record.get_record().is_expired(now) {
                if self.cache.remove(&record) {
                    // for PTR records, send event to listeners
                    if let Some(dns_ptr) = record.any().downcast_ref::<DnsPointer>() {
                        call_listener(
                            &self.queriers,
                            dns_ptr.get_name(),
                            ServiceEvent::ServiceRemoved(
                                dns_ptr.get_name().to_string(),
                                dns_ptr.alias.clone(),
                            ),
                        );
                    }
                }
            } else {
                self.handle_answer(record);
            }
        }
    }

    fn handle_query(&mut self, msg: DnsIncoming, addr: &SockAddr) {
        debug!("handle_query from {}", &addr);
        let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);

        // Special meta-query "_services._dns-sd._udp.<Domain>".
        // See https://datatracker.ietf.org/doc/html/rfc6763#section-9
        const META_QUERY: &str = "_services._dns-sd._udp.local.";

        for question in msg.questions.iter() {
            debug!("question: {:?}", &question);
            let qtype = question.entry.ty;

            if qtype == TYPE_PTR {
                for service in self.my_services.values() {
                    if question.entry.name == service.ty_domain {
                        out.add_answer_with_additionals(&msg, service);
                    } else if question.entry.name == META_QUERY {
                        let ptr_added = out.add_answer(
                            &msg,
                            Box::new(DnsPointer::new(
                                &question.entry.name,
                                TYPE_PTR,
                                CLASS_IN,
                                service.other_ttl,
                                service.ty_domain.clone(),
                            )),
                        );
                        if !ptr_added {
                            debug!("answer was not added for meta-query {:?}", &question);
                        }
                    }
                }
            } else {
                if qtype == TYPE_A || qtype == TYPE_ANY {
                    for service in self.my_services.values() {
                        if service.server == question.entry.name.to_lowercase() {
                            for address in &service.addresses {
                                out.add_answer(
                                    &msg,
                                    Box::new(DnsAddress::new(
                                        &question.entry.name,
                                        TYPE_A,
                                        CLASS_IN | CLASS_UNIQUE,
                                        service.host_ttl,
                                        *address,
                                    )),
                                );
                            }
                        }
                    }
                }

                let name_to_find = question.entry.name.to_lowercase();
                let service = match self.my_services.get(&name_to_find) {
                    Some(s) => s,
                    None => continue,
                };

                if qtype == TYPE_SRV || qtype == TYPE_ANY {
                    out.add_answer(
                        &msg,
                        Box::new(DnsSrv::new(
                            &question.entry.name,
                            CLASS_IN | CLASS_UNIQUE,
                            service.host_ttl,
                            service.priority,
                            service.weight,
                            service.port,
                            service.server.clone(),
                        )),
                    );
                }

                if qtype == TYPE_TXT || qtype == TYPE_ANY {
                    out.add_answer(
                        &msg,
                        Box::new(DnsTxt::new(
                            &question.entry.name,
                            TYPE_TXT,
                            CLASS_IN | CLASS_UNIQUE,
                            service.host_ttl,
                            service.generate_txt(),
                        )),
                    );
                }

                if qtype == TYPE_SRV {
                    for address in &service.addresses {
                        out.add_additional_answer(Box::new(DnsAddress::new(
                            &service.server,
                            TYPE_A,
                            CLASS_IN | CLASS_UNIQUE,
                            service.host_ttl,
                            *address,
                        )));
                    }
                }
            }
        }

        if !out.answers.is_empty() {
            out.id = msg.id;
            self.send(&out, &self.broadcast_addr);

            self.increase_counter(Counter::Respond, 1);
        }
    }

    /// Increases the value of `counter` by `count`.
    fn increase_counter(&mut self, counter: Counter, count: i64) {
        let key = counter.to_string();
        match self.counters.get_mut(&key) {
            Some(v) => *v += count,
            None => {
                self.counters.insert(key, count);
            }
        }
    }
}

/// All possible events sent to the client from the daemon.
#[derive(Debug)]
pub enum ServiceEvent {
    /// Started searching for a service type.
    SearchStarted(String),
    /// Found a specific (service_type, fullname).
    ServiceFound(String, String),
    /// Resolved a service instance with detailed info.
    ServiceResolved(ServiceInfo),
    /// A service instance (service_type, fullname) was removed.
    ServiceRemoved(String, String),
    /// Stopped searching for a service type.
    SearchStopped(String),
}

/// Commands supported by the daemon
#[derive(Debug)]
enum Command {
    /// Browsing for a service type (ty_domain, next_time_delay_in_seconds, channel::sender)
    Browse(String, u32, Sender<ServiceEvent>),

    /// Register a service
    Register(ServiceInfo),

    /// Unregister a service
    Unregister(String, Sender<UnregisterStatus>), // (fullname)

    /// Announce again a service to local network
    RegisterResend(String), // (fullname)

    /// Resend unregister packet.
    UnregisterResend(Vec<u8>), // (packet content)

    /// Stop browsing a service type
    StopBrowse(String), // (ty_domain)

    /// Read the current values of the counters
    GetMetrics(Sender<Metrics>),

    Exit,
}

struct DnsCache {
    /// <record_name, list_of_records_of_the_same_name>
    map: HashMap<String, Vec<DnsRecordBox>>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    fn get_records_by_name(&self, name: &str) -> Option<&Vec<DnsRecordBox>> {
        self.map.get(name)
    }

    /// Update a DNSRecord if already exists, otherwise insert a new record
    fn add_or_update(&mut self, incoming: DnsRecordBox) -> (&DnsRecordBox, bool) {
        let record_vec = self.map.entry(incoming.get_name().to_string()).or_default();

        let mut found = false;
        let mut idx = record_vec.len();

        for i in 0..record_vec.len() {
            let r = record_vec.get_mut(i).unwrap();
            if r.matches(incoming.as_ref()) {
                r.reset_ttl(incoming.as_ref());
                found = true;
                idx = i;
                break;
            }
        }

        if !found {
            record_vec.insert(0, incoming); // we did not find it.
            idx = 0;
        }

        (record_vec.get(idx).unwrap(), found)
    }

    /// Remove a record from the cache if exists, otherwise no-op
    fn remove(&mut self, record: &DnsRecordBox) -> bool {
        let mut found = false;
        if let Some(record_vec) = self.map.get_mut(record.get_name()) {
            record_vec.retain(|x| match x.matches(record.as_ref()) {
                true => {
                    found = true;
                    false
                }
                false => true,
            });
        }
        found
    }

    /// Iterate all records and remove ones that expired, allowing
    /// a function `f` to react with the expired ones.
    fn evict_expired<F>(&mut self, now: u64, f: F)
    where
        F: Fn(&DnsRecordBox), // Caller has a chance to do something with expired
    {
        for records in self.map.values_mut() {
            records.retain(|x| {
                let expired = x.get_record().is_expired(now);
                if expired {
                    f(x);
                }
                !expired // only retain non-expired ones
            });
        }
    }

    /// Returns the list of full name of the instances for a `ty_domain`.
    fn instance_names(&self, ty_domain: &str) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(instances) = self.map.get(ty_domain) {
            for instance_ptr in instances.iter() {
                if let Some(dns_ptr) = instance_ptr.any().downcast_ref::<DnsPointer>() {
                    result.push(dns_ptr.alias.clone());
                }
            }
        }
        result
    }

    /// Returns the list of instance names that are due for refresh
    /// for a `ty_domain`.
    ///
    /// For these instances, their refresh time will be updated so that
    /// they will not refresh again.
    fn refresh_due(&mut self, ty_domain: &str) -> Vec<String> {
        let now = current_time_millis();
        let mut result = Vec::new();

        for instance in self.instance_names(ty_domain).iter() {
            if let Some(records) = self.map.get_mut(instance) {
                for record in records.iter_mut() {
                    let rec = record.get_record_mut();
                    if !rec.is_expired(now) && rec.refresh_due(now) {
                        result.push(instance.clone());

                        // Only refresh a record once, until it expires and resets.
                        rec.refresh_no_more();
                        break; // for one instance, only query once
                    }
                }
            }
        }
        result
    }
}

pub trait AsIpv4Addrs {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>>;
}

impl<T: AsIpv4Addrs> AsIpv4Addrs for &T {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>> {
        (*self).as_ipv4_addrs()
    }
}

impl AsIpv4Addrs for &str {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>> {
        let mut addrs = HashSet::new();

        let iter = self
            .split(',')
            .map(str::trim)
            .map(std::net::Ipv4Addr::from_str);

        for addr in iter {
            let addr = addr.map_err(|err| Error::ParseIpAddr(err.to_string()))?;

            addrs.insert(Ipv4Addr::from_std(&addr));
        }

        Ok(addrs)
    }
}

impl AsIpv4Addrs for String {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>> {
        self.as_str().as_ipv4_addrs()
    }
}

impl<I: AsIpv4Addrs> AsIpv4Addrs for &[I] {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>> {
        let mut addrs = HashSet::new();

        for result in self.iter().map(I::as_ipv4_addrs) {
            addrs.extend(result?);
        }

        Ok(addrs)
    }
}

/// Optimization for zero sized/empty values, as `()` will never take up any space or evaluate to
/// anything, helpful in contexts where we just want an empty value.
impl AsIpv4Addrs for () {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>> {
        Ok(HashSet::new())
    }
}

impl AsIpv4Addrs for Ipv4Addr {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>> {
        let mut ips = HashSet::new();
        ips.insert(*self);

        Ok(ips)
    }
}

impl AsIpv4Addrs for std::net::Ipv4Addr {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>> {
        let mut ips = HashSet::new();
        ips.insert(Ipv4Addr::from_std(self));

        Ok(ips)
    }
}

/// Complete info about a Service Instance.
///
/// We can construct one PTR, one SRV and one TXT record from this info,
/// as well as A (IPv4 Address) records.
#[derive(Debug)]
pub struct ServiceInfo {
    ty_domain: String, // <service>.<domain>
    fullname: String,  // <instance>.<service>.<domain>
    server: String,    // fully qualified name for service host
    addresses: HashSet<Ipv4Addr>,
    port: u16,
    host_ttl: u32,  // used for SRV and Address records
    other_ttl: u32, // used for PTR and TXT records
    priority: u16,
    weight: u16,
    properties: HashMap<String, String>,
}

impl ServiceInfo {
    /// Creates a new service info.
    ///
    /// `ty_domain` is the service type and the domain label, for example
    /// "_my-service._udp.local.".
    ///
    /// `my_name` is the instance name, without the service type suffix.
    /// `properties` are optional key/value pairs for the service.
    ///
    /// The host TTL and other TTL are set to default values.
    pub fn new<Ip: AsIpv4Addrs>(
        ty_domain: &str,
        my_name: &str,
        host_name: &str,
        host_ipv4: Ip,
        port: u16,
        properties: Option<HashMap<String, String>>,
    ) -> Result<Self> {
        let fullname = format!("{}.{}", my_name, ty_domain);
        let ty_domain = ty_domain.to_string();
        let server = host_name.to_string();

        let addresses = host_ipv4.as_ipv4_addrs()?;

        let properties = properties.unwrap_or_default();

        let this = Self {
            ty_domain,
            fullname,
            server,
            addresses,
            port,
            host_ttl: DNS_HOST_TTL,
            other_ttl: DNS_OTHER_TTL,
            priority: 0,
            weight: 0,
            properties,
        };

        Ok(this)
    }

    /// Returns a reference of the service fullname.
    ///
    /// This is useful, for example, in unregister.
    pub fn get_fullname(&self) -> &str {
        &self.fullname
    }

    /// Returns a reference of the properties from TXT records.
    pub fn get_properties(&self) -> &HashMap<String, String> {
        &self.properties
    }

    /// Returns the service's hostname.
    pub fn get_hostname(&self) -> &str {
        &self.server
    }

    /// Returns the service's port.
    pub fn get_port(&self) -> u16 {
        self.port
    }

    /// Returns the service's addresses
    pub fn get_addresses(&self) -> &HashSet<Ipv4Addr> {
        &self.addresses
    }

    /// Returns the service's TTL used for SRV and Address records.
    pub fn get_host_ttl(&self) -> u32 {
        self.host_ttl
    }

    /// Returns the service's TTL used for PTR and TXT records.
    pub fn get_other_ttl(&self) -> u32 {
        self.other_ttl
    }

    fn is_ready(&self) -> bool {
        let some_missing = self.ty_domain.is_empty()
            || self.fullname.is_empty()
            || self.server.is_empty()
            || self.port == 0
            || self.addresses.is_empty()
            || self.properties.is_empty();
        !some_missing
    }

    fn generate_txt(&self) -> Vec<u8> {
        encode_txt(&self.properties)
    }

    fn set_properties_from_txt(&mut self, txt: &[u8]) {
        self.properties = decode_txt(txt);
    }
}

#[derive(PartialEq)]
enum PacketState {
    Init = 0,
    Finished = 1,
}

/// Representation of an outgoing packet
struct DnsOutgoing {
    flags: u16,
    id: u16,
    multicast: bool,
    questions: Vec<DnsQuestion>,
    answers: Vec<(Box<dyn DnsRecordExt>, u64)>,
    authorities: Vec<DnsPointer>,
    additionals: Vec<DnsRecordBox>,
}

impl DnsOutgoing {
    fn new(flags: u16) -> Self {
        DnsOutgoing {
            flags,
            id: 0,
            multicast: true,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    fn is_query(&self) -> bool {
        (self.flags & FLAGS_QR_MASK) == FLAGS_QR_QUERY
    }

    fn _is_response(&self) -> bool {
        (self.flags & FLAGS_QR_MASK) == FLAGS_QR_RESPONSE
    }

    // Adds an additional answer

    // From: RFC 6763, DNS-Based Service Discovery, February 2013

    // 12.  DNS Additional Record Generation

    //    DNS has an efficiency feature whereby a DNS server may place
    //    additional records in the additional section of the DNS message.
    //    These additional records are records that the client did not
    //    explicitly request, but the server has reasonable grounds to expect
    //    that the client might request them shortly, so including them can
    //    save the client from having to issue additional queries.

    //    This section recommends which additional records SHOULD be generated
    //    to improve network efficiency, for both Unicast and Multicast DNS-SD
    //    responses.

    // 12.1.  PTR Records

    //    When including a DNS-SD Service Instance Enumeration or Selective
    //    Instance Enumeration (subtype) PTR record in a response packet, the
    //    server/responder SHOULD include the following additional records:

    //    o  The SRV record(s) named in the PTR rdata.
    //    o  The TXT record(s) named in the PTR rdata.
    //    o  All address records (type "A" and "AAAA") named in the SRV rdata.

    // 12.2.  SRV Records

    //    When including an SRV record in a response packet, the
    //    server/responder SHOULD include the following additional records:

    //    o  All address records (type "A" and "AAAA") named in the SRV rdata.
    fn add_additional_answer(&mut self, answer: DnsRecordBox) {
        debug!("add_additional_answer: {:?}", &answer);
        self.additionals.push(answer);
    }

    /// Returns true if `answer` is added to the outgoing msg.
    /// Returns false if `answer` was not added as it expired or suppressed by `msg`.
    fn add_answer(&mut self, msg: &DnsIncoming, answer: Box<dyn DnsRecordExt>) -> bool {
        debug!("Check for add_answer");
        if !answer.suppressed_by(msg) {
            return self.add_answer_at_time(answer, 0);
        }
        false
    }

    /// Returns true if `answer` is added to the outgoing msg.
    /// Returns false if the answer expired hence not added.
    fn add_answer_at_time(&mut self, answer: Box<dyn DnsRecordExt>, now: u64) -> bool {
        debug!("Check for add_answer_at_time");
        if now == 0 || !answer.get_record().is_expired(now) {
            debug!("add_answer push: {:?}", &answer);
            self.answers.push((answer, now));
            return true;
        }
        false
    }

    /// Adds PTR answer and SRV, TXT, ADDR answers.
    /// See https://tools.ietf.org/html/rfc6763#section-12.1
    fn add_answer_with_additionals(&mut self, msg: &DnsIncoming, service: &ServiceInfo) {
        let ptr_added = self.add_answer(
            msg,
            Box::new(DnsPointer::new(
                &service.ty_domain,
                TYPE_PTR,
                CLASS_IN,
                service.other_ttl,
                service.fullname.clone(),
            )),
        );

        if !ptr_added {
            debug!("answer was not added for msg {:?}", msg);
            return;
        }

        // Add recommended additional answers according to
        // https://tools.ietf.org/html/rfc6763#section-12.1.
        self.add_additional_answer(Box::new(DnsSrv::new(
            &service.fullname,
            CLASS_IN | CLASS_UNIQUE,
            service.host_ttl,
            service.priority,
            service.weight,
            service.port,
            service.server.clone(),
        )));

        self.add_additional_answer(Box::new(DnsTxt::new(
            &service.fullname,
            TYPE_TXT,
            CLASS_IN | CLASS_UNIQUE,
            service.host_ttl,
            service.generate_txt(),
        )));

        for address in &service.addresses {
            self.add_additional_answer(Box::new(DnsAddress::new(
                &service.server,
                TYPE_A,
                CLASS_IN | CLASS_UNIQUE,
                service.host_ttl,
                *address,
            )));
        }
    }

    fn add_question(&mut self, name: &str, qtype: u16) {
        let q = DnsQuestion {
            entry: DnsEntry::new(name.to_string(), qtype, CLASS_IN),
        };
        self.questions.push(q);
    }

    fn to_packet(&self) -> DnsOutPacket {
        let mut packet = DnsOutPacket::new();
        if packet.state != PacketState::Finished {
            for question in self.questions.iter() {
                packet.write_question(question);
            }

            let mut answer_count = 0;
            for (answer, time) in self.answers.iter() {
                if packet.write_record(answer.as_ref(), *time) {
                    answer_count += 1;
                }
            }

            let mut auth_count = 0;
            for auth in self.authorities.iter() {
                auth_count += if packet.write_record(auth, 0) { 1 } else { 0 };
            }

            let mut addi_count = 0;
            for addi in self.additionals.iter() {
                addi_count += if packet.write_record(addi.as_ref(), 0) {
                    1
                } else {
                    0
                };
            }

            packet.state = PacketState::Finished;

            packet.insert_short(0, addi_count);
            packet.insert_short(0, auth_count);
            packet.insert_short(0, answer_count);
            packet.insert_short(0, self.questions.len() as u16);
            packet.insert_short(0, self.flags);
            if self.multicast {
                packet.insert_short(0, 0);
            } else {
                packet.insert_short(0, self.id);
            }
        }

        packet
    }
}

struct DnsOutPacket {
    data: Vec<Vec<u8>>,
    size: usize,
    state: PacketState,
    names: HashMap<String, u16>, // k: name, v: offset
}

impl DnsOutPacket {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            size: 12,
            state: PacketState::Init,
            names: HashMap::new(),
        }
    }

    fn write_question(&mut self, question: &DnsQuestion) {
        self.write_name(&question.entry.name);
        self.write_short(question.entry.ty);
        self.write_short(question.entry.class);
    }

    /// Writes a record (answer, authoritative answer, additional)
    /// Returns true if a record is written successfully, otherwise false.
    fn write_record(&mut self, record_ext: &dyn DnsRecordExt, now: u64) -> bool {
        if self.state == PacketState::Finished {
            return false;
        }

        let start_data_length = self.data.len();
        let start_size = self.size;

        let record = record_ext.get_record();
        self.write_name(&record.entry.name);
        self.write_short(record.entry.ty);
        if record.entry.unique {
            // check "multicast"
            self.write_short(record.entry.class | CLASS_UNIQUE);
        } else {
            self.write_short(record.entry.class);
        }

        if now == 0 {
            self.write_u32(record.ttl);
        } else {
            self.write_u32(record.get_remaining_ttl(now));
        }

        let index = self.data.len();

        // Adjust size for the short we will write before this record
        self.size += 2;
        record_ext.write(self);
        self.size -= 2;

        let length: usize = self.data[index..].iter().map(|x| x.len()).sum();
        self.insert_short(index, length as u16);

        if self.size > MAX_MSG_ABSOLUTE {
            self.data.truncate(start_data_length);
            self.size = start_size;
            self.state = PacketState::Finished;
            return false;
        }

        true
    }

    fn insert_short(&mut self, index: usize, value: u16) {
        self.data.insert(index, value.to_be_bytes().to_vec());
        self.size += 2;
    }

    // Write name to packet
    //
    // [RFC1035]
    // 4.1.4. Message compression
    //
    // In order to reduce the size of messages, the domain system utilizes a
    // compression scheme which eliminates the repetition of domain names in a
    // message.  In this scheme, an entire domain name or a list of labels at
    // the end of a domain name is replaced with a pointer to a prior occurrence
    // of the same name.
    // The pointer takes the form of a two octet sequence:
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     | 1  1|                OFFSET                   |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // The first two bits are ones.  This allows a pointer to be distinguished
    // from a label, since the label must begin with two zero bits because
    // labels are restricted to 63 octets or less.  (The 10 and 01 combinations
    // are reserved for future use.)  The OFFSET field specifies an offset from
    // the start of the message (i.e., the first octet of the ID field in the
    // domain header).  A zero offset specifies the first byte of the ID field,
    // etc.
    fn write_name(&mut self, name: &str) {
        // ignore the ending "." if exists
        let end = name.len();
        let end = if end > 0 && &name[end - 1..] == "." {
            end - 1
        } else {
            end
        };

        let mut here = 0;
        while here < end {
            const POINTER_MASK: u16 = 0xC000;
            let remaining = &name[here..end];

            // Check if 'remaining' already appeared in this message
            match self.names.get(remaining).copied() {
                Some(offset) => {
                    let pointer = offset | POINTER_MASK;
                    self.write_short(pointer);
                    // println!(
                    //     "written pointer {} ({}) for {}",
                    //     pointer,
                    //     pointer ^ POINTER_MASK,
                    //     remaining
                    // );
                    break;
                }
                None => {
                    // Remember the remaining parts so we can point to it
                    self.names.insert(remaining.to_string(), self.size as u16);
                    // println!("set offset {} for {}", self.size, remaining);

                    // Find the current label to write into the packet
                    let stop = match remaining.find('.') {
                        Some(i) => here + i,
                        None => end,
                    };
                    let label = &name[here..stop];
                    self.write_utf8(label);

                    here = stop + 1; // move past the current label
                }
            }

            if here >= end {
                self.write_byte(0); // name ends with 0 if not using a pointer
            }
        }
    }

    fn write_utf8(&mut self, utf: &str) {
        assert!(utf.len() < 64);
        self.write_byte(utf.len() as u8);
        self.write_bytes(utf.as_bytes());
    }

    fn write_bytes(&mut self, s: &[u8]) {
        self.data.push(s.to_vec());
        self.size += s.len();
    }

    fn write_u32(&mut self, int: u32) {
        self.data.push(int.to_be_bytes().to_vec());
        self.size += 4;
    }

    fn write_short(&mut self, short: u16) {
        self.data.push(short.to_be_bytes().to_vec());
        self.size += 2;
    }

    fn write_byte(&mut self, byte: u8) {
        self.data.push(vec![byte]);
        self.size += 1;
    }
}

#[derive(PartialEq, Debug)]
struct DnsEntry {
    name: String, // always lower case.
    ty: u16,
    class: u16,
    unique: bool,
}

impl DnsEntry {
    fn new(name: String, ty: u16, class: u16) -> Self {
        Self {
            name,
            ty,
            class: class & CLASS_MASK,
            unique: (class & CLASS_UNIQUE) != 0,
        }
    }
}

/// A DNS question entry
#[derive(Debug)]
struct DnsQuestion {
    entry: DnsEntry,
}

/// A DNS record - like a DNS entry, but has a TTL
#[derive(Debug)]
struct DnsRecord {
    entry: DnsEntry,
    ttl: u32,     // in seconds, 0 means this record should not be cached
    created: u64, // UNIX time in millis
    refresh: u64, // UNIX time in millis
}

/// Returns the time in millis at which this record will have expired
/// by a certain percentage.
fn get_expiration_time(created: u64, ttl: u32, percent: u32) -> u64 {
    created + (ttl * percent * 10) as u64
}

impl DnsRecord {
    fn new(name: &str, ty: u16, class: u16, ttl: u32) -> Self {
        let created = current_time_millis();
        let refresh = get_expiration_time(created, ttl, 80);
        Self {
            entry: DnsEntry::new(name.to_string(), ty, class),
            ttl,
            created,
            refresh,
        }
    }

    fn is_expired(&self, now: u64) -> bool {
        get_expiration_time(self.created, self.ttl, 100) <= now
    }

    fn refresh_due(&self, now: u64) -> bool {
        now >= self.refresh
    }

    /// Updates the refresh time to be the same as the expire time so that
    /// there is no more refresh for this record.
    fn refresh_no_more(&mut self) {
        self.refresh = get_expiration_time(self.created, self.ttl, 100);
    }

    /// Returns the remaining TTL in seconds
    fn get_remaining_ttl(&self, now: u64) -> u32 {
        let remaining_millis = get_expiration_time(self.created, self.ttl, 100) - now;
        cmp::max(0, remaining_millis / 1000) as u32
    }

    fn reset_ttl(&mut self, other: &DnsRecord) {
        self.ttl = other.ttl;
        self.created = other.created;
        self.refresh = get_expiration_time(self.created, self.ttl, 80);
    }
}

impl PartialEq for DnsRecord {
    fn eq(&self, other: &Self) -> bool {
        self.entry == other.entry
    }
}

trait DnsRecordExt: fmt::Debug {
    fn get_record(&self) -> &DnsRecord;
    fn get_record_mut(&mut self) -> &mut DnsRecord;
    fn write(&self, packet: &mut DnsOutPacket);
    fn any(&self) -> &dyn Any;

    fn matches(&self, other: &dyn DnsRecordExt) -> bool;

    fn get_name(&self) -> &str {
        self.get_record().entry.name.as_str()
    }
    fn get_type(&self) -> u16 {
        self.get_record().entry.ty
    }

    fn reset_ttl(&mut self, other: &dyn DnsRecordExt) {
        self.get_record_mut().reset_ttl(other.get_record());
    }

    /// Returns true if another record has matched content,
    /// and if its TTL is at least half of this record's.
    fn suppressed_by_answer(&self, other: &dyn DnsRecordExt) -> bool {
        self.matches(other) && (other.get_record().ttl > self.get_record().ttl / 2)
    }

    /// Required by RFC 6762 Section 7.1: Known-Answer Suppression.
    fn suppressed_by(&self, msg: &DnsIncoming) -> bool {
        for answer in msg.answers.iter() {
            if self.suppressed_by_answer(answer.as_ref()) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug)]
struct DnsAddress {
    record: DnsRecord,
    address: Ipv4Addr,
}

impl DnsAddress {
    fn new(name: &str, ty: u16, class: u16, ttl: u32, address: Ipv4Addr) -> Self {
        let record = DnsRecord::new(name, ty, class, ttl);
        Self { record, address }
    }
}

impl DnsRecordExt for DnsAddress {
    fn get_record(&self) -> &DnsRecord {
        &self.record
    }

    fn get_record_mut(&mut self) -> &mut DnsRecord {
        &mut self.record
    }

    fn write(&self, packet: &mut DnsOutPacket) {
        packet.write_bytes(self.address.octets().as_ref());
    }

    fn any(&self) -> &dyn Any {
        self
    }

    fn matches(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_a) = other.any().downcast_ref::<DnsAddress>() {
            return self.address == other_a.address && self.record.entry == other_a.record.entry;
        }
        false
    }
}

/// A DNS pointer record
#[derive(Debug)]
struct DnsPointer {
    record: DnsRecord,
    alias: String, // the full name of Service Instance
}

impl DnsPointer {
    fn new(name: &str, ty: u16, class: u16, ttl: u32, alias: String) -> Self {
        let record = DnsRecord::new(name, ty, class, ttl);
        Self { record, alias }
    }
}

impl DnsRecordExt for DnsPointer {
    fn get_record(&self) -> &DnsRecord {
        &self.record
    }

    fn get_record_mut(&mut self) -> &mut DnsRecord {
        &mut self.record
    }

    fn write(&self, packet: &mut DnsOutPacket) {
        packet.write_name(&self.alias);
    }

    fn any(&self) -> &dyn Any {
        self
    }

    fn matches(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_ptr) = other.any().downcast_ref::<DnsPointer>() {
            return self.alias == other_ptr.alias && self.record.entry == other_ptr.record.entry;
        }
        false
    }
}

// In common cases, there is one and only one SRV record for a particular fullname.
#[derive(Debug)]
struct DnsSrv {
    record: DnsRecord,
    priority: u16,
    // lower number means higher priority. Should be 0 in common cases.
    weight: u16,
    // Should be 0 in common cases
    host: String,
    port: u16,
}

impl DnsSrv {
    fn new(
        name: &str,
        class: u16,
        ttl: u32,
        priority: u16,
        weight: u16,
        port: u16,
        host: String,
    ) -> Self {
        let record = DnsRecord::new(name, TYPE_SRV, class, ttl);
        Self {
            record,
            priority,
            weight,
            host,
            port,
        }
    }
}

impl DnsRecordExt for DnsSrv {
    fn get_record(&self) -> &DnsRecord {
        &self.record
    }

    fn get_record_mut(&mut self) -> &mut DnsRecord {
        &mut self.record
    }

    fn write(&self, packet: &mut DnsOutPacket) {
        packet.write_short(self.priority);
        packet.write_short(self.weight);
        packet.write_short(self.port);
        packet.write_name(&self.host);
    }

    fn any(&self) -> &dyn Any {
        self
    }

    fn matches(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_svc) = other.any().downcast_ref::<DnsSrv>() {
            return self.host == other_svc.host
                && self.port == other_svc.port
                && self.weight == other_svc.weight
                && self.priority == other_svc.priority
                && self.record.entry == other_svc.record.entry;
        }
        false
    }
}

// From RFC 6763 section 6:
//
// The format of each constituent string within the DNS TXT record is a
// single length byte, followed by 0-255 bytes of text data.
//
// DNS-SD uses DNS TXT records to store arbitrary key/value pairs
//    conveying additional information about the named service.  Each
//    key/value pair is encoded as its own constituent string within the
//    DNS TXT record, in the form "key=value" (without the quotation
//    marks).  Everything up to the first '=' character is the key (Section
//    6.4).  Everything after the first '=' character to the end of the
//    string (including subsequent '=' characters, if any) is the value
#[derive(Debug)]
struct DnsTxt {
    record: DnsRecord,
    text: Vec<u8>,
}

impl DnsTxt {
    fn new(name: &str, ty: u16, class: u16, ttl: u32, text: Vec<u8>) -> Self {
        let record = DnsRecord::new(name, ty, class, ttl);
        Self { record, text }
    }
}

impl DnsRecordExt for DnsTxt {
    fn get_record(&self) -> &DnsRecord {
        &self.record
    }

    fn get_record_mut(&mut self) -> &mut DnsRecord {
        &mut self.record
    }

    fn write(&self, packet: &mut DnsOutPacket) {
        debug!("writing text length {}", &self.text.len());
        packet.write_bytes(&self.text);
    }

    fn any(&self) -> &dyn Any {
        self
    }

    fn matches(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_txt) = other.any().downcast_ref::<DnsTxt>() {
            return self.text == other_txt.text && self.record.entry == other_txt.record.entry;
        }
        false
    }
}

/// A DNS host information record
#[derive(Debug)]
struct DnsHostInfo {
    record: DnsRecord,
    cpu: String,
    os: String,
}

impl DnsHostInfo {
    fn new(name: &str, ty: u16, class: u16, ttl: u32, cpu: String, os: String) -> Self {
        let record = DnsRecord::new(name, ty, class, ttl);
        Self { record, cpu, os }
    }
}

impl DnsRecordExt for DnsHostInfo {
    fn get_record(&self) -> &DnsRecord {
        &self.record
    }

    fn get_record_mut(&mut self) -> &mut DnsRecord {
        &mut self.record
    }

    fn write(&self, packet: &mut DnsOutPacket) {
        println!("writing HInfo: cpu {} os {}", &self.cpu, &self.os);
        packet.write_bytes(self.cpu.as_bytes());
        packet.write_bytes(self.os.as_bytes());
    }

    fn any(&self) -> &dyn Any {
        self
    }

    fn matches(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_hinfo) = other.any().downcast_ref::<DnsHostInfo>() {
            return self.cpu == other_hinfo.cpu
                && self.os == other_hinfo.os
                && self.record.entry == other_hinfo.record.entry;
        }
        false
    }
}

/// Validate the service name in a fully qualified name.
///
/// A Full Name = <Instance>.<Service>.<Domain>
/// The only `<Domain>` supported are "._tcp.local." and "._udp.local.".
fn check_service_name(fullname: &str) -> Result<()> {
    if !(fullname.ends_with("._tcp.local.") || fullname.ends_with("._udp.local.")) {
        return Err(e_fmt!(
            "Service {} must end with '._tcp.local.' or '._udp.local.'",
            fullname
        ));
    }

    let domain_len = "._tcp.local.".len();
    let remaining: Vec<&str> = fullname[..fullname.len() - domain_len].split('.').collect();
    let name = remaining.last().ok_or_else(|| e_fmt!("No service name"))?;

    if &name[0..1] != "_" {
        return Err(e_fmt!("Service name must start with '_'"));
    }

    let name = &name[1..];

    if name.len() > 15 {
        return Err(e_fmt!("Service name must be <= 15 bytes"));
    }

    if name.contains("--") {
        return Err(e_fmt!("Service name must not contain '--'"));
    }

    if name.starts_with('-') || name.ends_with('-') {
        return Err(e_fmt!("Service name (%s) may not start or end with '-'"));
    }

    let ascii_count = name.chars().filter(|c| c.is_ascii_alphabetic()).count();
    if ascii_count < 1 {
        return Err(e_fmt!(
            "Service name must contain at least one letter (eg: 'A-Za-z')"
        ));
    }

    Ok(())
}

#[derive(Debug)]
struct DnsIncoming {
    offset: usize,
    data: Vec<u8>,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecordBox>,
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DnsIncoming {
    fn new(data: Vec<u8>) -> Result<Self> {
        let mut incoming = Self {
            offset: 0,
            data,
            questions: Vec::new(),
            answers: Vec::new(),
            id: 0,
            flags: 0,
            num_questions: 0,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        };

        incoming.read_header();
        incoming.read_questions()?;
        incoming.read_others()?;
        Ok(incoming)
    }

    fn is_query(&self) -> bool {
        (self.flags & FLAGS_QR_MASK) == FLAGS_QR_QUERY
    }

    fn is_response(&self) -> bool {
        (self.flags & FLAGS_QR_MASK) == FLAGS_QR_RESPONSE
    }

    // Returns the number of bytes read
    fn read_header(&mut self) {
        let data = &self.data[0..];
        self.id = u16_from_be_slice(&data[..2]);
        self.flags = u16_from_be_slice(&data[2..4]);
        self.num_questions = u16_from_be_slice(&data[4..6]);
        self.num_answers = u16_from_be_slice(&data[6..8]);
        self.num_authorities = u16_from_be_slice(&data[8..10]);
        self.num_additionals = u16_from_be_slice(&data[10..12]);

        self.offset = 12;

        debug!(
            "read_header: id {}, {} questions {} answers {} authorities {} additionals",
            self.id,
            self.num_questions,
            self.num_answers,
            self.num_authorities,
            self.num_additionals
        );
    }

    fn read_questions(&mut self) -> Result<()> {
        debug!("read_questions: {}", &self.num_questions);
        for _i in 0..self.num_questions {
            let name = self.read_name()?;

            let data = &self.data[self.offset..];
            let ty = u16_from_be_slice(&data[..2]);
            let class = u16_from_be_slice(&data[2..4]);
            self.offset += 4;

            self.questions.push(DnsQuestion {
                entry: DnsEntry::new(name, ty, class),
            });
        }
        Ok(())
    }

    fn read_others(&mut self) -> Result<()> {
        let n = self.num_answers + self.num_authorities + self.num_additionals;
        debug!("read_others: {}", n);
        for _ in 0..n {
            let name = self.read_name()?;
            let slice = &self.data[self.offset..];
            let ty = u16_from_be_slice(&slice[..2]);
            let class = u16_from_be_slice(&slice[2..4]);
            let ttl = u32_from_be_slice(&slice[4..8]);
            let length = u16_from_be_slice(&slice[8..10]) as usize;
            self.offset += 10;
            // print!("name: {} ", &name);
            // println!(
            //     "type {} class {} ttl {} length {}",
            //     &ty, &class, &ttl, &length
            // );

            let rec: Option<DnsRecordBox> = match ty {
                TYPE_A => Some(Box::new(DnsAddress::new(
                    &name,
                    ty,
                    class,
                    ttl,
                    self.read_ipv4(),
                ))),
                TYPE_CNAME | TYPE_PTR => Some(Box::new(DnsPointer::new(
                    &name,
                    ty,
                    class,
                    ttl,
                    self.read_name()?,
                ))),
                TYPE_TXT => Some(Box::new(DnsTxt::new(
                    &name,
                    ty,
                    class,
                    ttl,
                    self.read_vec(length),
                ))),
                TYPE_SRV => Some(Box::new(DnsSrv::new(
                    &name,
                    class,
                    ttl,
                    self.read_u16(),
                    self.read_u16(),
                    self.read_u16(),
                    self.read_name()?,
                ))),
                TYPE_HINFO => Some(Box::new(DnsHostInfo::new(
                    &name,
                    ty,
                    class,
                    ttl,
                    self.read_char_string(),
                    self.read_char_string(),
                ))),
                TYPE_AAAA => {
                    debug!("We don't support IPv6 TYPE_AAAA records");
                    self.offset += length;
                    None
                }
                _ => {
                    self.offset += length;
                    None
                }
            };

            if let Some(record) = rec {
                debug!("{:?}", &record);
                self.answers.push(record);
            }
        }

        Ok(())
    }

    fn read_char_string(&mut self) -> String {
        let length = self.data[self.offset];
        self.offset += 1;
        self.read_string(length as usize)
    }

    fn read_u16(&mut self) -> u16 {
        let slice = &self.data[self.offset..];
        let num = u16_from_be_slice(&slice[..2]);
        self.offset += 2;
        num
    }

    fn read_vec(&mut self, length: usize) -> Vec<u8> {
        let v = self.data[self.offset..self.offset + length].to_vec();
        self.offset += length;
        v
    }

    fn read_ipv4(&mut self) -> Ipv4Addr {
        let bytes = &self.data[self.offset..self.offset + 4];
        self.offset += bytes.len();
        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
    }

    fn read_string(&mut self, length: usize) -> String {
        let s = str::from_utf8(&self.data[self.offset..self.offset + length]).unwrap();
        self.offset += length;
        s.to_string()
    }

    fn read_name(&mut self) -> Result<String> {
        let data = &self.data[..];
        let mut offset = self.offset;
        let mut name = "".to_string();
        let mut at_end = false;

        loop {
            let length = data[offset];
            if length == 0 {
                if !at_end {
                    self.offset = offset + 1;
                }
                break; // The end of the name
            }

            match length & 0xC0 {
                // Check the first 2 bits
                0x00 => {
                    // regular utf8 string with length
                    offset += 1;
                    name += str::from_utf8(&data[offset..(offset + length as usize)])
                        .map_err(|e| e_fmt!("read_name: from_utf8: {}", e))?;
                    name += ".";
                    offset += length as usize;
                }
                0xC0 => {
                    let pointer = (u16_from_be_slice(&data[offset..]) ^ 0xC000) as usize;
                    if pointer >= offset {
                        println!("data: {:x?}", data);
                        panic!(
                            "Bad name: pointer {} offset {} self.offset {}",
                            &pointer, &offset, &self.offset
                        );
                    }

                    if !at_end {
                        self.offset = offset + 2;
                        at_end = true;
                    }
                    offset = pointer;
                }
                _ => {
                    error!("self offset {}, data: {:x?}", &self.offset, data);
                    panic!(
                        "Bad domain name at length byte 0x{:x} (offset {})",
                        length, offset
                    );
                }
            };
        }

        Ok(name)
    }
}

fn u16_from_be_slice(bytes: &[u8]) -> u16 {
    let u8_array: [u8; 2] = [bytes[0], bytes[1]];
    u16::from_be_bytes(u8_array)
}

fn u32_from_be_slice(s: &[u8]) -> u32 {
    let u8_array: [u8; 4] = [s[0], s[1], s[2], s[3]];
    u32::from_be_bytes(u8_array)
}

// Convert from properties key/value pairs to DNS TXT record content
fn encode_txt(map: &HashMap<String, String>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (k, v) in map {
        let s = format!("{}={}", k, v);
        bytes.push(s.len().try_into().unwrap());
        bytes.extend_from_slice(s.as_bytes());
    }
    if bytes.is_empty() {
        bytes.push(0);
    }
    bytes
}

// Convert from DNS TXT record content to key/value pairs
fn decode_txt(txt: &[u8]) -> HashMap<String, String> {
    let mut kv_map = HashMap::new();
    let mut offset = 0;
    while offset < txt.len() {
        let length = txt[offset] as usize;
        if length == 0 {
            break; // reached the end
        }
        offset += 1; // move over the length byte
        match String::from_utf8(txt[offset..offset + length].to_vec()) {
            Ok(kv_string) => match kv_string.find('=') {
                Some(idx) => {
                    let k = &kv_string[..idx];
                    let v = &kv_string[idx + 1..];
                    kv_map.insert(k.to_string(), v.to_string());
                }
                None => error!("cannot find = sign inside {}", &kv_string),
            },
            Err(e) => error!("failed to convert to String from key/value pair: {}", e),
        }
        offset += length;
    }

    kv_map
}

fn call_listener(
    listeners_map: &HashMap<String, Sender<ServiceEvent>>,
    ty_domain: &str,
    event: ServiceEvent,
) {
    if let Some(listener) = listeners_map.get(ty_domain) {
        match listener.send(event) {
            Ok(()) => debug!("Sent event to listener successfully"),
            Err(e) => error!("Failed to send event: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{decode_txt, encode_txt};

    #[test]
    fn test_txt_encode_decode() {
        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        map.insert("key2".to_string(), "value2".to_string());

        // test encode
        let encoded = encode_txt(&map);
        assert_eq!(
            encoded.len(),
            "key1=".len() + "value1".len() + "key2=".len() + "value2".len() + 2
        );
        assert_eq!(encoded[0] as usize, "key1=".len() + "value1".len());

        // test decode
        let decoded = decode_txt(&encoded);
        assert_eq!(map, decoded);
    }
}
