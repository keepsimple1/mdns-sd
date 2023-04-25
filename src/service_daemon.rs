//! Service daemon for mDNS Service Discovery.

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
#[cfg(feature = "logging")]
use crate::log::{debug, error};
use crate::{
    dns_parser::{
        current_time_millis, DnsAddress, DnsIncoming, DnsOutgoing, DnsPointer, DnsRecordBox,
        DnsRecordExt, DnsSrv, DnsTxt, CLASS_IN, CLASS_UNIQUE, FLAGS_AA, FLAGS_QR_QUERY,
        FLAGS_QR_RESPONSE, MAX_MSG_ABSOLUTE, TYPE_A, TYPE_ANY, TYPE_PTR, TYPE_SRV, TYPE_TXT,
    },
    error::{Error, Result},
    service_info::{split_sub_domain, ServiceInfo},
    Receiver,
};
use flume::{bounded, Sender, TrySendError};
use if_addrs::{IfAddr, Ifv4Addr};
use polling::Poller;
use socket2::{SockAddr, Socket};
use std::{
    cmp,
    collections::{HashMap, HashSet},
    fmt,
    io::Read,
    net::{Ipv4Addr, SocketAddrV4},
    str, thread,
    time::Duration,
    vec,
};

/// A simple macro to report all kinds of errors.
macro_rules! e_fmt {
  ($($arg:tt)+) => {
      Error::Msg(format!($($arg)+))
  };
}

/// The default max length of the service name without domain, not including the
/// leading underscore (`_`). It is set to 15 per
/// [RFC 6763 section 7.2](https://www.rfc-editor.org/rfc/rfc6763#section-7.2).
pub const SERVICE_NAME_LEN_MAX_DEFAULT: u8 = 15;

const MDNS_PORT: u16 = 5353;
const GROUP_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

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
        let zc = Zeroconf::new()?;
        let (sender, receiver) = bounded(100);

        // Spawn the daemon thread
        thread::Builder::new()
            .name("mDNS_daemon".to_string())
            .spawn(move || Self::run(zc, receiver))
            .map_err(|e| e_fmt!("thread builder failed to spawn: {}", e))?;

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
    ///
    /// If `service_info` has no addresses yet and its `addr_auto` is enabled,
    /// this method will automatically fill in addresses from the host.
    pub fn register(&self, mut service_info: ServiceInfo) -> Result<()> {
        check_service_name(service_info.get_fullname())?;

        if service_info.is_addr_auto() {
            for ifv4 in my_ipv4_interfaces() {
                service_info.insert_ipv4addr(ifv4.ip);
            }
        }

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

    /// Starts to monitor events from the daemon.
    ///
    /// Returns a channel [`Receiver`] of [`DaemonEvent`].
    pub fn monitor(&self) -> Result<Receiver<DaemonEvent>> {
        let (resp_s, resp_r) = bounded(100);
        self.sender
            .try_send(Command::Monitor(resp_s))
            .map_err(|e| match e {
                TrySendError::Full(_) => Error::Again,
                e => e_fmt!("starts a monitor: try_send: {}", e),
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

    /// Change the max length allowed for a service name.
    ///
    /// As RFC 6763 defines a length max for a service name, a user should not call
    /// this method unless they have to. See [`SERVICE_NAME_LEN_MAX_DEFAULT`].
    ///
    /// `len_max` is capped at an internal limit, which is currently 30.
    pub fn set_service_name_len_max(&self, len_max: u8) -> Result<()> {
        const SERVICE_NAME_LEN_MAX_LIMIT: u8 = 30; // Double the default length max.

        if len_max > SERVICE_NAME_LEN_MAX_LIMIT {
            return Err(Error::Msg(format!(
                "service name length max {} is too large",
                len_max
            )));
        }

        self.sender
            .try_send(Command::SetOption(DaemonOption::ServiceNameLenMax(len_max)))
            .map_err(|e| match e {
                TrySendError::Full(_) => Error::Again,
                e => e_fmt!("flume::channel::send failed: {}", e),
            })
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
        for (ipv4, if_sock) in zc.intf_socks.iter() {
            // It is OK to convert to `usize` here as we only support 32-bit
            // or 64-bit platforms.
            let key = u32::from(*ipv4) as usize;
            if let Err(e) = zc.poller.add(&if_sock.sock, polling::Event::readable(key)) {
                error!("add socket of {:?} to poller: {}", ipv4, e);
                return;
            }
        }
        let mut events = Vec::new();
        let timeout = Duration::from_millis(20); // moderate frequency for polling.

        const IP_CHECK_INTERVAL_MILLIS: u64 = 2000;
        let mut next_ip_check = current_time_millis() + IP_CHECK_INTERVAL_MILLIS;

        loop {
            // process incoming packets.
            events.clear();
            match zc.poller.wait(&mut events, Some(timeout)) {
                Ok(_) => {
                    for ev in events.iter() {
                        // Read until no more packets available.
                        let ipv4 = (ev.key as u32).into();
                        while zc.handle_read(&ipv4) {}

                        if let Some(intf_sock) = zc.intf_socks.get(&ipv4) {
                            if let Err(e) = zc
                                .poller
                                .modify(&intf_sock.sock, polling::Event::readable(ev.key))
                            {
                                error!("modify poller for IP {}: {}", &ipv4, e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => error!("failed to select from sockets: {}", e),
            }

            // Send out additional queries for unresolved instances, where
            // the early responses did not have SRV records.
            zc.query_missing_srv();

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

            // check IP changes.
            let now = current_time_millis();
            if now > next_ip_check {
                next_ip_check = now + IP_CHECK_INTERVAL_MILLIS;
                zc.check_ip_changes();
            }
        }
    }

    /// The entry point that executes all commands received by the daemon.
    ///
    /// `repeating`: whether this is a retransmission.
    fn exec_command(zc: &mut Zeroconf, command: Command, repeating: bool) {
        match command {
            Command::Browse(ty, next_delay, listener) => {
                let addr_list: Vec<_> = zc.intf_socks.keys().collect();
                if let Err(e) = listener.send(ServiceEvent::SearchStarted(format!(
                    "{} on addrs {:?}",
                    &ty, &addr_list
                ))) {
                    error!(
                        "Failed to send SearchStarted({})(repeating:{}): {}",
                        &ty, repeating, e
                    );
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
                        let outgoing_addrs = zc.send_unsolicited_response(info);
                        if !outgoing_addrs.is_empty() {
                            zc.notify_monitors(DaemonEvent::Announce(
                                fullname,
                                format!("{:?}", &outgoing_addrs),
                            ));
                        }
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
                        for (ipv4, intf_sock) in zc.intf_socks.iter() {
                            let packet = zc.unregister_service(&info, intf_sock);
                            // repeat for one time just in case some peers miss the message
                            if !repeating && !packet.is_empty() {
                                let next_time = current_time_millis() + 120;
                                zc.retransmissions.push(ReRun {
                                    next_time,
                                    command: Command::UnregisterResend(packet, *ipv4),
                                });
                            }
                        }
                        zc.increase_counter(Counter::Unregister, 1);
                        UnregisterStatus::OK
                    }
                };
                if let Err(e) = resp_s.send(response) {
                    error!("unregister: failed to send response: {}", e);
                }
            }

            Command::UnregisterResend(packet, ipv4) => {
                if let Some(intf_sock) = zc.intf_socks.get(&ipv4) {
                    debug!("Send a packet length of {}", packet.len());
                    send_packet(&packet[..], &zc.broadcast_addr, intf_sock);
                    zc.increase_counter(Counter::UnregisterResend, 1);
                }
            }

            Command::StopBrowse(ty_domain) => match zc.queriers.remove_entry(&ty_domain) {
                None => error!("StopBrowse: cannot find querier for {}", &ty_domain),
                Some((ty, sender)) => {
                    // Remove pending browse commands in the reruns.
                    debug!("StopBrowse: removed queryer for {}", &ty);
                    let mut i = 0;
                    while i < zc.retransmissions.len() {
                        if let Command::Browse(t, _, _) = &zc.retransmissions[i].command {
                            if t == &ty {
                                zc.retransmissions.remove(i);
                                debug!("StopBrowse: removed retransmission for {}", &ty);
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

            Command::Monitor(resp_s) => {
                zc.monitors.push(resp_s);
            }

            Command::SetOption(daemon_opt) => {
                zc.process_set_option(daemon_opt);
            }

            _ => {
                error!("unexpected command: {:?}", &command);
            }
        }
    }
}

/// Creates a new UDP socket that uses `intf_ip` to send and recv multicast.
fn new_socket_bind(intf_ip: &Ipv4Addr) -> Result<Socket> {
    // Use the same socket for receiving and sending multicast packets.
    // Such socket has to bind to INADDR_ANY.
    let sock = new_socket(Ipv4Addr::new(0, 0, 0, 0), MDNS_PORT, true)?;

    // Join mDNS group to receive packets.
    sock.join_multicast_v4(&GROUP_ADDR, intf_ip)
        .map_err(|e| e_fmt!("join multicast group on addr {}: {}", intf_ip, e))?;

    // Set IP_MULTICAST_IF to send packets.
    sock.set_multicast_if_v4(intf_ip)
        .map_err(|e| e_fmt!("set multicast_if on addr {}: {}", intf_ip, e))?;

    // Test if we can send packets successfully.
    let multicast_addr = SocketAddrV4::new(GROUP_ADDR, MDNS_PORT).into();
    let test_packet = DnsOutgoing::new(0).to_packet_data();
    sock.send_to(&test_packet, &multicast_addr)
        .map_err(|e| e_fmt!("send multicast packet on addr {}: {}", intf_ip, e))?;

    Ok(sock)
}

/// Creates a new UDP socket to bind to `port` with REUSEPORT option.
/// `non_block` indicates whether to set O_NONBLOCK for the socket.
fn new_socket(ipv4: Ipv4Addr, port: u16, non_block: bool) -> Result<Socket> {
    let fd = Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
        .map_err(|e| e_fmt!("create socket failed: {}", e))?;

    fd.set_reuse_address(true)
        .map_err(|e| e_fmt!("set ReuseAddr failed: {}", e))?;
    #[cfg(unix)] // this is currently restricted to Unix's in socket2
    fd.set_reuse_port(true)
        .map_err(|e| e_fmt!("set ReusePort failed: {}", e))?;

    if non_block {
        fd.set_nonblocking(true)
            .map_err(|e| e_fmt!("set O_NONBLOCK: {}", e))?;
    }

    let inet_addr = SocketAddrV4::new(ipv4, port);
    fd.bind(&inet_addr.into())
        .map_err(|e| e_fmt!("socket bind to {} failed: {}", &inet_addr, e))?;

    debug!("new socket bind to {}", &inet_addr);
    Ok(fd)
}

struct ReRun {
    next_time: u64,
    command: Command,
}

/// Represents a local IP interface and a socket to recv/send
/// multicast packets on the interface.
#[derive(Debug)]
struct IntfSock {
    intf: Ifv4Addr,
    sock: Socket,
}

/// A struct holding the state. It was inspired by `zeroconf` package in Python.
struct Zeroconf {
    /// Local interfaces with sockets to recv/send on these interfaces.
    intf_socks: HashMap<Ipv4Addr, IntfSock>,

    /// Local registered services， keyed by service full names.
    my_services: HashMap<String, ServiceInfo>,

    /// Well-known mDNS IPv4 address and port
    broadcast_addr: SockAddr,

    cache: DnsCache,

    /// Active "Browse" commands.
    queriers: HashMap<String, Sender<ServiceEvent>>, // <ty_domain, channel::sender>

    /// All repeating transmissions.
    retransmissions: Vec<ReRun>,

    counters: Metrics,

    /// Waits for incoming packets.
    poller: Poller,

    /// Channels to notify events.
    monitors: Vec<Sender<DaemonEvent>>,

    /// Options
    service_name_len_max: u8,
}

impl Zeroconf {
    fn new() -> Result<Self> {
        let poller = Poller::new().map_err(|e| e_fmt!("create Poller: {}", e))?;

        // Get IPv4 interfaces.
        let my_ifv4addrs = my_ipv4_interfaces();

        // Create a socket for every IPv4 interface.
        let mut intf_socks = HashMap::new();
        for intf in my_ifv4addrs {
            let sock = match new_socket_bind(&intf.ip) {
                Ok(s) => s,
                Err(e) => {
                    debug!("bind a socket to {}: {}. Skipped.", &intf.ip, e);
                    continue;
                }
            };
            intf_socks.insert(intf.ip, IntfSock { intf, sock });
        }

        let broadcast_addr = SocketAddrV4::new(GROUP_ADDR, MDNS_PORT).into();
        let monitors = Vec::new();
        let service_name_len_max = SERVICE_NAME_LEN_MAX_DEFAULT;

        Ok(Self {
            intf_socks,
            my_services: HashMap::new(),
            broadcast_addr,
            cache: DnsCache::new(),
            queriers: HashMap::new(),
            retransmissions: Vec::new(),
            counters: HashMap::new(),
            poller,
            monitors,
            service_name_len_max,
        })
    }

    fn process_set_option(&mut self, daemon_opt: DaemonOption) {
        match daemon_opt {
            DaemonOption::ServiceNameLenMax(length) => self.service_name_len_max = length,
        }
    }

    fn notify_monitors(&mut self, event: DaemonEvent) {
        // Only retain the monitors that are still connected.
        self.monitors.retain(|sender| {
            if let Err(e) = sender.try_send(event.clone()) {
                error!("notify_monitors: try_send: {}", &e);
                if matches!(e, TrySendError::Disconnected(_)) {
                    return false; // This monitor is dropped.
                }
            }
            true
        });
    }

    /// Add `addr` in my services that enabled `addr_auto`.
    fn add_addr_in_my_services(&mut self, addr: Ipv4Addr) {
        for (_, service_info) in self.my_services.iter_mut() {
            if service_info.is_addr_auto() {
                service_info.insert_ipv4addr(addr);
            }
        }
    }

    /// Remove `addr` in my services that enabled `addr_auto`.
    fn del_addr_in_my_services(&mut self, addr: &Ipv4Addr) {
        for (_, service_info) in self.my_services.iter_mut() {
            if service_info.is_addr_auto() {
                service_info.remove_ipv4addr(addr);
            }
        }
    }

    /// Check for IP changes and update intf_socks as needed.
    fn check_ip_changes(&mut self) {
        // Get the current IPv4 interfaces.
        let my_ifv4addrs = my_ipv4_interfaces();

        // Remove unused sockets in the poller.
        let deleted_addrs = self
            .intf_socks
            .iter()
            .filter_map(|(_, if_sock)| {
                if !my_ifv4addrs.contains(&if_sock.intf) {
                    if let Err(e) = self.poller.delete(&if_sock.sock) {
                        error!("check_ip_changes: poller.delete {:?}: {}", &if_sock.intf, e);
                    }
                    Some(if_sock.intf.ip)
                } else {
                    None
                }
            })
            .collect::<Vec<Ipv4Addr>>();

        // Remove deleted addrs from my services that enabled `addr_auto`.
        for ipv4 in deleted_addrs.iter() {
            self.del_addr_in_my_services(ipv4);
            self.notify_monitors(DaemonEvent::Ipv4Del(*ipv4));
        }

        // Keep the interfaces only if they still exist.
        self.intf_socks
            .retain(|_, v| my_ifv4addrs.contains(&v.intf));

        // Add newly found interfaces.
        for intf in my_ifv4addrs {
            // Skip existing interfaces.
            if self.intf_socks.get(&intf.ip).is_some() {
                continue;
            }

            // Bind the new interface.
            let new_ip = intf.ip;
            let sock = match new_socket_bind(&new_ip) {
                Ok(s) => {
                    debug!("check_ip_changes: bind {}", &intf.ip);
                    s
                }
                Err(e) => {
                    debug!("bind a socket to {}: {}. Skipped.", &intf.ip, e);
                    continue;
                }
            };

            // Add the new interface into the poller.
            let key = u32::from(new_ip) as usize;
            if let Err(e) = self.poller.add(&sock, polling::Event::readable(key)) {
                error!("check_ip_changes: poller add ip {}: {}", new_ip, e);
            }

            self.intf_socks.insert(new_ip, IntfSock { intf, sock });

            self.add_addr_in_my_services(new_ip);

            // Notify the monitors.
            self.notify_monitors(DaemonEvent::Ipv4Add(new_ip));
        }
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
        // Check the service name length.
        if let Err(e) = check_service_name_length(info.get_type(), self.service_name_len_max) {
            error!("check_service_name_length: {}", &e);
            self.notify_monitors(DaemonEvent::Error(e));
            return;
        }

        let outgoing_addrs = self.send_unsolicited_response(&info);
        if !outgoing_addrs.is_empty() {
            self.notify_monitors(DaemonEvent::Announce(
                info.get_fullname().to_string(),
                format!("{:?}", &outgoing_addrs),
            ));
        }

        // RFC 6762 section 8.3.
        // ..The Multicast DNS responder MUST send at least two unsolicited
        //    responses, one second apart.
        let next_time = current_time_millis() + 1000;

        // The key has to be lower case letter as DNS record name is case insensitive.
        // The info will have the original name.
        let service_fullname = info.get_fullname().to_lowercase();
        self.retransmissions.push(ReRun {
            next_time,
            command: Command::RegisterResend(service_fullname.clone()),
        });
        self.my_services.insert(service_fullname, info);
    }

    /// Sends out annoucement of `info` on every valid interface.
    /// Returns the list of interface IPs that sent out the annoucement.
    fn send_unsolicited_response(&self, info: &ServiceInfo) -> Vec<Ipv4Addr> {
        let mut outgoing_addrs = Vec::new();
        for (_, intf_sock) in self.intf_socks.iter() {
            if self.broadcast_service_on_intf(info, intf_sock) {
                outgoing_addrs.push(intf_sock.intf.ip);
            }
        }
        outgoing_addrs
    }

    /// Send an unsolicited response for owned service via `intf_sock`.
    /// Returns true if sent out successfully.
    fn broadcast_service_on_intf(&self, info: &ServiceInfo, intf_sock: &IntfSock) -> bool {
        let service_fullname = info.get_fullname();
        debug!("broadcast service {}", service_fullname);
        let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
        out.add_answer_at_time(
            Box::new(DnsPointer::new(
                info.get_type(),
                TYPE_PTR,
                CLASS_IN,
                info.get_other_ttl(),
                info.get_fullname().to_string(),
            )),
            0,
        );

        if let Some(sub) = info.get_subtype() {
            debug!("Adding subdomain {}", sub);
            out.add_answer_at_time(
                Box::new(DnsPointer::new(
                    sub,
                    TYPE_PTR,
                    CLASS_IN,
                    info.get_other_ttl(),
                    info.get_fullname().to_string(),
                )),
                0,
            );
        }

        out.add_answer_at_time(
            Box::new(DnsSrv::new(
                info.get_fullname(),
                CLASS_IN | CLASS_UNIQUE,
                info.get_host_ttl(),
                info.get_priority(),
                info.get_weight(),
                info.get_port(),
                info.get_hostname().to_string(),
            )),
            0,
        );
        out.add_answer_at_time(
            Box::new(DnsTxt::new(
                info.get_fullname(),
                TYPE_TXT,
                CLASS_IN | CLASS_UNIQUE,
                info.get_other_ttl(),
                info.generate_txt(),
            )),
            0,
        );

        let intf_addrs = info.get_addrs_on_intf(&intf_sock.intf);
        if intf_addrs.is_empty() {
            debug!("No valid addrs to add on intf {:?}", &intf_sock.intf);
            return false;
        }
        for addr in intf_addrs {
            out.add_answer_at_time(
                Box::new(DnsAddress::new(
                    info.get_hostname(),
                    TYPE_A,
                    CLASS_IN | CLASS_UNIQUE,
                    info.get_host_ttl(),
                    addr,
                )),
                0,
            );
        }

        self.send(&out, &self.broadcast_addr, intf_sock);
        true
    }

    fn unregister_service(&self, info: &ServiceInfo, intf_sock: &IntfSock) -> Vec<u8> {
        let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
        out.add_answer_at_time(
            Box::new(DnsPointer::new(
                info.get_type(),
                TYPE_PTR,
                CLASS_IN,
                0,
                info.get_fullname().to_string(),
            )),
            0,
        );

        if let Some(sub) = info.get_subtype() {
            debug!("Adding subdomain {}", sub);
            out.add_answer_at_time(
                Box::new(DnsPointer::new(
                    sub,
                    TYPE_PTR,
                    CLASS_IN,
                    0,
                    info.get_fullname().to_string(),
                )),
                0,
            );
        }

        out.add_answer_at_time(
            Box::new(DnsSrv::new(
                info.get_fullname(),
                CLASS_IN | CLASS_UNIQUE,
                0,
                info.get_priority(),
                info.get_weight(),
                info.get_port(),
                info.get_hostname().to_string(),
            )),
            0,
        );
        out.add_answer_at_time(
            Box::new(DnsTxt::new(
                info.get_fullname(),
                TYPE_TXT,
                CLASS_IN | CLASS_UNIQUE,
                0,
                info.generate_txt(),
            )),
            0,
        );

        for addr in info.get_addrs_on_intf(&intf_sock.intf) {
            out.add_answer_at_time(
                Box::new(DnsAddress::new(
                    info.get_hostname(),
                    TYPE_A,
                    CLASS_IN | CLASS_UNIQUE,
                    0,
                    addr,
                )),
                0,
            );
        }

        self.send(&out, &self.broadcast_addr, intf_sock)
    }

    /// Binds a channel `listener` to querying mDNS domain type `ty`.
    ///
    /// If there is already a `listener`, it will be updated, i.e. overwritten.
    fn add_querier(&mut self, ty: String, listener: Sender<ServiceEvent>) {
        self.queriers.insert(ty, listener);
    }

    /// Sends an outgoing packet, and returns the packet bytes.
    fn send(&self, out: &DnsOutgoing, addr: &SockAddr, intf: &IntfSock) -> Vec<u8> {
        let qtype = if out.is_query() { "query" } else { "response" };
        debug!(
            "Sending {} to {:?}: {} questions {} answers {} authorities {} additional",
            qtype,
            addr.as_socket(),
            out.questions.len(),
            out.answers.len(),
            out.authorities.len(),
            out.additionals.len()
        );
        let packet = out.to_packet_data();
        if packet.len() > MAX_MSG_ABSOLUTE {
            error!("Drop over-sized packet ({})", packet.len());
            return Vec::new();
        }

        send_packet(&packet[..], addr, intf);
        packet
    }

    fn send_query(&self, name: &str, qtype: u16) {
        debug!("Sending multicast query for {}", name);
        let mut out = DnsOutgoing::new(FLAGS_QR_QUERY);
        out.add_question(name, qtype);
        for (_, intf_sock) in self.intf_socks.iter() {
            self.send(&out, &self.broadcast_addr, intf_sock);
        }
    }

    /// Reads from the socket of `ipv4`.
    ///
    /// Returns false if failed to receive a packet,
    /// otherwise returns true.
    fn handle_read(&mut self, ipv4: &Ipv4Addr) -> bool {
        let intf_sock = match self.intf_socks.get_mut(ipv4) {
            Some(if_sock) => if_sock,
            None => return false,
        };
        let mut buf = vec![0u8; MAX_MSG_ABSOLUTE];
        let sz = match intf_sock.sock.read(&mut buf) {
            Ok(sz) => sz,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    error!("listening socket read failed: {}", e);
                }
                return false;
            }
        };

        debug!("received {} bytes", sz);

        // If sz is 0, it means sock reached End-of-File.
        if sz == 0 {
            error!("socket {:?} was likely shutdown", intf_sock);
            if let Err(e) = self.poller.delete(&intf_sock.sock) {
                error!("failed to remove sock {:?} from poller: {}", intf_sock, &e);
            }

            // Replace the closed socket with a new one.
            match new_socket_bind(&intf_sock.intf.ip) {
                Ok(sock) => {
                    let intf = intf_sock.intf.clone();
                    self.intf_socks.insert(*ipv4, IntfSock { intf, sock });
                    debug!("reset socket for IP {}", ipv4);
                }
                Err(e) => error!("re-bind a socket to {}: {}", ipv4, e),
            }
            return false;
        }

        match DnsIncoming::new(buf) {
            Ok(msg) => {
                if msg.is_query() {
                    self.handle_query(msg, ipv4);
                } else if msg.is_response() {
                    self.handle_response(msg);
                } else {
                    error!("Invalid message: not query and not response");
                }
            }
            Err(e) => error!("Invalid incoming message: {}", e),
        }

        true
    }

    /// Sends TYPE_ANY query for instances that're missing SRV records.
    fn query_missing_srv(&mut self) {
        let now = current_time_millis();
        let wait_in_millis = 800; // The threshold for deeming SRV missing.

        for records in self.cache.ptr.values() {
            for record in records.iter() {
                if let Some(ptr) = record.any().downcast_ref::<DnsPointer>() {
                    if !self.cache.srv.contains_key(&ptr.alias)
                        && valid_instance_name(&ptr.alias)
                        && now > ptr.get_record().get_created() + wait_in_millis
                    {
                        self.send_query(&ptr.alias, TYPE_ANY);
                    }
                }
            }
        }
    }

    /// Checks if `ty_domain` has records in the cache. If yes, sends the
    /// cached records via `sender`.
    fn query_cache(&mut self, ty_domain: &str, sender: Sender<ServiceEvent>) {
        if let Some(records) = self.cache.ptr.get(ty_domain) {
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
        let my_name = {
            let name = fullname.trim_end_matches(split_sub_domain(ty_domain).0);
            name.strip_suffix('.').unwrap_or(name).to_string()
        };

        let mut info = ServiceInfo::new(ty_domain, &my_name, "", (), 0, None)?;

        // resolve SRV record
        if let Some(records) = self.cache.srv.get(fullname) {
            if let Some(answer) = records.get(0) {
                if let Some(dns_srv) = answer.any().downcast_ref::<DnsSrv>() {
                    info.set_hostname(dns_srv.host.clone());
                    info.set_port(dns_srv.port);
                }
            }
        }

        // resolve TXT record
        if let Some(records) = self.cache.txt.get(fullname) {
            if let Some(record) = records.get(0) {
                if let Some(dns_txt) = record.any().downcast_ref::<DnsTxt>() {
                    info.set_properties_from_txt(&dns_txt.text);
                }
            }
        }

        // resolve A records
        if let Some(records) = self.cache.addr.get(info.get_hostname()) {
            for answer in records.iter() {
                if let Some(dns_a) = answer.any().downcast_ref::<DnsAddress>() {
                    info.insert_ipv4addr(dns_a.address);
                }
            }
        }

        Ok(info)
    }

    /// Deal with incoming response packets.  All answers
    /// are held in the cache, and listeners are notified.
    fn handle_response(&mut self, mut msg: DnsIncoming) {
        debug!(
            "handle_response: {} answers {} authorities {} additionals",
            &msg.answers.len(),
            &msg.num_authorities,
            &msg.num_additionals
        );
        let now = current_time_millis();

        // remove records that are expired.
        msg.answers.retain(|record| {
            if !record.get_record().is_expired(now) {
                return true;
            }

            debug!("record is expired, removing it from cache.");
            if self.cache.remove(record) {
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
            false
        });

        /// Represents a DNS record change that involves one service instance.
        struct InstanceChange {
            ty: u16,      // The type of DNS record for the instance.
            name: String, // The name of the record.
        }

        // Go through all answers to get the new and updated records.
        // For new PTR records, send out ServiceFound immediately. For others,
        // collect them into `changes`.
        //
        // Note: we don't try to identify the update instances based on
        // each record immediately as the answers are likely related to each
        // other.
        let mut changes = Vec::new();
        for record in msg.answers {
            if let Some((dns_record, true)) = self.cache.add_or_update(record) {
                let ty = dns_record.get_type();
                let name = dns_record.get_name();
                if ty == TYPE_PTR {
                    // send ServiceFound
                    if let Some(dns_ptr) = dns_record.any().downcast_ref::<DnsPointer>() {
                        call_listener(
                            &self.queriers,
                            name,
                            ServiceEvent::ServiceFound(name.to_string(), dns_ptr.alias.clone()),
                        );
                    }
                } else {
                    changes.push(InstanceChange {
                        ty,
                        name: name.to_string(),
                    });
                }
            }
        }

        // Identify the instances that need to be "resolved".
        let mut updated_instances = HashSet::new();
        for update in changes {
            match update.ty {
                TYPE_SRV | TYPE_TXT => {
                    updated_instances.insert(update.name);
                }
                TYPE_A => {
                    let instances = self.cache.get_instances_on_host(&update.name);
                    updated_instances.extend(instances);
                }
                _ => {}
            }
        }

        // Resolve the updated (including new) instances.
        //
        // Note: it is possible that more than 1 PTR pointing to the same
        // instance. For example, a regular service type PTR and a sub-type
        // service type PTR can both point to the same service instance.
        // This loop automatically handles the sub-type PTRs.
        for (ty_domain, records) in self.cache.ptr.iter() {
            for record in records.iter() {
                if let Some(dns_ptr) = record.any().downcast_ref::<DnsPointer>() {
                    if updated_instances.contains(&dns_ptr.alias) {
                        if let Ok(info) =
                            self.create_service_info_from_cache(ty_domain, &dns_ptr.alias)
                        {
                            if info.is_ready() {
                                call_listener(
                                    &self.queriers,
                                    ty_domain,
                                    ServiceEvent::ServiceResolved(info),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    fn handle_query(&mut self, msg: DnsIncoming, ipv4: &Ipv4Addr) {
        let intf_sock = match self.intf_socks.get(ipv4) {
            Some(sock) => sock,
            None => return,
        };
        let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);

        // Special meta-query "_services._dns-sd._udp.<Domain>".
        // See https://datatracker.ietf.org/doc/html/rfc6763#section-9
        const META_QUERY: &str = "_services._dns-sd._udp.local.";

        for question in msg.questions.iter() {
            debug!("question: {:?}", &question);
            let qtype = question.entry.ty;

            if qtype == TYPE_PTR {
                for service in self.my_services.values() {
                    if question.entry.name == service.get_type()
                        || service
                            .get_subtype()
                            .as_ref()
                            .map_or(false, |v| v == &question.entry.name)
                    {
                        out.add_answer_with_additionals(&msg, service, &intf_sock.intf);
                    } else if question.entry.name == META_QUERY {
                        let ptr_added = out.add_answer(
                            &msg,
                            Box::new(DnsPointer::new(
                                &question.entry.name,
                                TYPE_PTR,
                                CLASS_IN,
                                service.get_other_ttl(),
                                service.get_type().to_string(),
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
                        if service.get_hostname() == question.entry.name.to_lowercase() {
                            let intf_addrs = service.get_addrs_on_intf(&intf_sock.intf);
                            if intf_addrs.is_empty() && qtype == TYPE_A {
                                error!(
                                    "Cannot find valid addrs for TYPE_A response on intf {:?}",
                                    &intf_sock.intf
                                );
                                return;
                            }
                            for address in intf_addrs {
                                out.add_answer(
                                    &msg,
                                    Box::new(DnsAddress::new(
                                        &question.entry.name,
                                        TYPE_A,
                                        CLASS_IN | CLASS_UNIQUE,
                                        service.get_host_ttl(),
                                        address,
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
                            service.get_host_ttl(),
                            service.get_priority(),
                            service.get_weight(),
                            service.get_port(),
                            service.get_hostname().to_string(),
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
                            service.get_host_ttl(),
                            service.generate_txt(),
                        )),
                    );
                }

                if qtype == TYPE_SRV {
                    let intf_addrs = service.get_addrs_on_intf(&intf_sock.intf);
                    if intf_addrs.is_empty() {
                        error!(
                            "Cannot find valid addrs for TYPE_SRV response on intf {:?}",
                            &intf_sock.intf
                        );
                        return;
                    }
                    for address in intf_addrs {
                        out.add_additional_answer(Box::new(DnsAddress::new(
                            service.get_hostname(),
                            TYPE_A,
                            CLASS_IN | CLASS_UNIQUE,
                            service.get_host_ttl(),
                            address,
                        )));
                    }
                }
            }
        }

        if !out.answers.is_empty() {
            out.id = msg.id;
            self.send(&out, &self.broadcast_addr, intf_sock);

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

/// All possible events sent to the client from the daemon
/// regarding service discovery.
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

/// Some notable events from the daemon besides [`ServiceEvent`].
/// These events are expected to happen infrequently.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum DaemonEvent {
    /// Daemon unsolicitly announced a service from an interface.
    Announce(String, String),

    /// Daemon encountered an error.
    Error(Error),

    /// Daemon detected a new IPv4 address from the host.
    Ipv4Add(Ipv4Addr),

    /// Daemon detected a IPv4 address removed from the host.
    Ipv4Del(Ipv4Addr),
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
    UnregisterResend(Vec<u8>, Ipv4Addr), // (packet content)

    /// Stop browsing a service type
    StopBrowse(String), // (ty_domain)

    /// Read the current values of the counters
    GetMetrics(Sender<Metrics>),

    /// Monitor noticable events in the daemon.
    Monitor(Sender<DaemonEvent>),

    SetOption(DaemonOption),

    Exit,
}

#[derive(Debug)]
enum DaemonOption {
    ServiceNameLenMax(u8),
}

struct DnsCache {
    ptr: HashMap<String, Vec<DnsRecordBox>>,
    srv: HashMap<String, Vec<DnsRecordBox>>,
    txt: HashMap<String, Vec<DnsRecordBox>>,
    addr: HashMap<String, Vec<DnsRecordBox>>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            ptr: HashMap::new(),
            srv: HashMap::new(),
            txt: HashMap::new(),
            addr: HashMap::new(),
        }
    }

    /// Returns the list of instances that has `host` as its hostname.
    fn get_instances_on_host(&self, host: &str) -> Vec<String> {
        self.srv
            .iter()
            .filter_map(|(instance, srv_list)| {
                if let Some(item) = srv_list.get(0) {
                    if let Some(dns_srv) = item.any().downcast_ref::<DnsSrv>() {
                        if dns_srv.host == host {
                            return Some(instance.clone());
                        }
                    }
                }
                None
            })
            .collect()
    }

    /// Update a DNSRecord if already exists, otherwise insert a new record
    fn add_or_update(&mut self, incoming: DnsRecordBox) -> Option<(&DnsRecordBox, bool)> {
        let entry_name = incoming.get_name().to_string();
        let record_vec = match incoming.get_type() {
            TYPE_PTR => self.ptr.entry(entry_name).or_default(),
            TYPE_SRV => self.srv.entry(entry_name).or_default(),
            TYPE_TXT => self.txt.entry(entry_name).or_default(),
            TYPE_A => self.addr.entry(entry_name).or_default(),
            _ => return None,
        };

        let (idx, updated) = match record_vec
            .iter_mut()
            .enumerate()
            .find(|(_idx, r)| r.matches(incoming.as_ref()))
        {
            Some((i, r)) => {
                r.reset_ttl(incoming.as_ref());
                (i, false)
            }
            None => {
                record_vec.insert(0, incoming); // A new record.
                (0, true)
            }
        };
        Some((record_vec.get(idx).unwrap(), updated))
    }

    /// Remove a record from the cache if exists, otherwise no-op
    fn remove(&mut self, record: &DnsRecordBox) -> bool {
        let mut found = false;
        let record_name = record.get_name();
        let record_vec = match record.get_type() {
            TYPE_PTR => self.ptr.get_mut(record_name),
            TYPE_SRV => self.srv.get_mut(record_name),
            TYPE_TXT => self.txt.get_mut(record_name),
            TYPE_A => self.addr.get_mut(record_name),
            _ => return found,
        };
        if let Some(record_vec) = record_vec {
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
        let all_records = self
            .ptr
            .values_mut()
            .chain(self.srv.values_mut())
            .chain(self.txt.values_mut())
            .chain(self.addr.values_mut());
        for records in all_records {
            records.retain(|x| {
                let expired = x.get_record().is_expired(now);
                if expired {
                    f(x);
                }
                !expired // only retain non-expired ones
            });
        }
    }

    /// Returns the list of instance names that are due for refresh
    /// for a `ty_domain`.
    ///
    /// For these instances, their refresh time will be updated so that
    /// they will not refresh again.
    fn refresh_due(&mut self, ty_domain: &str) -> Vec<String> {
        let now = current_time_millis();

        self.ptr
            .get_mut(ty_domain)
            .into_iter()
            .flatten()
            .filter_map(|record| {
                let rec = record.get_record_mut();
                if rec.is_expired(now) || !rec.refresh_due(now) {
                    return None;
                }
                rec.refresh_no_more();

                record
                    .any()
                    .downcast_ref::<DnsPointer>()
                    .map(|dns_ptr| dns_ptr.alias.clone())
            })
            .collect()
    }
}

/// The length of Service Domain name supported in this lib.
const DOMAIN_LEN: usize = "._tcp.local.".len();

/// Validate the length of "service_name" in a "_<service_name>.<domain_name>." string.
fn check_service_name_length(ty_domain: &str, limit: u8) -> Result<()> {
    let service_name_len = ty_domain.len() - DOMAIN_LEN - 1; // exclude the leading `_`
    if service_name_len > limit as usize {
        return Err(e_fmt!("Service name length must be <= {} bytes", limit));
    }
    Ok(())
}

/// Validate the service name in a fully qualified name.
///
/// A Full Name = <Instance>.<Service>.<Domain>
/// The only `<Domain>` supported are "._tcp.local." and "._udp.local.".
///
/// Note: this function does not check for the length of the service name.
/// Instead `register_service` method will check the length.
fn check_service_name(fullname: &str) -> Result<()> {
    if !(fullname.ends_with("._tcp.local.") || fullname.ends_with("._udp.local.")) {
        return Err(e_fmt!(
            "Service {} must end with '._tcp.local.' or '._udp.local.'",
            fullname
        ));
    }

    let remaining: Vec<&str> = fullname[..fullname.len() - DOMAIN_LEN].split('.').collect();
    let name = remaining.last().ok_or_else(|| e_fmt!("No service name"))?;

    if &name[0..1] != "_" {
        return Err(e_fmt!("Service name must start with '_'"));
    }

    let name = &name[1..];

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

/// Returns valid IPv4 interfaces in the host system.
fn my_ipv4_interfaces() -> Vec<Ifv4Addr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| {
            if i.is_loopback() {
                None
            } else {
                match i.addr {
                    IfAddr::V4(ifv4) => Some(ifv4),
                    _ => None,
                }
            }
        })
        .collect()
}

/// Sends out `packet` to `addr` on the socket in `intf_sock`.
fn send_packet(packet: &[u8], addr: &SockAddr, intf_sock: &IntfSock) {
    match intf_sock.sock.send_to(packet, addr) {
        Ok(sz) => debug!("sent out {} bytes on interface {:?}", sz, &intf_sock.intf),
        Err(e) => error!(
            "send to {:?} via interface {:?} failed: {}",
            addr, &intf_sock.intf, e
        ),
    }
}

/// Returns true if `name` is a valid instance name of format:
/// <instance>.<service_type>.<_udp|_tcp>.local.
/// Note: <instance> could contain '.' as well.
fn valid_instance_name(name: &str) -> bool {
    name.split('.').count() >= 5
}

#[cfg(test)]
mod tests {
    use super::valid_instance_name;

    #[test]
    fn test_instance_name() {
        assert_eq!(valid_instance_name("my-laser._printer._tcp.local."), true);
        assert_eq!(valid_instance_name("my-laser.._printer._tcp.local."), true);
        assert_eq!(valid_instance_name("_printer._tcp.local."), false);
    }
}
