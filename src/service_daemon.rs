//! Service daemon for mDNS Service Discovery.

// How DNS-based Service Discovery works in a nutshell:
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
use crate::log::{debug, trace};
use crate::{
    dns_cache::{current_time_millis, DnsCache},
    dns_parser::{
        ip_address_rr_type, DnsAddress, DnsEntryExt, DnsIncoming, DnsOutgoing, DnsPointer,
        DnsRecordBox, DnsRecordExt, DnsSrv, DnsTxt, RRType, CLASS_CACHE_FLUSH, CLASS_IN, FLAGS_AA,
        FLAGS_QR_QUERY, FLAGS_QR_RESPONSE, MAX_MSG_ABSOLUTE,
    },
    error::{Error, Result},
    service_info::{
        split_sub_domain, valid_ip_on_intf, DnsRegistry, Probe, ServiceInfo, ServiceStatus,
    },
    Receiver,
};
use flume::{bounded, Sender, TrySendError};
use if_addrs::{IfAddr, Interface};
use mio::{net::UdpSocket as MioUdpSocket, Poll};
use socket2::Socket;
use std::{
    cmp::{self, Reverse},
    collections::{BinaryHeap, HashMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
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

/// The default time out for [ServiceDaemon::verify] is 10 seconds, per
/// [RFC 6762 section 10.4](https://datatracker.ietf.org/doc/html/rfc6762#section-10.4)
pub const VERIFY_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);

const MDNS_PORT: u16 = 5353;
const GROUP_ADDR_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const GROUP_ADDR_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const LOOPBACK_V4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

const RESOLVE_WAIT_IN_MILLIS: u64 = 500;

/// Response status code for the service `unregister` call.
#[derive(Debug)]
pub enum UnregisterStatus {
    /// Unregister was successful.
    OK,
    /// The service was not found in the registration.
    NotFound,
}

/// Status code for the service daemon.
#[derive(Debug, PartialEq, Clone, Eq)]
#[non_exhaustive]
pub enum DaemonStatus {
    /// The daemon is running as normal.
    Running,

    /// The daemon has been shutdown.
    Shutdown,
}

/// Different counters included in the metrics.
/// Currently all counters are for outgoing packets.
#[derive(Hash, Eq, PartialEq)]
enum Counter {
    Register,
    RegisterResend,
    Unregister,
    UnregisterResend,
    Browse,
    ResolveHostname,
    Respond,
    CacheRefreshPTR,
    CacheRefreshSRV,
    CacheRefreshAddr,
    KnownAnswerSuppression,
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Register => write!(f, "register"),
            Self::RegisterResend => write!(f, "register-resend"),
            Self::Unregister => write!(f, "unregister"),
            Self::UnregisterResend => write!(f, "unregister-resend"),
            Self::Browse => write!(f, "browse"),
            Self::ResolveHostname => write!(f, "resolve-hostname"),
            Self::Respond => write!(f, "respond"),
            Self::CacheRefreshPTR => write!(f, "cache-refresh-ptr"),
            Self::CacheRefreshSRV => write!(f, "cache-refresh-srv"),
            Self::CacheRefreshAddr => write!(f, "cache-refresh-addr"),
            Self::KnownAnswerSuppression => write!(f, "known-answer-suppression"),
        }
    }
}

/// The metrics is a HashMap of (name_key, i64_value).
/// The main purpose is to help monitoring the mDNS packet traffic.
pub type Metrics = HashMap<String, i64>;

const SIGNAL_SOCK_EVENT_KEY: usize = usize::MAX - 1; // avoid to overlap with zc.poll_ids

/// A daemon thread for mDNS
///
/// This struct provides a handle and an API to the daemon. It is cloneable.
#[derive(Clone)]
pub struct ServiceDaemon {
    /// Sender handle of the channel to the daemon.
    sender: Sender<Command>,

    /// Send to this addr to signal that a `Command` is coming.
    ///
    /// The daemon listens on this addr together with other mDNS sockets,
    /// to avoid busy polling the flume channel. If there is a way to poll
    /// the channel and mDNS sockets together, then this can be removed.
    signal_addr: SocketAddr,
}

impl ServiceDaemon {
    /// Creates a new daemon and spawns a thread to run the daemon.
    ///
    /// The daemon (re)uses the default mDNS port 5353. To keep it simple, we don't
    /// ask callers to set the port.
    pub fn new() -> Result<Self> {
        // Use port 0 to allow the system assign a random available port,
        // no need for a pre-defined port number.
        let signal_addr = SocketAddrV4::new(LOOPBACK_V4, 0);

        let signal_sock = UdpSocket::bind(signal_addr)
            .map_err(|e| e_fmt!("failed to create signal_sock for daemon: {}", e))?;

        // Get the socket with the OS chosen port
        let signal_addr = signal_sock
            .local_addr()
            .map_err(|e| e_fmt!("failed to get signal sock addr: {}", e))?;

        // Must be nonblocking so we can listen to it together with mDNS sockets.
        signal_sock
            .set_nonblocking(true)
            .map_err(|e| e_fmt!("failed to set nonblocking for signal socket: {}", e))?;

        let poller = Poll::new().map_err(|e| e_fmt!("failed to create mio Poll: {e}"))?;

        let (sender, receiver) = bounded(100);

        // Spawn the daemon thread
        let mio_sock = MioUdpSocket::from_std(signal_sock);
        thread::Builder::new()
            .name("mDNS_daemon".to_string())
            .spawn(move || Self::daemon_thread(mio_sock, poller, receiver))
            .map_err(|e| e_fmt!("thread builder failed to spawn: {}", e))?;

        Ok(Self {
            sender,
            signal_addr,
        })
    }

    /// Sends `cmd` to the daemon via its channel, and sends a signal
    /// to its sock addr to notify.
    fn send_cmd(&self, cmd: Command) -> Result<()> {
        let cmd_name = cmd.to_string();

        // First, send to the flume channel.
        self.sender.try_send(cmd).map_err(|e| match e {
            TrySendError::Full(_) => Error::Again,
            e => e_fmt!("flume::channel::send failed: {}", e),
        })?;

        // Second, send a signal to notify the daemon.
        let addr = SocketAddrV4::new(LOOPBACK_V4, 0);
        let socket = UdpSocket::bind(addr)
            .map_err(|e| e_fmt!("Failed to create socket to send signal: {}", e))?;
        socket
            .send_to(cmd_name.as_bytes(), self.signal_addr)
            .map_err(|e| {
                e_fmt!(
                    "signal socket send_to {} ({}) failed: {}",
                    self.signal_addr,
                    cmd_name,
                    e
                )
            })?;

        Ok(())
    }

    /// Starts browsing for a specific service type.
    ///
    /// `service_type` must end with a valid mDNS domain: '._tcp.local.' or '._udp.local.'
    ///
    /// Returns a channel `Receiver` to receive events about the service. The caller
    /// can call `.recv_async().await` on this receiver to handle events in an
    /// async environment or call `.recv()` in a sync environment.
    ///
    /// When a new instance is found, the daemon automatically tries to resolve, i.e.
    /// finding more details, i.e. SRV records and TXT records.
    pub fn browse(&self, service_type: &str) -> Result<Receiver<ServiceEvent>> {
        check_domain_suffix(service_type)?;

        let (resp_s, resp_r) = bounded(10);
        self.send_cmd(Command::Browse(service_type.to_string(), 1, resp_s))?;
        Ok(resp_r)
    }

    /// Stops searching for a specific service type.
    ///
    /// When an error is returned, the caller should retry only when
    /// the error is `Error::Again`, otherwise should log and move on.
    pub fn stop_browse(&self, ty_domain: &str) -> Result<()> {
        self.send_cmd(Command::StopBrowse(ty_domain.to_string()))
    }

    /// Starts querying for the ip addresses of a hostname.
    ///
    /// Returns a channel `Receiver` to receive events about the hostname.
    /// The caller can call `.recv_async().await` on this receiver to handle events in an
    /// async environment or call `.recv()` in a sync environment.
    ///
    /// The `timeout` is specified in milliseconds.
    pub fn resolve_hostname(
        &self,
        hostname: &str,
        timeout: Option<u64>,
    ) -> Result<Receiver<HostnameResolutionEvent>> {
        check_hostname(hostname)?;
        let (resp_s, resp_r) = bounded(10);
        self.send_cmd(Command::ResolveHostname(
            hostname.to_string(),
            1,
            resp_s,
            timeout,
        ))?;
        Ok(resp_r)
    }

    /// Stops querying for the ip addresses of a hostname.
    ///
    /// When an error is returned, the caller should retry only when
    /// the error is `Error::Again`, otherwise should log and move on.
    pub fn stop_resolve_hostname(&self, hostname: &str) -> Result<()> {
        self.send_cmd(Command::StopResolveHostname(hostname.to_string()))
    }

    /// Registers a service provided by this host.
    ///
    /// If `service_info` has no addresses yet and its `addr_auto` is enabled,
    /// this method will automatically fill in addresses from the host.
    ///
    /// To re-announce a service with an updated `service_info`, just call
    /// this `register` function again. No need to call `unregister` first.
    pub fn register(&self, service_info: ServiceInfo) -> Result<()> {
        check_service_name(service_info.get_fullname())?;
        check_hostname(service_info.get_hostname())?;

        self.send_cmd(Command::Register(service_info))
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
        self.send_cmd(Command::Unregister(fullname.to_lowercase(), resp_s))?;
        Ok(resp_r)
    }

    /// Starts to monitor events from the daemon.
    ///
    /// Returns a channel [`Receiver`] of [`DaemonEvent`].
    pub fn monitor(&self) -> Result<Receiver<DaemonEvent>> {
        let (resp_s, resp_r) = bounded(100);
        self.send_cmd(Command::Monitor(resp_s))?;
        Ok(resp_r)
    }

    /// Shuts down the daemon thread and returns a channel to receive the status.
    ///
    /// When an error is returned, the caller should retry only when
    /// the error is `Error::Again`, otherwise should log and move on.
    pub fn shutdown(&self) -> Result<Receiver<DaemonStatus>> {
        let (resp_s, resp_r) = bounded(1);
        self.send_cmd(Command::Exit(resp_s))?;
        Ok(resp_r)
    }

    /// Returns the status of the daemon.
    ///
    /// When an error is returned, the caller should retry only when
    /// the error is `Error::Again`, otherwise should consider the daemon
    /// stopped working and move on.
    pub fn status(&self) -> Result<Receiver<DaemonStatus>> {
        let (resp_s, resp_r) = bounded(1);

        if self.sender.is_disconnected() {
            resp_s
                .send(DaemonStatus::Shutdown)
                .map_err(|e| e_fmt!("failed to send daemon status to the client: {}", e))?;
        } else {
            self.send_cmd(Command::GetStatus(resp_s))?;
        }

        Ok(resp_r)
    }

    /// Returns a channel receiver for the metrics, e.g. input/output counters.
    ///
    /// The metrics returned is a snapshot. Hence the caller should call
    /// this method repeatedly if they want to monitor the metrics continuously.
    pub fn get_metrics(&self) -> Result<Receiver<Metrics>> {
        let (resp_s, resp_r) = bounded(1);
        self.send_cmd(Command::GetMetrics(resp_s))?;
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

        self.send_cmd(Command::SetOption(DaemonOption::ServiceNameLenMax(len_max)))
    }

    /// Include interfaces that match `if_kind` for this service daemon.
    ///
    /// For example:
    /// ```ignore
    ///     daemon.enable_interface("en0")?;
    /// ```
    pub fn enable_interface(&self, if_kind: impl IntoIfKindVec) -> Result<()> {
        let if_kind_vec = if_kind.into_vec();
        self.send_cmd(Command::SetOption(DaemonOption::EnableInterface(
            if_kind_vec.kinds,
        )))
    }

    /// Ignore/exclude interfaces that match `if_kind` for this daemon.
    ///
    /// For example:
    /// ```ignore
    ///     daemon.disable_interface(IfKind::IPv6)?;
    /// ```
    pub fn disable_interface(&self, if_kind: impl IntoIfKindVec) -> Result<()> {
        let if_kind_vec = if_kind.into_vec();
        self.send_cmd(Command::SetOption(DaemonOption::DisableInterface(
            if_kind_vec.kinds,
        )))
    }

    /// Enable or disable the loopback for locally sent multicast packets in IPv4.
    ///
    /// By default, multicast loop is enabled for IPv4. When disabled, a querier will not
    /// receive announcements from a responder on the same host.
    ///
    /// Reference: <https://learn.microsoft.com/en-us/windows/win32/winsock/ip-multicast-2>
    ///
    /// "The Winsock version of the IP_MULTICAST_LOOP option is semantically different than
    /// the UNIX version of the IP_MULTICAST_LOOP option:
    ///
    /// In Winsock, the IP_MULTICAST_LOOP option applies only to the receive path.
    /// In the UNIX version, the IP_MULTICAST_LOOP option applies to the send path."
    ///
    /// Which means, in order NOT to receive localhost announcements, you want to call
    /// this API on the querier side on Windows, but on the responder side on Unix.
    pub fn set_multicast_loop_v4(&self, on: bool) -> Result<()> {
        self.send_cmd(Command::SetOption(DaemonOption::MulticastLoopV4(on)))
    }

    /// Enable or disable the loopback for locally sent multicast packets in IPv6.
    ///
    /// By default, multicast loop is enabled for IPv6. When disabled, a querier will not
    /// receive announcements from a responder on the same host.
    ///
    /// Reference: <https://learn.microsoft.com/en-us/windows/win32/winsock/ip-multicast-2>
    ///
    /// "The Winsock version of the IP_MULTICAST_LOOP option is semantically different than
    /// the UNIX version of the IP_MULTICAST_LOOP option:
    ///
    /// In Winsock, the IP_MULTICAST_LOOP option applies only to the receive path.
    /// In the UNIX version, the IP_MULTICAST_LOOP option applies to the send path."
    ///
    /// Which means, in order NOT to receive localhost announcements, you want to call
    /// this API on the querier side on Windows, but on the responder side on Unix.
    pub fn set_multicast_loop_v6(&self, on: bool) -> Result<()> {
        self.send_cmd(Command::SetOption(DaemonOption::MulticastLoopV6(on)))
    }

    /// Proactively confirms whether a service instance still valid.
    ///
    /// This call will issue queries for a service instance's SRV record and Address records.
    ///
    /// For `timeout`, most users should use [VERIFY_TIMEOUT_DEFAULT]
    /// unless there is a reason not to follow RFC.
    ///
    /// If no response is received within `timeout`, the current resource
    /// records will be flushed, and if needed, `ServiceRemoved` event will be
    /// sent to active queriers.
    ///
    /// Reference: [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762#section-10.4)
    pub fn verify(&self, instance_fullname: String, timeout: Duration) -> Result<()> {
        self.send_cmd(Command::Verify(instance_fullname, timeout))
    }

    fn daemon_thread(signal_sock: MioUdpSocket, poller: Poll, receiver: Receiver<Command>) {
        let zc = Zeroconf::new(signal_sock, poller);

        if let Some(cmd) = Self::run(zc, receiver) {
            match cmd {
                Command::Exit(resp_s) => {
                    // It is guaranteed that the receiver already dropped,
                    // i.e. the daemon command channel closed.
                    if let Err(e) = resp_s.send(DaemonStatus::Shutdown) {
                        debug!("exit: failed to send response of shutdown: {}", e);
                    }
                }
                _ => {
                    debug!("Unexpected command: {:?}", cmd);
                }
            }
        }
    }

    fn handle_poller_events(zc: &mut Zeroconf, events: &mio::Events) {
        for ev in events.iter() {
            trace!("event received with key {:?}", ev.token());
            if ev.token().0 == SIGNAL_SOCK_EVENT_KEY {
                // Drain signals as we will drain commands as well.
                zc.signal_sock_drain();

                if let Err(e) = zc.poller.registry().reregister(
                    &mut zc.signal_sock,
                    ev.token(),
                    mio::Interest::READABLE,
                ) {
                    debug!("failed to modify poller for signal socket: {}", e);
                }
                continue; // Next event.
            }

            // Read until no more packets available.
            let intf = match zc.poll_ids.get(&ev.token().0) {
                Some(interface) => interface.clone(),
                None => {
                    debug!("Ip for event key {} not found", ev.token().0);
                    break;
                }
            };
            while zc.handle_read(&intf) {}

            // we continue to monitor this socket.
            if let Some(sock) = zc.intf_socks.get_mut(&intf) {
                if let Err(e) =
                    zc.poller
                        .registry()
                        .reregister(sock, ev.token(), mio::Interest::READABLE)
                {
                    debug!("modify poller for interface {:?}: {}", &intf, e);
                    break;
                }
            }
        }
    }

    /// The main event loop of the daemon thread
    ///
    /// In each round, it will:
    /// 1. select the listening sockets with a timeout.
    /// 2. process the incoming packets if any.
    /// 3. try_recv on its channel and execute commands.
    /// 4. announce its registered services.
    /// 5. process retransmissions if any.
    fn run(mut zc: Zeroconf, receiver: Receiver<Command>) -> Option<Command> {
        // Add the daemon's signal socket to the poller.
        if let Err(e) = zc.poller.registry().register(
            &mut zc.signal_sock,
            mio::Token(SIGNAL_SOCK_EVENT_KEY),
            mio::Interest::READABLE,
        ) {
            debug!("failed to add signal socket to the poller: {}", e);
            return None;
        }

        // Add mDNS sockets to the poller.
        for (intf, sock) in zc.intf_socks.iter_mut() {
            let key =
                Zeroconf::add_poll_impl(&mut zc.poll_ids, &mut zc.poll_id_count, intf.clone());

            if let Err(e) =
                zc.poller
                    .registry()
                    .register(sock, mio::Token(key), mio::Interest::READABLE)
            {
                debug!("add socket of {:?} to poller: {e}", intf);
                return None;
            }
        }

        // Setup timer for IP checks.
        const IP_CHECK_INTERVAL_MILLIS: u64 = 30_000;
        let mut next_ip_check = current_time_millis() + IP_CHECK_INTERVAL_MILLIS;
        zc.add_timer(next_ip_check);

        // Start the run loop.

        let mut events = mio::Events::with_capacity(1024);
        loop {
            let now = current_time_millis();

            let earliest_timer = zc.peek_earliest_timer();
            let timeout = earliest_timer.map(|timer| {
                // If `timer` already passed, set `timeout` to be 1ms.
                let millis = if timer > now { timer - now } else { 1 };
                Duration::from_millis(millis)
            });

            // Process incoming packets, command events and optional timeout.
            events.clear();
            match zc.poller.poll(&mut events, timeout) {
                Ok(_) => Self::handle_poller_events(&mut zc, &events),
                Err(e) => debug!("failed to select from sockets: {}", e),
            }

            let now = current_time_millis();

            // Remove the timer if already passed.
            if let Some(timer) = earliest_timer {
                if now >= timer {
                    zc.pop_earliest_timer();
                }
            }

            // Remove hostname resolvers with expired timeouts.
            for hostname in zc
                .hostname_resolvers
                .clone()
                .into_iter()
                .filter(|(_, (_, timeout))| timeout.map(|t| now >= t).unwrap_or(false))
                .map(|(hostname, _)| hostname)
            {
                trace!("hostname resolver timeout for {}", &hostname);
                call_hostname_resolution_listener(
                    &zc.hostname_resolvers,
                    &hostname,
                    HostnameResolutionEvent::SearchTimeout(hostname.to_owned()),
                );
                call_hostname_resolution_listener(
                    &zc.hostname_resolvers,
                    &hostname,
                    HostnameResolutionEvent::SearchStopped(hostname.to_owned()),
                );
                zc.hostname_resolvers.remove(&hostname);
            }

            // process commands from the command channel
            while let Ok(command) = receiver.try_recv() {
                if matches!(command, Command::Exit(_)) {
                    zc.status = DaemonStatus::Shutdown;
                    return Some(command);
                }
                zc.exec_command(command, false);
            }

            // check for repeated commands and run them if their time is up.
            let mut i = 0;
            while i < zc.retransmissions.len() {
                if now >= zc.retransmissions[i].next_time {
                    let rerun = zc.retransmissions.remove(i);
                    zc.exec_command(rerun.command, true);
                } else {
                    i += 1;
                }
            }

            // Refresh cached service records with active queriers
            zc.refresh_active_services();

            // Refresh cached A/AAAA records with active queriers
            let mut query_count = 0;
            for (hostname, _sender) in zc.hostname_resolvers.iter() {
                for (hostname, ip_addr) in
                    zc.cache.refresh_due_hostname_resolutions(hostname).iter()
                {
                    zc.send_query(hostname, ip_address_rr_type(ip_addr));
                    query_count += 1;
                }
            }

            zc.increase_counter(Counter::CacheRefreshAddr, query_count);

            // check and evict expired records in our cache
            let now = current_time_millis();

            // Notify service listeners about the expired records.
            let expired_services = zc.cache.evict_expired_services(now);
            zc.notify_service_removal(expired_services);

            // Notify hostname listeners about the expired records.
            let expired_addrs = zc.cache.evict_expired_addr(now);
            for (hostname, addrs) in expired_addrs {
                call_hostname_resolution_listener(
                    &zc.hostname_resolvers,
                    &hostname,
                    HostnameResolutionEvent::AddressesRemoved(hostname.clone(), addrs),
                );
                let instances = zc.cache.get_instances_on_host(&hostname);
                let instance_set: HashSet<String> = instances.into_iter().collect();
                zc.resolve_updated_instances(&instance_set);
            }

            // Send out probing queries.
            zc.probing_handler();

            // check IP changes.
            if now > next_ip_check {
                next_ip_check = now + IP_CHECK_INTERVAL_MILLIS;
                zc.check_ip_changes();
                zc.add_timer(next_ip_check);
            }
        }
    }
}

/// Creates a new UDP socket that uses `intf` to send and recv multicast.
fn new_socket_bind(intf: &Interface, should_loop: bool) -> Result<MioUdpSocket> {
    // Use the same socket for receiving and sending multicast packets.
    // Such socket has to bind to INADDR_ANY or IN6ADDR_ANY.
    let intf_ip = &intf.ip();
    match intf_ip {
        IpAddr::V4(ip) => {
            let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), MDNS_PORT);
            let sock = new_socket(addr.into(), true)?;

            // Join mDNS group to receive packets.
            sock.join_multicast_v4(&GROUP_ADDR_V4, ip)
                .map_err(|e| e_fmt!("join multicast group on addr {}: {}", intf_ip, e))?;

            // Set IP_MULTICAST_IF to send packets.
            sock.set_multicast_if_v4(ip)
                .map_err(|e| e_fmt!("set multicast_if on addr {}: {}", ip, e))?;

            if !should_loop {
                sock.set_multicast_loop_v4(false)
                    .map_err(|e| e_fmt!("failed to set multicast loop v4 for {ip}: {e}"))?;
            }

            // Test if we can send packets successfully.
            let multicast_addr = SocketAddrV4::new(GROUP_ADDR_V4, MDNS_PORT).into();
            let test_packets = DnsOutgoing::new(0).to_data_on_wire();
            for packet in test_packets {
                sock.send_to(&packet, &multicast_addr)
                    .map_err(|e| e_fmt!("send multicast packet on addr {}: {}", ip, e))?;
            }
            Ok(MioUdpSocket::from_std(UdpSocket::from(sock)))
        }
        IpAddr::V6(ip) => {
            let addr = SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), MDNS_PORT, 0, 0);
            let sock = new_socket(addr.into(), true)?;

            // Join mDNS group to receive packets.
            sock.join_multicast_v6(&GROUP_ADDR_V6, intf.index.unwrap_or(0))
                .map_err(|e| e_fmt!("join multicast group on addr {}: {}", ip, e))?;

            // Set IPV6_MULTICAST_IF to send packets.
            sock.set_multicast_if_v6(intf.index.unwrap_or(0))
                .map_err(|e| e_fmt!("set multicast_if on addr {}: {}", ip, e))?;

            // We are not sending multicast packets to test this socket as there might
            // be many IPv6 interfaces on a host and could cause such send error:
            // "No buffer space available (os error 55)".

            Ok(MioUdpSocket::from_std(UdpSocket::from(sock)))
        }
    }
}

/// Creates a new UDP socket to bind to `port` with REUSEPORT option.
/// `non_block` indicates whether to set O_NONBLOCK for the socket.
fn new_socket(addr: SocketAddr, non_block: bool) -> Result<Socket> {
    let domain = match addr {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };

    let fd = Socket::new(domain, socket2::Type::DGRAM, None)
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

    fd.bind(&addr.into())
        .map_err(|e| e_fmt!("socket bind to {} failed: {}", &addr, e))?;

    trace!("new socket bind to {}", &addr);
    Ok(fd)
}

/// Specify a UNIX timestamp in millis to run `command` for the next time.
struct ReRun {
    /// UNIX timestamp in millis.
    next_time: u64,
    command: Command,
}

/// Enum to represent the IP version.
#[derive(Debug, Eq, Hash, PartialEq)]
enum IpVersion {
    V4,
    V6,
}

/// A struct to track multicast send status for a network interface.
#[derive(Debug, Eq, Hash, PartialEq)]
struct MulticastSendTracker {
    intf_index: u32,
    ip_version: IpVersion,
}

/// Returns the multicast send tracker if the interface index is valid
fn multicast_send_tracker(intf: &Interface) -> Option<MulticastSendTracker> {
    match intf.index {
        Some(index) => {
            let ip_ver = match intf.addr {
                IfAddr::V4(_) => IpVersion::V4,
                IfAddr::V6(_) => IpVersion::V6,
            };
            Some(MulticastSendTracker {
                intf_index: index,
                ip_version: ip_ver,
            })
        }
        None => None,
    }
}

/// Specify kinds of interfaces. It is used to enable or to disable interfaces in the daemon.
///
/// Note that for ergonomic reasons, `From<&str>` and `From<IpAddr>` are implemented.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IfKind {
    /// All interfaces.
    All,

    /// All IPv4 interfaces.
    IPv4,

    /// All IPv6 interfaces.
    IPv6,

    /// By the interface name, for example "en0"
    Name(String),

    /// By an IPv4 or IPv6 address.
    Addr(IpAddr),
}

impl IfKind {
    /// Checks if `intf` matches with this interface kind.
    fn matches(&self, intf: &Interface) -> bool {
        match self {
            Self::All => true,
            Self::IPv4 => intf.ip().is_ipv4(),
            Self::IPv6 => intf.ip().is_ipv6(),
            Self::Name(ifname) => ifname == &intf.name,
            Self::Addr(addr) => addr == &intf.ip(),
        }
    }
}

/// The first use case of specifying an interface was to
/// use an interface name. Hence adding this for ergonomic reasons.
impl From<&str> for IfKind {
    fn from(val: &str) -> Self {
        Self::Name(val.to_string())
    }
}

impl From<&String> for IfKind {
    fn from(val: &String) -> Self {
        Self::Name(val.to_string())
    }
}

/// Still for ergonomic reasons.
impl From<IpAddr> for IfKind {
    fn from(val: IpAddr) -> Self {
        Self::Addr(val)
    }
}

/// A list of `IfKind` that can be used to match interfaces.
pub struct IfKindVec {
    kinds: Vec<IfKind>,
}

/// A trait that converts a type into a Vec of `IfKind`.
pub trait IntoIfKindVec {
    fn into_vec(self) -> IfKindVec;
}

impl<T: Into<IfKind>> IntoIfKindVec for T {
    fn into_vec(self) -> IfKindVec {
        let if_kind: IfKind = self.into();
        IfKindVec {
            kinds: vec![if_kind],
        }
    }
}

impl<T: Into<IfKind>> IntoIfKindVec for Vec<T> {
    fn into_vec(self) -> IfKindVec {
        let kinds: Vec<IfKind> = self.into_iter().map(|x| x.into()).collect();
        IfKindVec { kinds }
    }
}

/// Selection of interfaces.
struct IfSelection {
    /// The interfaces to be selected.
    if_kind: IfKind,

    /// Whether the `if_kind` should be enabled or not.
    selected: bool,
}

/// A struct holding the state. It was inspired by `zeroconf` package in Python.
struct Zeroconf {
    /// Local interfaces with sockets to recv/send on these interfaces.
    intf_socks: HashMap<Interface, MioUdpSocket>,

    /// Map poll id to Interface.
    poll_ids: HashMap<usize, Interface>,

    /// Next poll id value
    poll_id_count: usize,

    /// Local registered services， keyed by service full names.
    my_services: HashMap<String, ServiceInfo>,

    /// Received DNS records.
    cache: DnsCache,

    /// Registered service records.
    dns_registry_map: HashMap<Interface, DnsRegistry>,

    /// Active "Browse" commands.
    service_queriers: HashMap<String, Sender<ServiceEvent>>, // <ty_domain, channel::sender>

    /// Active "ResolveHostname" commands.
    ///
    /// The timestamps are set at the future timestamp when the command should timeout.
    hostname_resolvers: HashMap<String, (Sender<HostnameResolutionEvent>, Option<u64>)>, // <hostname, (channel::sender, UNIX timestamp in millis)>

    /// All repeating transmissions.
    retransmissions: Vec<ReRun>,

    counters: Metrics,

    /// Waits for incoming packets.
    poller: Poll,

    /// Channels to notify events.
    monitors: Vec<Sender<DaemonEvent>>,

    /// Options
    service_name_len_max: u8,

    /// All interface selections called to the daemon.
    if_selections: Vec<IfSelection>,

    /// Socket for signaling.
    signal_sock: MioUdpSocket,

    /// Timestamps marking where we need another iteration of the run loop,
    /// to react to events like retransmissions, cache refreshes, interface IP address changes, etc.
    ///
    /// When the run loop goes through a single iteration, it will
    /// set its timeout to the earliest timer in this list.
    timers: BinaryHeap<Reverse<u64>>,

    status: DaemonStatus,

    /// Service instances that are pending for resolving SRV and TXT.
    pending_resolves: HashSet<String>,

    /// Service instances that are already resolved.
    resolved: HashSet<String>,

    multicast_loop_v4: bool,

    multicast_loop_v6: bool,
}

impl Zeroconf {
    fn new(signal_sock: MioUdpSocket, poller: Poll) -> Self {
        // Get interfaces.
        let my_ifaddrs = my_ip_interfaces();

        // Create a socket for every IP addr.
        // Note: it is possible that `my_ifaddrs` contains the same IP addr with different interface names,
        // or the same interface name with different IP addrs.
        let mut intf_socks = HashMap::new();
        let mut dns_registry_map = HashMap::new();

        for intf in my_ifaddrs {
            let sock = match new_socket_bind(&intf, true) {
                Ok(s) => s,
                Err(e) => {
                    trace!("bind a socket to {}: {}. Skipped.", &intf.ip(), e);
                    continue;
                }
            };

            dns_registry_map.insert(intf.clone(), DnsRegistry::new());

            intf_socks.insert(intf, sock);
        }

        let monitors = Vec::new();
        let service_name_len_max = SERVICE_NAME_LEN_MAX_DEFAULT;

        let timers = BinaryHeap::new();
        let if_selections = vec![];

        let status = DaemonStatus::Running;

        Self {
            intf_socks,
            poll_ids: HashMap::new(),
            poll_id_count: 0,
            my_services: HashMap::new(),
            cache: DnsCache::new(),
            dns_registry_map,
            hostname_resolvers: HashMap::new(),
            service_queriers: HashMap::new(),
            retransmissions: Vec::new(),
            counters: HashMap::new(),
            poller,
            monitors,
            service_name_len_max,
            if_selections,
            signal_sock,
            timers,
            status,
            pending_resolves: HashSet::new(),
            resolved: HashSet::new(),
            multicast_loop_v4: true,
            multicast_loop_v6: true,
        }
    }

    fn process_set_option(&mut self, daemon_opt: DaemonOption) {
        match daemon_opt {
            DaemonOption::ServiceNameLenMax(length) => self.service_name_len_max = length,
            DaemonOption::EnableInterface(if_kind) => self.enable_interface(if_kind),
            DaemonOption::DisableInterface(if_kind) => self.disable_interface(if_kind),
            DaemonOption::MulticastLoopV4(on) => self.set_multicast_loop_v4(on),
            DaemonOption::MulticastLoopV6(on) => self.set_multicast_loop_v6(on),
        }
    }

    fn enable_interface(&mut self, kinds: Vec<IfKind>) {
        for if_kind in kinds {
            self.if_selections.push(IfSelection {
                if_kind,
                selected: true,
            });
        }

        self.apply_intf_selections(my_ip_interfaces());
    }

    fn disable_interface(&mut self, kinds: Vec<IfKind>) {
        for if_kind in kinds {
            self.if_selections.push(IfSelection {
                if_kind,
                selected: false,
            });
        }

        self.apply_intf_selections(my_ip_interfaces());
    }

    fn set_multicast_loop_v4(&mut self, on: bool) {
        for (_, sock) in self.intf_socks.iter_mut() {
            if let Err(e) = sock.set_multicast_loop_v4(on) {
                debug!("failed to set multicast loop v4: {e}");
            }
        }
    }

    fn set_multicast_loop_v6(&mut self, on: bool) {
        for (_, sock) in self.intf_socks.iter_mut() {
            if let Err(e) = sock.set_multicast_loop_v6(on) {
                debug!("failed to set multicast loop v6: {e}");
            }
        }
    }

    fn notify_monitors(&mut self, event: DaemonEvent) {
        // Only retain the monitors that are still connected.
        self.monitors.retain(|sender| {
            if let Err(e) = sender.try_send(event.clone()) {
                debug!("notify_monitors: try_send: {}", &e);
                if matches!(e, TrySendError::Disconnected(_)) {
                    return false; // This monitor is dropped.
                }
            }
            true
        });
    }

    /// Remove `addr` in my services that enabled `addr_auto`.
    fn del_addr_in_my_services(&mut self, addr: &IpAddr) {
        for (_, service_info) in self.my_services.iter_mut() {
            if service_info.is_addr_auto() {
                service_info.remove_ipaddr(addr);
            }
        }
    }

    /// Insert a new interface into the poll map and return key
    fn add_poll(&mut self, intf: Interface) -> usize {
        Self::add_poll_impl(&mut self.poll_ids, &mut self.poll_id_count, intf)
    }

    /// Insert a new interface into the poll map and return its key.
    ///
    /// This exists to satisfy the borrow checker
    fn add_poll_impl(
        poll_ids: &mut HashMap<usize, Interface>,
        poll_id_count: &mut usize,
        intf: Interface,
    ) -> usize {
        let key = *poll_id_count;
        *poll_id_count += 1;
        let _ = (*poll_ids).insert(key, intf);
        key
    }

    fn add_timer(&mut self, next_time: u64) {
        self.timers.push(Reverse(next_time));
    }

    fn peek_earliest_timer(&self) -> Option<u64> {
        self.timers.peek().map(|Reverse(v)| *v)
    }

    fn pop_earliest_timer(&mut self) -> Option<u64> {
        self.timers.pop().map(|Reverse(v)| v)
    }

    /// Apply all selections to `interfaces` and return the selected addresses.
    fn selected_addrs(&self, interfaces: Vec<Interface>) -> HashSet<IpAddr> {
        let intf_count = interfaces.len();
        let mut intf_selections = vec![true; intf_count];

        // apply if_selections
        for selection in self.if_selections.iter() {
            // Mark the interfaces for this selection.
            for i in 0..intf_count {
                if selection.if_kind.matches(&interfaces[i]) {
                    intf_selections[i] = selection.selected;
                }
            }
        }

        let mut selected_addrs = HashSet::new();
        for i in 0..intf_count {
            if intf_selections[i] {
                selected_addrs.insert(interfaces[i].addr.ip());
            }
        }

        selected_addrs
    }

    /// Apply all selections to `interfaces`.
    ///
    /// For any interface, add it if selected but not bound yet,
    /// delete it if not selected but still bound.
    fn apply_intf_selections(&mut self, interfaces: Vec<Interface>) {
        // By default, we enable all interfaces.
        let intf_count = interfaces.len();
        let mut intf_selections = vec![true; intf_count];

        // apply if_selections
        for selection in self.if_selections.iter() {
            // Mark the interfaces for this selection.
            for i in 0..intf_count {
                if selection.if_kind.matches(&interfaces[i]) {
                    intf_selections[i] = selection.selected;
                }
            }
        }

        // Update `intf_socks` based on the selections.
        for (idx, intf) in interfaces.into_iter().enumerate() {
            if intf_selections[idx] {
                // Add the interface
                if !self.intf_socks.contains_key(&intf) {
                    self.add_new_interface(intf);
                }
            } else {
                // Remove the interface
                if let Some(mut sock) = self.intf_socks.remove(&intf) {
                    if let Err(e) = self.poller.registry().deregister(&mut sock) {
                        debug!("process_if_selections: poller.delete {:?}: {}", &intf, e);
                    }
                    // Remove from poll_ids
                    self.poll_ids.retain(|_, v| v != &intf);
                }
            }
        }
    }

    /// Check for IP changes and update intf_socks as needed.
    fn check_ip_changes(&mut self) {
        // Get the current interfaces.
        let my_ifaddrs = my_ip_interfaces();

        let poll_ids = &mut self.poll_ids;
        let poller = &mut self.poller;
        // Remove unused sockets in the poller.
        let deleted_addrs = self
            .intf_socks
            .iter_mut()
            .filter_map(|(intf, sock)| {
                if !my_ifaddrs.contains(intf) {
                    if let Err(e) = poller.registry().deregister(sock) {
                        debug!("check_ip_changes: poller.delete {:?}: {}", intf, e);
                    }
                    // Remove from poll_ids
                    poll_ids.retain(|_, v| v != intf);
                    Some(intf.ip())
                } else {
                    None
                }
            })
            .collect::<Vec<IpAddr>>();

        // Remove deleted addrs from my services that enabled `addr_auto`.
        for ip in deleted_addrs.iter() {
            self.del_addr_in_my_services(ip);
            self.notify_monitors(DaemonEvent::IpDel(*ip));
        }

        // Keep the interfaces only if they still exist.
        self.intf_socks.retain(|intf, _| my_ifaddrs.contains(intf));

        // Add newly found interfaces only if in our selections.
        self.apply_intf_selections(my_ifaddrs);
    }

    fn add_new_interface(&mut self, intf: Interface) {
        // Bind the new interface.
        let new_ip = intf.ip();
        let should_loop = if new_ip.is_ipv4() {
            self.multicast_loop_v4
        } else {
            self.multicast_loop_v6
        };
        let mut sock = match new_socket_bind(&intf, should_loop) {
            Ok(s) => s,
            Err(e) => {
                debug!("bind a socket to {}: {}. Skipped.", &intf.ip(), e);
                return;
            }
        };

        // Add the new interface into the poller.
        let key = self.add_poll(intf.clone());
        if let Err(e) =
            self.poller
                .registry()
                .register(&mut sock, mio::Token(key), mio::Interest::READABLE)
        {
            debug!("check_ip_changes: poller add ip {}: {}", new_ip, e);
            return;
        }

        debug!("add new interface {}: {new_ip}", intf.name);
        let dns_registry = match self.dns_registry_map.get_mut(&intf) {
            Some(registry) => registry,
            None => self
                .dns_registry_map
                .entry(intf.clone())
                .or_insert_with(DnsRegistry::new),
        };

        for (_, service_info) in self.my_services.iter_mut() {
            if service_info.is_addr_auto() {
                service_info.insert_ipaddr(new_ip);

                if announce_service_on_intf(dns_registry, service_info, &intf, &sock) {
                    debug!(
                        "Announce service {} on {}",
                        service_info.get_fullname(),
                        intf.ip()
                    );
                    service_info.set_status(&intf, ServiceStatus::Announced);
                } else {
                    for timer in dns_registry.new_timers.drain(..) {
                        self.timers.push(Reverse(timer));
                    }
                    service_info.set_status(&intf, ServiceStatus::Probing);
                }
            }
        }

        self.intf_socks.insert(intf, sock);

        // Notify the monitors.
        self.notify_monitors(DaemonEvent::IpAdd(new_ip));
    }

    /// Registers a service.
    ///
    /// RFC 6762 section 8.3.
    /// ...the Multicast DNS responder MUST send
    ///    an unsolicited Multicast DNS response containing, in the Answer
    ///    Section, all of its newly registered resource records
    ///
    /// Zeroconf will then respond to requests for information about this service.
    fn register_service(&mut self, mut info: ServiceInfo) {
        // Check the service name length.
        if let Err(e) = check_service_name_length(info.get_type(), self.service_name_len_max) {
            debug!("check_service_name_length: {}", &e);
            self.notify_monitors(DaemonEvent::Error(e));
            return;
        }

        if info.is_addr_auto() {
            let selected_addrs = self.selected_addrs(my_ip_interfaces());
            for addr in selected_addrs {
                info.insert_ipaddr(addr);
            }
        }

        debug!("register service {:?}", &info);

        let outgoing_addrs = self.send_unsolicited_response(&mut info);
        if !outgoing_addrs.is_empty() {
            self.notify_monitors(DaemonEvent::Announce(
                info.get_fullname().to_string(),
                format!("{:?}", &outgoing_addrs),
            ));
        }

        // The key has to be lower case letter as DNS record name is case insensitive.
        // The info will have the original name.
        let service_fullname = info.get_fullname().to_lowercase();
        self.my_services.insert(service_fullname, info);
    }

    /// Sends out announcement of `info` on every valid interface.
    /// Returns the list of interface IPs that sent out the announcement.
    fn send_unsolicited_response(&mut self, info: &mut ServiceInfo) -> Vec<IpAddr> {
        let mut outgoing_addrs = Vec::new();
        // Send the announcement on one interface per ip version.
        let mut multicast_sent_trackers = HashSet::new();

        let mut outgoing_intfs = Vec::new();

        for (intf, sock) in self.intf_socks.iter() {
            if let Some(tracker) = multicast_send_tracker(intf) {
                if multicast_sent_trackers.contains(&tracker) {
                    continue; // No need to send again on the same interface with same ip version.
                }
            }

            let dns_registry = match self.dns_registry_map.get_mut(intf) {
                Some(registry) => registry,
                None => self
                    .dns_registry_map
                    .entry(intf.clone())
                    .or_insert_with(DnsRegistry::new),
            };

            if announce_service_on_intf(dns_registry, info, intf, sock) {
                if let Some(tracker) = multicast_send_tracker(intf) {
                    multicast_sent_trackers.insert(tracker);
                }
                outgoing_addrs.push(intf.ip());
                outgoing_intfs.push(intf.clone());

                debug!("Announce service {} on {}", info.get_fullname(), intf.ip());

                info.set_status(intf, ServiceStatus::Announced);
            } else {
                for timer in dns_registry.new_timers.drain(..) {
                    self.timers.push(Reverse(timer));
                }
                info.set_status(intf, ServiceStatus::Probing);
            }
        }

        // RFC 6762 section 8.3.
        // ..The Multicast DNS responder MUST send at least two unsolicited
        //    responses, one second apart.
        let next_time = current_time_millis() + 1000;
        for intf in outgoing_intfs {
            self.add_retransmission(
                next_time,
                Command::RegisterResend(info.get_fullname().to_string(), intf),
            );
        }

        outgoing_addrs
    }

    /// Send probings or finish them if expired. Notify waiting services.
    fn probing_handler(&mut self) {
        let now = current_time_millis();

        for (intf, sock) in self.intf_socks.iter() {
            let Some(dns_registry) = self.dns_registry_map.get_mut(intf) else {
                continue;
            };

            let mut expired_probe_names = Vec::new();
            let mut out = DnsOutgoing::new(FLAGS_QR_QUERY);

            for (name, probe) in dns_registry.probing.iter_mut() {
                if now >= probe.next_send {
                    if probe.expired(now) {
                        // move the record to active
                        expired_probe_names.push(name.clone());
                    } else {
                        out.add_question(name, RRType::ANY);

                        /*
                        RFC 6762 section 8.2: https://datatracker.ietf.org/doc/html/rfc6762#section-8.2
                        ...
                        for tiebreaking to work correctly in all
                        cases, the Authority Section must contain *all* the records and
                        proposed rdata being probed for uniqueness.
                         */
                        for record in probe.records.iter() {
                            out.add_authority(record.clone());
                        }

                        probe.update_next_send(now);

                        // add timer
                        self.timers.push(Reverse(probe.next_send));
                    }
                }
            }

            // send probing.
            if !out.questions().is_empty() {
                debug!("sending out probing of {} questions", out.questions().len());
                send_dns_outgoing(&out, intf, sock);
            }

            let mut waiting_services = HashSet::new();

            for name in expired_probe_names {
                let Some(probe) = dns_registry.probing.remove(&name) else {
                    continue;
                };

                // send notifications about name changes
                for record in probe.records.iter() {
                    if let Some(new_name) = record.get_record().get_new_name() {
                        dns_registry
                            .name_changes
                            .insert(name.clone(), new_name.to_string());

                        let event = DnsNameChange {
                            original: record.get_record().get_original_name().to_string(),
                            new_name: new_name.to_string(),
                            rr_type: record.get_type(),
                            intf_name: intf.name.to_string(),
                        };
                        notify_monitors(&mut self.monitors, DaemonEvent::NameChange(event));
                    }
                }

                // move RR from probe to active.
                debug!(
                    "probe of '{name}' finished: move {} records to active. ({} waiting services)",
                    probe.records.len(),
                    probe.waiting_services.len(),
                );

                // Move records to active and plan to wake up services if records are not empty.
                if !probe.records.is_empty() {
                    match dns_registry.active.get_mut(&name) {
                        Some(records) => {
                            records.extend(probe.records);
                        }
                        None => {
                            dns_registry.active.insert(name, probe.records);
                        }
                    }

                    waiting_services.extend(probe.waiting_services);
                }
            }

            // wake up services waiting.
            for service_name in waiting_services {
                debug!(
                    "try to announce service {service_name} on intf {}",
                    intf.ip()
                );
                // service names are lowercase
                if let Some(info) = self.my_services.get_mut(&service_name.to_lowercase()) {
                    if info.get_status(intf) == ServiceStatus::Announced {
                        debug!("service {} already announced", info.get_fullname());
                        continue;
                    }

                    if announce_service_on_intf(dns_registry, info, intf, sock) {
                        let next_time = now + 1000;
                        let command =
                            Command::RegisterResend(info.get_fullname().to_string(), intf.clone());
                        self.retransmissions.push(ReRun { next_time, command });
                        self.timers.push(Reverse(next_time));

                        let fullname = match dns_registry.name_changes.get(&service_name) {
                            Some(new_name) => new_name.to_string(),
                            None => service_name.to_string(),
                        };

                        let mut hostname = info.get_hostname();
                        if let Some(new_name) = dns_registry.name_changes.get(hostname) {
                            hostname = new_name;
                        }

                        debug!("wake up: announce service {} on {}", fullname, intf.ip());
                        notify_monitors(
                            &mut self.monitors,
                            DaemonEvent::Announce(fullname, format!("{}:{}", hostname, &intf.ip())),
                        );

                        info.set_status(intf, ServiceStatus::Announced);
                    }
                }
            }
        }
    }

    fn unregister_service(
        &self,
        info: &ServiceInfo,
        intf: &Interface,
        sock: &MioUdpSocket,
    ) -> Vec<u8> {
        let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
        out.add_answer_at_time(
            DnsPointer::new(
                info.get_type(),
                RRType::PTR,
                CLASS_IN,
                0,
                info.get_fullname().to_string(),
            ),
            0,
        );

        if let Some(sub) = info.get_subtype() {
            trace!("Adding subdomain {}", sub);
            out.add_answer_at_time(
                DnsPointer::new(
                    sub,
                    RRType::PTR,
                    CLASS_IN,
                    0,
                    info.get_fullname().to_string(),
                ),
                0,
            );
        }

        out.add_answer_at_time(
            DnsSrv::new(
                info.get_fullname(),
                CLASS_IN | CLASS_CACHE_FLUSH,
                0,
                info.get_priority(),
                info.get_weight(),
                info.get_port(),
                info.get_hostname().to_string(),
            ),
            0,
        );
        out.add_answer_at_time(
            DnsTxt::new(
                info.get_fullname(),
                CLASS_IN | CLASS_CACHE_FLUSH,
                0,
                info.generate_txt(),
            ),
            0,
        );

        for address in info.get_addrs_on_intf(intf) {
            out.add_answer_at_time(
                DnsAddress::new(
                    info.get_hostname(),
                    ip_address_rr_type(&address),
                    CLASS_IN | CLASS_CACHE_FLUSH,
                    0,
                    address,
                ),
                0,
            );
        }

        // `out` data is non-empty, hence we can do this.
        send_dns_outgoing(&out, intf, sock).remove(0)
    }

    /// Binds a channel `listener` to querying mDNS hostnames.
    ///
    /// If there is already a `listener`, it will be updated, i.e. overwritten.
    fn add_hostname_resolver(
        &mut self,
        hostname: String,
        listener: Sender<HostnameResolutionEvent>,
        timeout: Option<u64>,
    ) {
        let real_timeout = timeout.map(|t| current_time_millis() + t);
        self.hostname_resolvers
            .insert(hostname, (listener, real_timeout));
        if let Some(t) = real_timeout {
            self.add_timer(t);
        }
    }

    /// Sends a multicast query for `name` with `qtype`.
    fn send_query(&self, name: &str, qtype: RRType) {
        self.send_query_vec(&[(name, qtype)]);
    }

    /// Sends out a list of `questions` (i.e. DNS questions) via multicast.
    fn send_query_vec(&self, questions: &[(&str, RRType)]) {
        trace!("Sending query questions: {:?}", questions);
        let mut out = DnsOutgoing::new(FLAGS_QR_QUERY);
        let now = current_time_millis();

        for (name, qtype) in questions {
            out.add_question(name, *qtype);

            for record in self.cache.get_known_answers(name, *qtype, now) {
                /*
                RFC 6762 section 7.1: https://datatracker.ietf.org/doc/html/rfc6762#section-7.1
                ...
                    When a Multicast DNS querier sends a query to which it already knows
                    some answers, it populates the Answer Section of the DNS query
                    message with those answers.
                 */
                trace!("add known answer: {:?}", record);
                let mut new_record = record.clone();
                new_record.get_record_mut().update_ttl(now);
                out.add_answer_box(new_record);
            }
        }

        // Send the query on one interface per ip version.
        let mut multicast_sent_trackers = HashSet::new();
        for (intf, sock) in self.intf_socks.iter() {
            if let Some(tracker) = multicast_send_tracker(intf) {
                if multicast_sent_trackers.contains(&tracker) {
                    continue; // no need to send query the same interface with same ip version.
                }
                multicast_sent_trackers.insert(tracker);
            }
            send_dns_outgoing(&out, intf, sock);
        }
    }

    /// Reads from the socket of `ip`.
    ///
    /// Returns false if failed to receive a packet,
    /// otherwise returns true.
    fn handle_read(&mut self, intf: &Interface) -> bool {
        let sock = match self.intf_socks.get_mut(intf) {
            Some(if_sock) => if_sock,
            None => return false,
        };
        let mut buf = vec![0u8; MAX_MSG_ABSOLUTE];

        // Read the next mDNS UDP datagram.
        //
        // If the datagram is larger than `buf`, excess bytes may or may not
        // be truncated by the socket layer depending on the platform's libc.
        // In any case, such large datagram will not be decoded properly and
        // this function should return false but should not crash.
        let sz = match sock.recv(&mut buf) {
            Ok(sz) => sz,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    debug!("listening socket read failed: {}", e);
                }
                return false;
            }
        };

        trace!("received {} bytes at IP: {}", sz, intf.ip());

        // If sz is 0, it means sock reached End-of-File.
        if sz == 0 {
            debug!("socket {:?} was likely shutdown", &sock);
            if let Err(e) = self.poller.registry().deregister(sock) {
                debug!("failed to remove sock {:?} from poller: {}", sock, &e);
            }

            // Replace the closed socket with a new one.
            let should_loop = if intf.ip().is_ipv4() {
                self.multicast_loop_v4
            } else {
                self.multicast_loop_v6
            };
            match new_socket_bind(intf, should_loop) {
                Ok(new_sock) => {
                    trace!("reset socket for IP {}", intf.ip());
                    self.intf_socks.insert(intf.clone(), new_sock);
                }
                Err(e) => debug!("re-bind a socket to {:?}: {}", intf, e),
            }

            return false;
        }

        buf.truncate(sz); // reduce potential processing errors

        match DnsIncoming::new(buf) {
            Ok(msg) => {
                if msg.is_query() {
                    self.handle_query(msg, intf);
                } else if msg.is_response() {
                    self.handle_response(msg, intf);
                } else {
                    debug!("Invalid message: not query and not response");
                }
            }
            Err(e) => debug!("Invalid incoming DNS message: {}", e),
        }

        true
    }

    /// Returns true, if sent query. Returns false if SRV already exists.
    fn query_unresolved(&mut self, instance: &str) -> bool {
        if !valid_instance_name(instance) {
            trace!("instance name {} not valid", instance);
            return false;
        }

        if let Some(records) = self.cache.get_srv(instance) {
            for record in records {
                if let Some(srv) = record.any().downcast_ref::<DnsSrv>() {
                    if self.cache.get_addr(srv.host()).is_none() {
                        self.send_query_vec(&[(srv.host(), RRType::A), (srv.host(), RRType::AAAA)]);
                        return true;
                    }
                }
            }
        } else {
            self.send_query(instance, RRType::ANY);
            return true;
        }

        false
    }

    /// Checks if `ty_domain` has records in the cache. If yes, sends the
    /// cached records via `sender`.
    fn query_cache_for_service(&mut self, ty_domain: &str, sender: &Sender<ServiceEvent>) {
        let mut resolved: HashSet<String> = HashSet::new();
        let mut unresolved: HashSet<String> = HashSet::new();

        if let Some(records) = self.cache.get_ptr(ty_domain) {
            for record in records.iter() {
                if let Some(ptr) = record.any().downcast_ref::<DnsPointer>() {
                    let info = match self.create_service_info_from_cache(ty_domain, ptr.alias()) {
                        Ok(ok) => ok,
                        Err(err) => {
                            debug!("Error while creating service info from cache: {}", err);
                            continue;
                        }
                    };

                    match sender.send(ServiceEvent::ServiceFound(
                        ty_domain.to_string(),
                        ptr.alias().to_string(),
                    )) {
                        Ok(()) => trace!("send service found {}", ptr.alias()),
                        Err(e) => {
                            debug!("failed to send service found: {}", e);
                            continue;
                        }
                    }

                    if info.is_ready() {
                        resolved.insert(ptr.alias().to_string());
                        match sender.send(ServiceEvent::ServiceResolved(info)) {
                            Ok(()) => trace!("sent service resolved: {}", ptr.alias()),
                            Err(e) => debug!("failed to send service resolved: {}", e),
                        }
                    } else {
                        unresolved.insert(ptr.alias().to_string());
                    }
                }
            }
        }

        for instance in resolved.drain() {
            self.pending_resolves.remove(&instance);
            self.resolved.insert(instance);
        }

        for instance in unresolved.drain() {
            self.add_pending_resolve(instance);
        }
    }

    /// Checks if `hostname` has records in the cache. If yes, sends the
    /// cached records via `sender`.
    fn query_cache_for_hostname(
        &mut self,
        hostname: &str,
        sender: Sender<HostnameResolutionEvent>,
    ) {
        let addresses = self.cache.get_addresses_for_host(hostname);
        if !addresses.is_empty() {
            match sender.send(HostnameResolutionEvent::AddressesFound(
                hostname.to_string(),
                addresses,
            )) {
                Ok(()) => trace!("sent hostname addresses found"),
                Err(e) => debug!("failed to send hostname addresses found: {}", e),
            }
        }
    }

    fn add_pending_resolve(&mut self, instance: String) {
        if !self.pending_resolves.contains(&instance) {
            let next_time = current_time_millis() + RESOLVE_WAIT_IN_MILLIS;
            self.add_retransmission(next_time, Command::Resolve(instance.clone(), 1));
            self.pending_resolves.insert(instance);
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

        let now = current_time_millis();
        let mut info = ServiceInfo::new(ty_domain, &my_name, "", (), 0, None)?;

        // Be sure setting `subtype` if available even when querying for the parent domain.
        if let Some(subtype) = self.cache.get_subtype(fullname) {
            trace!(
                "ty_domain: {} found subtype {} for instance: {}",
                ty_domain,
                subtype,
                fullname
            );
            if info.get_subtype().is_none() {
                info.set_subtype(subtype.clone());
            }
        }

        // resolve SRV record
        if let Some(records) = self.cache.get_srv(fullname) {
            if let Some(answer) = records.first() {
                if let Some(dns_srv) = answer.any().downcast_ref::<DnsSrv>() {
                    info.set_hostname(dns_srv.host().to_string());
                    info.set_port(dns_srv.port());
                }
            }
        }

        // resolve TXT record
        if let Some(records) = self.cache.get_txt(fullname) {
            if let Some(record) = records.first() {
                if let Some(dns_txt) = record.any().downcast_ref::<DnsTxt>() {
                    info.set_properties_from_txt(dns_txt.text());
                }
            }
        }

        // resolve A and AAAA records
        if let Some(records) = self.cache.get_addr(info.get_hostname()) {
            for answer in records.iter() {
                if let Some(dns_a) = answer.any().downcast_ref::<DnsAddress>() {
                    if dns_a.get_record().is_expired(now) {
                        trace!("Addr expired: {}", dns_a.address());
                    } else {
                        info.insert_ipaddr(dns_a.address());
                    }
                }
            }
        }

        Ok(info)
    }

    /// Deal with incoming response packets.  All answers
    /// are held in the cache, and listeners are notified.
    fn handle_response(&mut self, mut msg: DnsIncoming, intf: &Interface) {
        trace!(
            "handle_response: {} answers {} authorities {} additionals",
            msg.answers().len(),
            &msg.authorities().len(),
            &msg.num_additionals()
        );
        let now = current_time_millis();

        // remove records that are expired.
        let mut record_predicate = |record: &DnsRecordBox| {
            if !record.get_record().is_expired(now) {
                return true;
            }

            debug!("record is expired, removing it from cache.");
            if self.cache.remove(record) {
                // for PTR records, send event to listeners
                if let Some(dns_ptr) = record.any().downcast_ref::<DnsPointer>() {
                    call_service_listener(
                        &self.service_queriers,
                        dns_ptr.get_name(),
                        ServiceEvent::ServiceRemoved(
                            dns_ptr.get_name().to_string(),
                            dns_ptr.alias().to_string(),
                        ),
                    );
                }
            }
            false
        };
        msg.answers_mut().retain(&mut record_predicate);
        msg.authorities_mut().retain(&mut record_predicate);
        msg.additionals_mut().retain(&mut record_predicate);

        // check possible conflicts and handle them.
        self.conflict_handler(&msg, intf);

        /// Represents a DNS record change that involves one service instance.
        struct InstanceChange {
            ty: RRType,   // The type of DNS record for the instance.
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
        let mut timers = Vec::new();
        for record in msg.all_records() {
            match self.cache.add_or_update(intf, record, &mut timers) {
                Some((dns_record, true)) => {
                    timers.push(dns_record.get_record().get_expire_time());
                    timers.push(dns_record.get_record().get_refresh_time());

                    let ty = dns_record.get_type();
                    let name = dns_record.get_name();
                    if ty == RRType::PTR {
                        if self.service_queriers.contains_key(name) {
                            timers.push(dns_record.get_record().get_refresh_time());
                        }

                        // send ServiceFound
                        if let Some(dns_ptr) = dns_record.any().downcast_ref::<DnsPointer>() {
                            call_service_listener(
                                &self.service_queriers,
                                name,
                                ServiceEvent::ServiceFound(
                                    name.to_string(),
                                    dns_ptr.alias().to_string(),
                                ),
                            );
                            changes.push(InstanceChange {
                                ty,
                                name: dns_ptr.alias().to_string(),
                            });
                        }
                    } else {
                        changes.push(InstanceChange {
                            ty,
                            name: name.to_string(),
                        });
                    }
                }
                Some((dns_record, false)) => {
                    timers.push(dns_record.get_record().get_expire_time());
                    timers.push(dns_record.get_record().get_refresh_time());
                }
                _ => {}
            }
        }

        // Add timers for the new records.
        for t in timers {
            self.add_timer(t);
        }

        // Go through remaining changes to see if any hostname resolutions were found or updated.
        changes
            .iter()
            .filter(|change| change.ty == RRType::A || change.ty == RRType::AAAA)
            .map(|change| change.name.clone())
            .collect::<HashSet<String>>()
            .iter()
            .map(|hostname| (hostname, self.cache.get_addresses_for_host(hostname)))
            .for_each(|(hostname, addresses)| {
                call_hostname_resolution_listener(
                    &self.hostname_resolvers,
                    hostname,
                    HostnameResolutionEvent::AddressesFound(hostname.to_string(), addresses),
                )
            });

        // Identify the instances that need to be "resolved".
        let mut updated_instances = HashSet::new();
        for update in changes {
            match update.ty {
                RRType::PTR | RRType::SRV | RRType::TXT => {
                    updated_instances.insert(update.name);
                }
                RRType::A | RRType::AAAA => {
                    let instances = self.cache.get_instances_on_host(&update.name);
                    updated_instances.extend(instances);
                }
                _ => {}
            }
        }

        self.resolve_updated_instances(&updated_instances);
    }

    fn conflict_handler(&mut self, msg: &DnsIncoming, intf: &Interface) {
        let Some(dns_registry) = self.dns_registry_map.get_mut(intf) else {
            return;
        };

        for answer in msg.answers().iter() {
            let mut new_records = Vec::new();

            let name = answer.get_name();
            let Some(probe) = dns_registry.probing.get_mut(name) else {
                continue;
            };

            // check against possible multicast forwarding
            if answer.get_type() == RRType::A || answer.get_type() == RRType::AAAA {
                if let Some(answer_addr) = answer.any().downcast_ref::<DnsAddress>() {
                    if !valid_ip_on_intf(&answer_addr.address(), intf) {
                        debug!(
                            "conflict handler: answer addr {:?} not in the subnet of {:?}",
                            answer_addr, intf
                        );
                        continue;
                    }
                }

                // double check if any other address record matches rrdata,
                // as there could be multiple addresses for the same name.
                let any_match = probe.records.iter().any(|r| {
                    r.get_type() == answer.get_type()
                        && r.get_class() == answer.get_class()
                        && r.rrdata_match(answer.as_ref())
                });
                if any_match {
                    continue; // no conflict for this answer.
                }
            }

            probe.records.retain(|record| {
                if record.get_type() == answer.get_type()
                    && record.get_class() == answer.get_class()
                    && !record.rrdata_match(answer.as_ref())
                {
                    debug!(
                        "found conflict name: '{name}' record: {}: {} PEER: {}",
                        record.get_type(),
                        record.rdata_print(),
                        answer.rdata_print()
                    );

                    // create a new name for this record
                    // then remove the old record in probing.
                    let mut new_record = record.clone();
                    let new_name = match record.get_type() {
                        RRType::A => hostname_change(name),
                        RRType::AAAA => hostname_change(name),
                        _ => name_change(name),
                    };
                    new_record.get_record_mut().set_new_name(new_name);
                    new_records.push(new_record);
                    return false; // old record is dropped from the probe.
                }

                true
            });

            // ?????
            // if probe.records.is_empty() {
            //     dns_registry.probing.remove(name);
            // }

            // Probing again with the new names.
            let create_time = current_time_millis() + fastrand::u64(0..250);

            let waiting_services = probe.waiting_services.clone();

            for record in new_records {
                if dns_registry.update_hostname(name, record.get_name(), create_time) {
                    self.timers.push(Reverse(create_time));
                }

                // remember the name changes (note: `name` might not be the original, it could be already changed once.)
                dns_registry.name_changes.insert(
                    record.get_record().get_original_name().to_string(),
                    record.get_name().to_string(),
                );

                let new_probe = match dns_registry.probing.get_mut(record.get_name()) {
                    Some(p) => p,
                    None => {
                        let new_probe = dns_registry
                            .probing
                            .entry(record.get_name().to_string())
                            .or_insert_with(|| {
                                debug!("conflict handler: new probe of {}", record.get_name());
                                Probe::new(create_time)
                            });
                        self.timers.push(Reverse(new_probe.next_send));
                        new_probe
                    }
                };

                debug!(
                    "insert record with new name '{}' {} into probe",
                    record.get_name(),
                    record.get_type()
                );
                new_probe.insert_record(record);

                new_probe.waiting_services.extend(waiting_services.clone());
            }
        }
    }

    /// Resolve the updated (including new) instances.
    ///
    /// Note: it is possible that more than 1 PTR pointing to the same
    /// instance. For example, a regular service type PTR and a sub-type
    /// service type PTR can both point to the same service instance.
    /// This loop automatically handles the sub-type PTRs.
    fn resolve_updated_instances(&mut self, updated_instances: &HashSet<String>) {
        let mut resolved: HashSet<String> = HashSet::new();
        let mut unresolved: HashSet<String> = HashSet::new();
        let mut removed_instances = HashMap::new();

        for (ty_domain, records) in self.cache.all_ptr().iter() {
            if !self.service_queriers.contains_key(ty_domain) {
                // No need to resolve if not in our queries.
                continue;
            }

            for record in records.iter() {
                if let Some(dns_ptr) = record.any().downcast_ref::<DnsPointer>() {
                    if updated_instances.contains(dns_ptr.alias()) {
                        if let Ok(info) =
                            self.create_service_info_from_cache(ty_domain, dns_ptr.alias())
                        {
                            if info.is_ready() {
                                resolved.insert(dns_ptr.alias().to_string());
                                call_service_listener(
                                    &self.service_queriers,
                                    ty_domain,
                                    ServiceEvent::ServiceResolved(info),
                                );
                            } else {
                                if self.resolved.remove(dns_ptr.alias()) {
                                    removed_instances
                                        .entry(ty_domain.to_string())
                                        .or_insert_with(HashSet::new)
                                        .insert(dns_ptr.alias().to_string());
                                }
                                unresolved.insert(dns_ptr.alias().to_string());
                            }
                        }
                    }
                }
            }
        }

        for instance in resolved.drain() {
            self.pending_resolves.remove(&instance);
            self.resolved.insert(instance);
        }

        for instance in unresolved.drain() {
            self.add_pending_resolve(instance);
        }

        self.notify_service_removal(removed_instances);
    }

    /// Handle incoming query packets, figure out whether and what to respond.
    fn handle_query(&mut self, msg: DnsIncoming, intf: &Interface) {
        let sock = match self.intf_socks.get(intf) {
            Some(sock) => sock,
            None => return,
        };
        let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);

        // Special meta-query "_services._dns-sd._udp.<Domain>".
        // See https://datatracker.ietf.org/doc/html/rfc6763#section-9
        const META_QUERY: &str = "_services._dns-sd._udp.local.";

        let Some(dns_registry) = self.dns_registry_map.get_mut(intf) else {
            debug!("missing dns registry for intf {}", intf.ip());
            return;
        };

        for question in msg.questions().iter() {
            trace!("query question: {:?}", &question);

            let qtype = question.entry_type();

            if qtype == RRType::PTR {
                for service in self.my_services.values() {
                    if service.get_status(intf) != ServiceStatus::Announced {
                        continue;
                    }

                    if question.entry_name() == service.get_type()
                        || service
                            .get_subtype()
                            .as_ref()
                            .is_some_and(|v| v == question.entry_name())
                    {
                        add_answer_with_additionals(&mut out, &msg, service, intf, dns_registry);
                    } else if question.entry_name() == META_QUERY {
                        let ptr_added = out.add_answer(
                            &msg,
                            DnsPointer::new(
                                question.entry_name(),
                                RRType::PTR,
                                CLASS_IN,
                                service.get_other_ttl(),
                                service.get_type().to_string(),
                            ),
                        );
                        if !ptr_added {
                            trace!("answer was not added for meta-query {:?}", &question);
                        }
                    }
                }
            } else {
                // Simultaneous Probe Tiebreaking (RFC 6762 section 8.2)
                if qtype == RRType::ANY && msg.num_authorities() > 0 {
                    let probe_name = question.entry_name();

                    if let Some(probe) = dns_registry.probing.get_mut(probe_name) {
                        let now = current_time_millis();

                        // Only do tiebreaking if probe already started.
                        // This check also helps avoid redo tiebreaking if start time
                        // was postponed.
                        if probe.start_time < now {
                            let incoming_records: Vec<_> = msg
                                .authorities()
                                .iter()
                                .filter(|r| r.get_name() == probe_name)
                                .collect();

                            /*
                            RFC 6762 section 8.2: https://datatracker.ietf.org/doc/html/rfc6762#section-8.2
                            ...
                            if the host finds that its own data is lexicographically later, it
                            simply ignores the other host's probe.  If the host finds that its
                            own data is lexicographically earlier, then it defers to the winning
                            host by waiting one second, and then begins probing for this record
                            again.
                            */
                            match probe.tiebreaking(&incoming_records) {
                                cmp::Ordering::Less => {
                                    debug!(
                                        "tiebreaking '{}': LOST, will wait for one second",
                                        probe_name
                                    );
                                    probe.start_time = now + 1000; // wait and restart.
                                    probe.next_send = now + 1000;
                                }
                                ordering => {
                                    debug!("tiebreaking '{}': {:?}", probe_name, ordering);
                                }
                            }
                        }
                    }
                }

                if qtype == RRType::A || qtype == RRType::AAAA || qtype == RRType::ANY {
                    for service in self.my_services.values() {
                        if service.get_status(intf) != ServiceStatus::Announced {
                            continue;
                        }

                        let service_hostname =
                            match dns_registry.name_changes.get(service.get_hostname()) {
                                Some(new_name) => new_name,
                                None => service.get_hostname(),
                            };

                        if service_hostname.to_lowercase() == question.entry_name().to_lowercase() {
                            let intf_addrs = service.get_addrs_on_intf(intf);
                            if intf_addrs.is_empty()
                                && (qtype == RRType::A || qtype == RRType::AAAA)
                            {
                                let t = match qtype {
                                    RRType::A => "TYPE_A",
                                    RRType::AAAA => "TYPE_AAAA",
                                    _ => "invalid_type",
                                };
                                trace!(
                                    "Cannot find valid addrs for {} response on intf {:?}",
                                    t,
                                    &intf
                                );
                                return;
                            }
                            for address in intf_addrs {
                                out.add_answer(
                                    &msg,
                                    DnsAddress::new(
                                        question.entry_name(),
                                        ip_address_rr_type(&address),
                                        CLASS_IN | CLASS_CACHE_FLUSH,
                                        service.get_host_ttl(),
                                        address,
                                    ),
                                );
                            }
                        }
                    }
                }

                let query_name = question.entry_name().to_lowercase();
                let service_opt = self
                    .my_services
                    .iter()
                    .find(|(k, _v)| {
                        let service_name = match dns_registry.name_changes.get(k.as_str()) {
                            Some(new_name) => new_name,
                            None => k,
                        };
                        service_name == &query_name
                    })
                    .map(|(_, v)| v);

                let Some(service) = service_opt else {
                    continue;
                };

                if service.get_status(intf) != ServiceStatus::Announced {
                    continue;
                }

                if qtype == RRType::SRV || qtype == RRType::ANY {
                    out.add_answer(
                        &msg,
                        DnsSrv::new(
                            question.entry_name(),
                            CLASS_IN | CLASS_CACHE_FLUSH,
                            service.get_host_ttl(),
                            service.get_priority(),
                            service.get_weight(),
                            service.get_port(),
                            service.get_hostname().to_string(),
                        ),
                    );
                }

                if qtype == RRType::TXT || qtype == RRType::ANY {
                    out.add_answer(
                        &msg,
                        DnsTxt::new(
                            question.entry_name(),
                            CLASS_IN | CLASS_CACHE_FLUSH,
                            service.get_host_ttl(),
                            service.generate_txt(),
                        ),
                    );
                }

                if qtype == RRType::SRV {
                    let intf_addrs = service.get_addrs_on_intf(intf);
                    if intf_addrs.is_empty() {
                        debug!(
                            "Cannot find valid addrs for TYPE_SRV response on intf {:?}",
                            &intf
                        );
                        return;
                    }
                    for address in intf_addrs {
                        out.add_additional_answer(DnsAddress::new(
                            service.get_hostname(),
                            ip_address_rr_type(&address),
                            CLASS_IN | CLASS_CACHE_FLUSH,
                            service.get_host_ttl(),
                            address,
                        ));
                    }
                }
            }
        }

        if !out.answers_count() > 0 {
            out.set_id(msg.id());
            send_dns_outgoing(&out, intf, sock);

            self.increase_counter(Counter::Respond, 1);
            self.notify_monitors(DaemonEvent::Respond(intf.ip()));
        }

        self.increase_counter(Counter::KnownAnswerSuppression, out.known_answer_count());
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

    fn signal_sock_drain(&self) {
        let mut signal_buf = [0; 1024];

        // This recv is non-blocking as the socket is non-blocking.
        while let Ok(sz) = self.signal_sock.recv(&mut signal_buf) {
            trace!(
                "signal socket recvd: {}",
                String::from_utf8_lossy(&signal_buf[0..sz])
            );
        }
    }

    fn add_retransmission(&mut self, next_time: u64, command: Command) {
        self.retransmissions.push(ReRun { next_time, command });
        self.add_timer(next_time);
    }

    /// Sends service removal event to listeners for expired service records.
    fn notify_service_removal(&self, expired: HashMap<String, HashSet<String>>) {
        for (ty_domain, sender) in self.service_queriers.iter() {
            if let Some(instances) = expired.get(ty_domain) {
                for instance_name in instances {
                    let event = ServiceEvent::ServiceRemoved(
                        ty_domain.to_string(),
                        instance_name.to_string(),
                    );
                    match sender.send(event) {
                        Ok(()) => debug!("notify_service_removal: sent ServiceRemoved to listener of {ty_domain}: {instance_name}"),
                        Err(e) => debug!("Failed to send event: {}", e),
                    }
                }
            }
        }
    }

    /// The entry point that executes all commands received by the daemon.
    ///
    /// `repeating`: whether this is a retransmission.
    fn exec_command(&mut self, command: Command, repeating: bool) {
        match command {
            Command::Browse(ty, next_delay, listener) => {
                self.exec_command_browse(repeating, ty, next_delay, listener);
            }

            Command::ResolveHostname(hostname, next_delay, listener, timeout) => {
                self.exec_command_resolve_hostname(
                    repeating, hostname, next_delay, listener, timeout,
                );
            }

            Command::Register(service_info) => {
                self.register_service(service_info);
                self.increase_counter(Counter::Register, 1);
            }

            Command::RegisterResend(fullname, intf) => {
                trace!("register-resend service: {fullname} on {:?}", &intf.addr);
                self.exec_command_register_resend(fullname, intf);
            }

            Command::Unregister(fullname, resp_s) => {
                trace!("unregister service {} repeat {}", &fullname, &repeating);
                self.exec_command_unregister(repeating, fullname, resp_s);
            }

            Command::UnregisterResend(packet, ip) => {
                self.exec_command_unregister_resend(packet, ip);
            }

            Command::StopBrowse(ty_domain) => self.exec_command_stop_browse(ty_domain),

            Command::StopResolveHostname(hostname) => {
                self.exec_command_stop_resolve_hostname(hostname)
            }

            Command::Resolve(instance, try_count) => self.exec_command_resolve(instance, try_count),

            Command::GetMetrics(resp_s) => match resp_s.send(self.counters.clone()) {
                Ok(()) => trace!("Sent metrics to the client"),
                Err(e) => debug!("Failed to send metrics: {}", e),
            },

            Command::GetStatus(resp_s) => match resp_s.send(self.status.clone()) {
                Ok(()) => trace!("Sent status to the client"),
                Err(e) => debug!("Failed to send status: {}", e),
            },

            Command::Monitor(resp_s) => {
                self.monitors.push(resp_s);
            }

            Command::SetOption(daemon_opt) => {
                self.process_set_option(daemon_opt);
            }

            Command::Verify(instance_fullname, timeout) => {
                self.exec_command_verify(instance_fullname, timeout, repeating);
            }

            _ => {
                debug!("unexpected command: {:?}", &command);
            }
        }
    }

    fn exec_command_browse(
        &mut self,
        repeating: bool,
        ty: String,
        next_delay: u32,
        listener: Sender<ServiceEvent>,
    ) {
        let pretty_addrs: Vec<String> = self
            .intf_socks
            .keys()
            .map(|itf| format!("{} ({})", itf.ip(), itf.name))
            .collect();

        if let Err(e) = listener.send(ServiceEvent::SearchStarted(format!(
            "{ty} on {} interfaces [{}]",
            pretty_addrs.len(),
            pretty_addrs.join(", ")
        ))) {
            debug!(
                "Failed to send SearchStarted({})(repeating:{}): {}",
                &ty, repeating, e
            );
            return;
        }
        if !repeating {
            // Binds a `listener` to querying mDNS domain type `ty`.
            //
            // If there is already a `listener`, it will be updated, i.e. overwritten.
            self.service_queriers.insert(ty.clone(), listener.clone());

            // if we already have the records in our cache, just send them
            self.query_cache_for_service(&ty, &listener);
        }

        self.send_query(&ty, RRType::PTR);
        self.increase_counter(Counter::Browse, 1);

        let next_time = current_time_millis() + (next_delay * 1000) as u64;
        let max_delay = 60 * 60;
        let delay = cmp::min(next_delay * 2, max_delay);
        self.add_retransmission(next_time, Command::Browse(ty, delay, listener));
    }

    fn exec_command_resolve_hostname(
        &mut self,
        repeating: bool,
        hostname: String,
        next_delay: u32,
        listener: Sender<HostnameResolutionEvent>,
        timeout: Option<u64>,
    ) {
        let addr_list: Vec<_> = self.intf_socks.keys().collect();
        if let Err(e) = listener.send(HostnameResolutionEvent::SearchStarted(format!(
            "{} on addrs {:?}",
            &hostname, &addr_list
        ))) {
            debug!(
                "Failed to send ResolveStarted({})(repeating:{}): {}",
                &hostname, repeating, e
            );
            return;
        }
        if !repeating {
            self.add_hostname_resolver(hostname.to_owned(), listener.clone(), timeout);
            // if we already have the records in our cache, just send them
            self.query_cache_for_hostname(&hostname, listener.clone());
        }

        self.send_query_vec(&[(&hostname, RRType::A), (&hostname, RRType::AAAA)]);
        self.increase_counter(Counter::ResolveHostname, 1);

        let now = current_time_millis();
        let next_time = now + u64::from(next_delay) * 1000;
        let max_delay = 60 * 60;
        let delay = cmp::min(next_delay * 2, max_delay);

        // Only add retransmission if it does not exceed the hostname resolver timeout, if any.
        if self
            .hostname_resolvers
            .get(&hostname)
            .and_then(|(_sender, timeout)| *timeout)
            .map(|timeout| next_time < timeout)
            .unwrap_or(true)
        {
            self.add_retransmission(
                next_time,
                Command::ResolveHostname(hostname, delay, listener, None),
            );
        }
    }

    fn exec_command_resolve(&mut self, instance: String, try_count: u16) {
        let pending_query = self.query_unresolved(&instance);
        let max_try = 3;
        if pending_query && try_count < max_try {
            // Note that if the current try already succeeds, the next retransmission
            // will be no-op as the cache has been updated.
            let next_time = current_time_millis() + RESOLVE_WAIT_IN_MILLIS;
            self.add_retransmission(next_time, Command::Resolve(instance, try_count + 1));
        }
    }

    fn exec_command_unregister(
        &mut self,
        repeating: bool,
        fullname: String,
        resp_s: Sender<UnregisterStatus>,
    ) {
        let response = match self.my_services.remove_entry(&fullname) {
            None => {
                debug!("unregister: cannot find such service {}", &fullname);
                UnregisterStatus::NotFound
            }
            Some((_k, info)) => {
                let mut timers = Vec::new();
                // Send one unregister per interface and ip version
                let mut multicast_sent_trackers = HashSet::new();

                for (intf, sock) in self.intf_socks.iter() {
                    if let Some(tracker) = multicast_send_tracker(intf) {
                        if multicast_sent_trackers.contains(&tracker) {
                            continue; // no need to send unregister the same interface with same ip version.
                        }
                        multicast_sent_trackers.insert(tracker);
                    }
                    let packet = self.unregister_service(&info, intf, sock);
                    // repeat for one time just in case some peers miss the message
                    if !repeating && !packet.is_empty() {
                        let next_time = current_time_millis() + 120;
                        self.retransmissions.push(ReRun {
                            next_time,
                            command: Command::UnregisterResend(packet, intf.clone()),
                        });
                        timers.push(next_time);
                    }
                }

                for t in timers {
                    self.add_timer(t);
                }

                self.increase_counter(Counter::Unregister, 1);
                UnregisterStatus::OK
            }
        };
        if let Err(e) = resp_s.send(response) {
            debug!("unregister: failed to send response: {}", e);
        }
    }

    fn exec_command_unregister_resend(&mut self, packet: Vec<u8>, intf: Interface) {
        if let Some(sock) = self.intf_socks.get(&intf) {
            debug!("UnregisterResend from {}", &intf.ip());
            multicast_on_intf(&packet[..], &intf, sock);
            self.increase_counter(Counter::UnregisterResend, 1);
        }
    }

    fn exec_command_stop_browse(&mut self, ty_domain: String) {
        match self.service_queriers.remove_entry(&ty_domain) {
            None => debug!("StopBrowse: cannot find querier for {}", &ty_domain),
            Some((ty, sender)) => {
                // Remove pending browse commands in the reruns.
                trace!("StopBrowse: removed queryer for {}", &ty);
                let mut i = 0;
                while i < self.retransmissions.len() {
                    if let Command::Browse(t, _, _) = &self.retransmissions[i].command {
                        if t == &ty {
                            self.retransmissions.remove(i);
                            trace!("StopBrowse: removed retransmission for {}", &ty);
                            continue;
                        }
                    }
                    i += 1;
                }

                // Notify the client.
                match sender.send(ServiceEvent::SearchStopped(ty_domain)) {
                    Ok(()) => trace!("Sent SearchStopped to the listener"),
                    Err(e) => debug!("Failed to send SearchStopped: {}", e),
                }
            }
        }
    }

    fn exec_command_stop_resolve_hostname(&mut self, hostname: String) {
        if let Some((host, (sender, _timeout))) = self.hostname_resolvers.remove_entry(&hostname) {
            // Remove pending resolve commands in the reruns.
            trace!("StopResolve: removed queryer for {}", &host);
            let mut i = 0;
            while i < self.retransmissions.len() {
                if let Command::Resolve(t, _) = &self.retransmissions[i].command {
                    if t == &host {
                        self.retransmissions.remove(i);
                        trace!("StopResolve: removed retransmission for {}", &host);
                        continue;
                    }
                }
                i += 1;
            }

            // Notify the client.
            match sender.send(HostnameResolutionEvent::SearchStopped(hostname)) {
                Ok(()) => trace!("Sent SearchStopped to the listener"),
                Err(e) => debug!("Failed to send SearchStopped: {}", e),
            }
        }
    }

    fn exec_command_register_resend(&mut self, fullname: String, intf: Interface) {
        let Some(info) = self.my_services.get_mut(&fullname) else {
            trace!("announce: cannot find such service {}", &fullname);
            return;
        };

        let Some(dns_registry) = self.dns_registry_map.get_mut(&intf) else {
            return;
        };

        let Some(sock) = self.intf_socks.get(&intf) else {
            return;
        };

        if announce_service_on_intf(dns_registry, info, &intf, sock) {
            let mut hostname = info.get_hostname();
            if let Some(new_name) = dns_registry.name_changes.get(hostname) {
                hostname = new_name;
            }
            let service_name = match dns_registry.name_changes.get(&fullname) {
                Some(new_name) => new_name.to_string(),
                None => fullname,
            };

            debug!("resend: announce service {} on {}", service_name, intf.ip());

            notify_monitors(
                &mut self.monitors,
                DaemonEvent::Announce(service_name, format!("{}:{}", hostname, &intf.ip())),
            );
            info.set_status(&intf, ServiceStatus::Announced);
        } else {
            debug!("register-resend should not fail");
        }

        self.increase_counter(Counter::RegisterResend, 1);
    }

    fn exec_command_verify(&mut self, instance: String, timeout: Duration, repeating: bool) {
        /*
        RFC 6762 section 10.4:
        ...
        When the cache receives this hint that it should reconfirm some
        record, it MUST issue two or more queries for the resource record in
        dispute.  If no response is received within ten seconds, then, even
        though its TTL may indicate that it is not yet due to expire, that
        record SHOULD be promptly flushed from the cache.
        */
        let now = current_time_millis();
        let expire_at = if repeating {
            None
        } else {
            Some(now + timeout.as_millis() as u64)
        };

        // send query for the resource records.
        let record_vec = self.cache.service_verify_queries(&instance, expire_at);

        if !record_vec.is_empty() {
            let query_vec: Vec<(&str, RRType)> = record_vec
                .iter()
                .map(|(record, rr_type)| (record.as_str(), *rr_type))
                .collect();
            self.send_query_vec(&query_vec);

            if let Some(new_expire) = expire_at {
                self.add_timer(new_expire); // ensure a check for the new expire time.

                // schedule a resend 1 second later
                self.add_retransmission(now + 1000, Command::Verify(instance, timeout));
            }
        }
    }

    /// Refresh cached service records with active queriers
    fn refresh_active_services(&mut self) {
        let mut query_ptr_count = 0;
        let mut query_srv_count = 0;
        let mut new_timers = HashSet::new();
        let mut query_addr_count = 0;

        for (ty_domain, _sender) in self.service_queriers.iter() {
            let refreshed_timers = self.cache.refresh_due_ptr(ty_domain);
            if !refreshed_timers.is_empty() {
                trace!("sending refresh query for PTR: {}", ty_domain);
                self.send_query(ty_domain, RRType::PTR);
                query_ptr_count += 1;
                new_timers.extend(refreshed_timers);
            }

            let (instances, timers) = self.cache.refresh_due_srv(ty_domain);
            for instance in instances.iter() {
                trace!("sending refresh query for SRV: {}", instance);
                self.send_query(instance, RRType::SRV);
                query_srv_count += 1;
            }
            new_timers.extend(timers);
            let (hostnames, timers) = self.cache.refresh_due_hosts(ty_domain);
            for hostname in hostnames.iter() {
                trace!("sending refresh queries for A and AAAA:  {}", hostname);
                self.send_query_vec(&[(hostname, RRType::A), (hostname, RRType::AAAA)]);
                query_addr_count += 2;
            }
            new_timers.extend(timers);
        }

        for timer in new_timers {
            self.add_timer(timer);
        }

        self.increase_counter(Counter::CacheRefreshPTR, query_ptr_count);
        self.increase_counter(Counter::CacheRefreshSRV, query_srv_count);
        self.increase_counter(Counter::CacheRefreshAddr, query_addr_count);
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

/// All possible events sent to the client from the daemon
/// regarding host resolution.
#[derive(Debug)]
#[non_exhaustive]
pub enum HostnameResolutionEvent {
    /// Started searching for the ip address of a hostname.
    SearchStarted(String),
    /// One or more addresses for a hostname has been found.
    AddressesFound(String, HashSet<IpAddr>),
    /// One or more addresses for a hostname has been removed.
    AddressesRemoved(String, HashSet<IpAddr>),
    /// The search for the ip address of a hostname has timed out.
    SearchTimeout(String),
    /// Stopped searching for the ip address of a hostname.
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

    /// Daemon detected a new IP address from the host.
    IpAdd(IpAddr),

    /// Daemon detected a IP address removed from the host.
    IpDel(IpAddr),

    /// Daemon resolved a name conflict by changing one of its names.
    /// see [DnsNameChange] for more details.
    NameChange(DnsNameChange),

    /// Send out a multicast response via an IP address.
    Respond(IpAddr),
}

/// Represents a name change due to a name conflict resolution.
/// See [RFC 6762 section 9](https://datatracker.ietf.org/doc/html/rfc6762#section-9)
#[derive(Clone, Debug)]
pub struct DnsNameChange {
    /// The original name set in `ServiceInfo` by the user.
    pub original: String,

    /// A new name is created by appending a suffix after the original name.
    ///
    /// - for a service instance name, the suffix is `(N)`, where N starts at 2.
    /// - for a host name, the suffix is `-N`, where N starts at 2.
    ///
    /// For example:
    ///
    /// - Service name `foo._service-type._udp` becomes `foo (2)._service-type._udp`
    /// - Host name `foo.local.` becomes `foo-2.local.`
    pub new_name: String,

    /// The resource record type
    pub rr_type: RRType,

    /// The interface where the name conflict and its change happened.
    pub intf_name: String,
}

/// Commands supported by the daemon
#[derive(Debug)]
enum Command {
    /// Browsing for a service type (ty_domain, next_time_delay_in_seconds, channel::sender)
    Browse(String, u32, Sender<ServiceEvent>),

    /// Resolve a hostname to IP addresses.
    ResolveHostname(String, u32, Sender<HostnameResolutionEvent>, Option<u64>), // (hostname, next_time_delay_in_seconds, sender, timeout_in_milliseconds)

    /// Register a service
    Register(ServiceInfo),

    /// Unregister a service
    Unregister(String, Sender<UnregisterStatus>), // (fullname)

    /// Announce again a service to local network
    RegisterResend(String, Interface), // (fullname)

    /// Resend unregister packet.
    UnregisterResend(Vec<u8>, Interface), // (packet content)

    /// Stop browsing a service type
    StopBrowse(String), // (ty_domain)

    /// Stop resolving a hostname
    StopResolveHostname(String), // (hostname)

    /// Send query to resolve a service instance.
    /// This is used when a PTR record exists but SRV & TXT records are missing.
    Resolve(String, u16), // (service_instance_fullname, try_count)

    /// Read the current values of the counters
    GetMetrics(Sender<Metrics>),

    /// Get the current status of the daemon.
    GetStatus(Sender<DaemonStatus>),

    /// Monitor noticable events in the daemon.
    Monitor(Sender<DaemonEvent>),

    SetOption(DaemonOption),

    /// Proactively confirm a DNS resource record.
    ///
    /// The intention is to check if a service name or IP address still valid
    /// before its TTL expires.
    Verify(String, Duration),

    Exit(Sender<DaemonStatus>),
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Browse(_, _, _) => write!(f, "Command Browse"),
            Self::ResolveHostname(_, _, _, _) => write!(f, "Command ResolveHostname"),
            Self::Exit(_) => write!(f, "Command Exit"),
            Self::GetStatus(_) => write!(f, "Command GetStatus"),
            Self::GetMetrics(_) => write!(f, "Command GetMetrics"),
            Self::Monitor(_) => write!(f, "Command Monitor"),
            Self::Register(_) => write!(f, "Command Register"),
            Self::RegisterResend(_, _) => write!(f, "Command RegisterResend"),
            Self::SetOption(_) => write!(f, "Command SetOption"),
            Self::StopBrowse(_) => write!(f, "Command StopBrowse"),
            Self::StopResolveHostname(_) => write!(f, "Command StopResolveHostname"),
            Self::Unregister(_, _) => write!(f, "Command Unregister"),
            Self::UnregisterResend(_, _) => write!(f, "Command UnregisterResend"),
            Self::Resolve(_, _) => write!(f, "Command Resolve"),
            Self::Verify(_, _) => write!(f, "Command VerifyResource"),
        }
    }
}

#[derive(Debug)]
enum DaemonOption {
    ServiceNameLenMax(u8),
    EnableInterface(Vec<IfKind>),
    DisableInterface(Vec<IfKind>),
    MulticastLoopV4(bool),
    MulticastLoopV6(bool),
}

/// The length of Service Domain name supported in this lib.
const DOMAIN_LEN: usize = "._tcp.local.".len();

/// Validate the length of "service_name" in a "_<service_name>.<domain_name>." string.
fn check_service_name_length(ty_domain: &str, limit: u8) -> Result<()> {
    if ty_domain.len() <= DOMAIN_LEN + 1 {
        // service name cannot be empty or only '_'.
        return Err(e_fmt!("Service type name cannot be empty: {}", ty_domain));
    }

    let service_name_len = ty_domain.len() - DOMAIN_LEN - 1; // exclude the leading `_`
    if service_name_len > limit as usize {
        return Err(e_fmt!("Service name length must be <= {} bytes", limit));
    }
    Ok(())
}

/// Checks if `name` ends with a valid domain: '._tcp.local.' or '._udp.local.'
fn check_domain_suffix(name: &str) -> Result<()> {
    if !(name.ends_with("._tcp.local.") || name.ends_with("._udp.local.")) {
        return Err(e_fmt!(
            "mDNS service {} must end with '._tcp.local.' or '._udp.local.'",
            name
        ));
    }

    Ok(())
}

/// Validate the service name in a fully qualified name.
///
/// A Full Name = <Instance>.<Service>.<Domain>
/// The only `<Domain>` supported are "._tcp.local." and "._udp.local.".
///
/// Note: this function does not check for the length of the service name.
/// Instead, `register_service` method will check the length.
fn check_service_name(fullname: &str) -> Result<()> {
    check_domain_suffix(fullname)?;

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

/// Validate a hostname.
fn check_hostname(hostname: &str) -> Result<()> {
    if !hostname.ends_with(".local.") {
        return Err(e_fmt!("Hostname must end with '.local.': {hostname}"));
    }

    if hostname == ".local." {
        return Err(e_fmt!(
            "The part of the hostname before '.local.' cannot be empty"
        ));
    }

    if hostname.len() > 255 {
        return Err(e_fmt!("Hostname length must be <= 255 bytes"));
    }

    Ok(())
}

fn call_service_listener(
    listeners_map: &HashMap<String, Sender<ServiceEvent>>,
    ty_domain: &str,
    event: ServiceEvent,
) {
    if let Some(listener) = listeners_map.get(ty_domain) {
        match listener.send(event) {
            Ok(()) => trace!("Sent event to listener successfully"),
            Err(e) => debug!("Failed to send event: {}", e),
        }
    }
}

fn call_hostname_resolution_listener(
    listeners_map: &HashMap<String, (Sender<HostnameResolutionEvent>, Option<u64>)>,
    hostname: &str,
    event: HostnameResolutionEvent,
) {
    if let Some(listener) = listeners_map.get(hostname).map(|(l, _)| l) {
        match listener.send(event) {
            Ok(()) => trace!("Sent event to listener successfully"),
            Err(e) => debug!("Failed to send event: {}", e),
        }
    }
}

/// Returns valid network interfaces in the host system.
/// Loopback interfaces are excluded.
fn my_ip_interfaces() -> Vec<Interface> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .collect()
}

/// Send an outgoing mDNS query or response, and returns the packet bytes.
fn send_dns_outgoing(out: &DnsOutgoing, intf: &Interface, sock: &MioUdpSocket) -> Vec<Vec<u8>> {
    let qtype = if out.is_query() { "query" } else { "response" };
    trace!(
        "send outgoing {}: {} questions {} answers {} authorities {} additional",
        qtype,
        out.questions().len(),
        out.answers_count(),
        out.authorities().len(),
        out.additionals().len()
    );
    let packet_list = out.to_data_on_wire();
    for packet in packet_list.iter() {
        multicast_on_intf(packet, intf, sock);
    }
    packet_list
}

/// Sends a multicast packet, and returns the packet bytes.
fn multicast_on_intf(packet: &[u8], intf: &Interface, socket: &MioUdpSocket) {
    if packet.len() > MAX_MSG_ABSOLUTE {
        debug!("Drop over-sized packet ({})", packet.len());
        return;
    }

    let addr: SocketAddr = match intf.addr {
        if_addrs::IfAddr::V4(_) => SocketAddrV4::new(GROUP_ADDR_V4, MDNS_PORT).into(),
        if_addrs::IfAddr::V6(_) => {
            let mut sock = SocketAddrV6::new(GROUP_ADDR_V6, MDNS_PORT, 0, 0);
            sock.set_scope_id(intf.index.unwrap_or(0)); // Choose iface for multicast
            sock.into()
        }
    };

    send_packet(packet, addr, intf, socket);
}

/// Sends out `packet` to `addr` on the socket in `intf_sock`.
fn send_packet(packet: &[u8], addr: SocketAddr, intf: &Interface, sock: &MioUdpSocket) {
    match sock.send_to(packet, addr) {
        Ok(sz) => trace!("sent out {} bytes on interface {:?}", sz, intf),
        Err(e) => debug!("Failed to send to {} via {:?}: {}", addr, &intf, e),
    }
}

/// Returns true if `name` is a valid instance name of format:
/// <instance>.<service_type>.<_udp|_tcp>.local.
/// Note: <instance> could contain '.' as well.
fn valid_instance_name(name: &str) -> bool {
    name.split('.').count() >= 5
}

fn notify_monitors(monitors: &mut Vec<Sender<DaemonEvent>>, event: DaemonEvent) {
    monitors.retain(|sender| {
        if let Err(e) = sender.try_send(event.clone()) {
            debug!("notify_monitors: try_send: {}", &e);
            if matches!(e, TrySendError::Disconnected(_)) {
                return false; // This monitor is dropped.
            }
        }
        true
    });
}

/// Check if all unique records passed "probing", and if yes, create a packet
/// to announce the service.
fn prepare_announce(
    info: &ServiceInfo,
    intf: &Interface,
    dns_registry: &mut DnsRegistry,
) -> Option<DnsOutgoing> {
    let intf_addrs = info.get_addrs_on_intf(intf);
    if intf_addrs.is_empty() {
        trace!("No valid addrs to add on intf {:?}", &intf);
        return None;
    }

    // check if we changed our name due to conflicts.
    let service_fullname = match dns_registry.name_changes.get(info.get_fullname()) {
        Some(new_name) => new_name,
        None => info.get_fullname(),
    };

    debug!(
        "prepare to announce service {service_fullname} on {}: {}",
        &intf.name,
        &intf.ip()
    );

    let mut probing_count = 0;
    let mut out = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
    let create_time = current_time_millis() + fastrand::u64(0..250);

    out.add_answer_at_time(
        DnsPointer::new(
            info.get_type(),
            RRType::PTR,
            CLASS_IN,
            info.get_other_ttl(),
            service_fullname.to_string(),
        ),
        0,
    );

    if let Some(sub) = info.get_subtype() {
        trace!("Adding subdomain {}", sub);
        out.add_answer_at_time(
            DnsPointer::new(
                sub,
                RRType::PTR,
                CLASS_IN,
                info.get_other_ttl(),
                service_fullname.to_string(),
            ),
            0,
        );
    }

    // SRV records.
    let hostname = match dns_registry.name_changes.get(info.get_hostname()) {
        Some(new_name) => new_name.to_string(),
        None => info.get_hostname().to_string(),
    };

    let mut srv = DnsSrv::new(
        info.get_fullname(),
        CLASS_IN | CLASS_CACHE_FLUSH,
        info.get_host_ttl(),
        info.get_priority(),
        info.get_weight(),
        info.get_port(),
        hostname,
    );

    if let Some(new_name) = dns_registry.name_changes.get(info.get_fullname()) {
        srv.get_record_mut().set_new_name(new_name.to_string());
    }

    if !info.requires_probe()
        || dns_registry.is_probing_done(&srv, info.get_fullname(), create_time)
    {
        out.add_answer_at_time(srv, 0);
    } else {
        probing_count += 1;
    }

    // TXT records.

    let mut txt = DnsTxt::new(
        info.get_fullname(),
        CLASS_IN | CLASS_CACHE_FLUSH,
        info.get_other_ttl(),
        info.generate_txt(),
    );

    if let Some(new_name) = dns_registry.name_changes.get(info.get_fullname()) {
        txt.get_record_mut().set_new_name(new_name.to_string());
    }

    if !info.requires_probe()
        || dns_registry.is_probing_done(&txt, info.get_fullname(), create_time)
    {
        out.add_answer_at_time(txt, 0);
    } else {
        probing_count += 1;
    }

    // Address records. (A and AAAA)

    let hostname = info.get_hostname();
    for address in intf_addrs {
        let mut dns_addr = DnsAddress::new(
            hostname,
            ip_address_rr_type(&address),
            CLASS_IN | CLASS_CACHE_FLUSH,
            info.get_host_ttl(),
            address,
        );

        if let Some(new_name) = dns_registry.name_changes.get(hostname) {
            dns_addr.get_record_mut().set_new_name(new_name.to_string());
        }

        if !info.requires_probe()
            || dns_registry.is_probing_done(&dns_addr, info.get_fullname(), create_time)
        {
            out.add_answer_at_time(dns_addr, 0);
        } else {
            probing_count += 1;
        }
    }

    if probing_count > 0 {
        return None;
    }

    Some(out)
}

/// Send an unsolicited response for owned service via `intf` and `sock`.
/// Returns true if sent out successfully.
fn announce_service_on_intf(
    dns_registry: &mut DnsRegistry,
    info: &ServiceInfo,
    intf: &Interface,
    sock: &MioUdpSocket,
) -> bool {
    if let Some(out) = prepare_announce(info, intf, dns_registry) {
        send_dns_outgoing(&out, intf, sock);
        return true;
    }
    false
}

/// Returns a new name based on the `original` to avoid conflicts.
/// If the name already contains a number in parentheses, increments that number.
///
/// Examples:
/// - `foo.local.` becomes `foo (2).local.`
/// - `foo (2).local.` becomes `foo (3).local.`
/// - `foo (9)` becomes `foo (10)`
fn name_change(original: &str) -> String {
    let mut parts: Vec<_> = original.split('.').collect();
    let Some(first_part) = parts.get_mut(0) else {
        return format!("{original} (2)");
    };

    let mut new_name = format!("{} (2)", first_part);

    // check if there is already has `(<num>)` suffix.
    if let Some(paren_pos) = first_part.rfind(" (") {
        // Check if there's a closing parenthesis
        if let Some(end_paren) = first_part[paren_pos..].find(')') {
            let absolute_end_pos = paren_pos + end_paren;
            // Only process if the closing parenthesis is the last character
            if absolute_end_pos == first_part.len() - 1 {
                let num_start = paren_pos + 2; // Skip " ("
                                               // Try to parse the number between parentheses
                if let Ok(number) = first_part[num_start..absolute_end_pos].parse::<u32>() {
                    let base_name = &first_part[..paren_pos];
                    new_name = format!("{} ({})", base_name, number + 1)
                }
            }
        }
    }

    *first_part = &new_name;
    parts.join(".")
}

/// Returns a new name based on the `original` to avoid conflicts.
/// If the name already contains a hyphenated number, increments that number.
///
/// Examples:
/// - `foo.local.` becomes `foo-2.local.`
/// - `foo-2.local.` becomes `foo-3.local.`
/// - `foo` becomes `foo-2`
fn hostname_change(original: &str) -> String {
    let mut parts: Vec<_> = original.split('.').collect();
    let Some(first_part) = parts.get_mut(0) else {
        return format!("{original}-2");
    };

    let mut new_name = format!("{}-2", first_part);

    // check if there is already a `-<num>` suffix
    if let Some(hyphen_pos) = first_part.rfind('-') {
        // Try to parse everything after the hyphen as a number
        if let Ok(number) = first_part[hyphen_pos + 1..].parse::<u32>() {
            let base_name = &first_part[..hyphen_pos];
            new_name = format!("{}-{}", base_name, number + 1);
        }
    }

    *first_part = &new_name;
    parts.join(".")
}

fn add_answer_with_additionals(
    out: &mut DnsOutgoing,
    msg: &DnsIncoming,
    service: &ServiceInfo,
    intf: &Interface,
    dns_registry: &DnsRegistry,
) {
    let intf_addrs = service.get_addrs_on_intf(intf);
    if intf_addrs.is_empty() {
        trace!("No addrs on LAN of intf {:?}", intf);
        return;
    }

    // check if we changed our name due to conflicts.
    let service_fullname = match dns_registry.name_changes.get(service.get_fullname()) {
        Some(new_name) => new_name,
        None => service.get_fullname(),
    };

    let hostname = match dns_registry.name_changes.get(service.get_hostname()) {
        Some(new_name) => new_name,
        None => service.get_hostname(),
    };

    let ptr_added = out.add_answer(
        msg,
        DnsPointer::new(
            service.get_type(),
            RRType::PTR,
            CLASS_IN,
            service.get_other_ttl(),
            service_fullname.to_string(),
        ),
    );

    if !ptr_added {
        trace!("answer was not added for msg {:?}", msg);
        return;
    }

    if let Some(sub) = service.get_subtype() {
        trace!("Adding subdomain {}", sub);
        out.add_additional_answer(DnsPointer::new(
            sub,
            RRType::PTR,
            CLASS_IN,
            service.get_other_ttl(),
            service_fullname.to_string(),
        ));
    }

    // Add recommended additional answers according to
    // https://tools.ietf.org/html/rfc6763#section-12.1.
    out.add_additional_answer(DnsSrv::new(
        service_fullname,
        CLASS_IN | CLASS_CACHE_FLUSH,
        service.get_host_ttl(),
        service.get_priority(),
        service.get_weight(),
        service.get_port(),
        hostname.to_string(),
    ));

    out.add_additional_answer(DnsTxt::new(
        service_fullname,
        CLASS_IN | CLASS_CACHE_FLUSH,
        service.get_host_ttl(),
        service.generate_txt(),
    ));

    for address in intf_addrs {
        out.add_additional_answer(DnsAddress::new(
            hostname,
            ip_address_rr_type(&address),
            CLASS_IN | CLASS_CACHE_FLUSH,
            service.get_host_ttl(),
            address,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        check_domain_suffix, check_service_name_length, hostname_change, my_ip_interfaces,
        name_change, new_socket_bind, send_dns_outgoing, valid_instance_name,
        HostnameResolutionEvent, ServiceDaemon, ServiceEvent, ServiceInfo, GROUP_ADDR_V4,
        MDNS_PORT,
    };
    use crate::{
        dns_parser::{DnsOutgoing, DnsPointer, RRType, CLASS_IN, FLAGS_AA, FLAGS_QR_RESPONSE},
        service_daemon::check_hostname,
    };
    use std::{
        net::{SocketAddr, SocketAddrV4},
        time::Duration,
    };
    use test_log::test;

    #[test]
    fn test_socketaddr_print() {
        let addr: SocketAddr = SocketAddrV4::new(GROUP_ADDR_V4, MDNS_PORT).into();
        let print = format!("{}", addr);
        assert_eq!(print, "224.0.0.251:5353");
    }

    #[test]
    fn test_instance_name() {
        assert!(valid_instance_name("my-laser._printer._tcp.local."));
        assert!(valid_instance_name("my-laser.._printer._tcp.local."));
        assert!(!valid_instance_name("_printer._tcp.local."));
    }

    #[test]
    fn test_check_service_name_length() {
        let result = check_service_name_length("_tcp", 100);
        assert!(result.is_err());
        if let Err(e) = result {
            println!("{}", e);
        }
    }

    #[test]
    fn test_check_hostname() {
        // valid hostnames
        for hostname in &[
            "my_host.local.",
            &("A".repeat(255 - ".local.".len()) + ".local."),
        ] {
            let result = check_hostname(hostname);
            assert!(result.is_ok());
        }

        // erroneous hostnames
        for hostname in &[
            "my_host.local",
            ".local.",
            &("A".repeat(256 - ".local.".len()) + ".local."),
        ] {
            let result = check_hostname(hostname);
            assert!(result.is_err());
            if let Err(e) = result {
                println!("{}", e);
            }
        }
    }

    #[test]
    fn test_check_domain_suffix() {
        assert!(check_domain_suffix("_missing_dot._tcp.local").is_err());
        assert!(check_domain_suffix("_missing_bar.tcp.local.").is_err());
        assert!(check_domain_suffix("_mis_spell._tpp.local.").is_err());
        assert!(check_domain_suffix("_mis_spell._upp.local.").is_err());
        assert!(check_domain_suffix("_has_dot._tcp.local.").is_ok());
        assert!(check_domain_suffix("_goodname._udp.local.").is_ok());
    }

    #[test]
    fn test_service_with_temporarily_invalidated_ptr() {
        // Create a daemon
        let d = ServiceDaemon::new().expect("Failed to create daemon");

        let service = "_test_inval_ptr._udp.local.";
        let host_name = "my_host_tmp_invalidated_ptr.local.";
        let intfs: Vec<_> = my_ip_interfaces();
        let intf_ips: Vec<_> = intfs.iter().map(|intf| intf.ip()).collect();
        let port = 5201;
        let my_service =
            ServiceInfo::new(service, "my_instance", host_name, &intf_ips[..], port, None)
                .expect("invalid service info")
                .enable_addr_auto();
        let result = d.register(my_service.clone());
        assert!(result.is_ok());

        // Browse for a service
        let browse_chan = d.browse(service).unwrap();
        let timeout = Duration::from_secs(2);
        let mut resolved = false;

        while let Ok(event) = browse_chan.recv_timeout(timeout) {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    resolved = true;
                    println!("Resolved a service of {}", &info.get_fullname());
                    break;
                }
                e => {
                    println!("Received event {:?}", e);
                }
            }
        }

        assert!(resolved);

        println!("Stopping browse of {}", service);
        // Pause browsing so restarting will cause a new immediate query.
        // Unregistering will not work here, it will invalidate all the records.
        d.stop_browse(service).unwrap();

        // Ensure the search is stopped.
        // Reduces the chance of receiving an answer adding the ptr back to the
        // cache causing the later browse to return directly from the cache.
        // (which invalidates what this test is trying to test for.)
        let mut stopped = false;
        while let Ok(event) = browse_chan.recv_timeout(timeout) {
            match event {
                ServiceEvent::SearchStopped(_) => {
                    stopped = true;
                    println!("Stopped browsing service");
                    break;
                }
                // Other `ServiceResolved` messages may be received
                // here as they come from different interfaces.
                // That's fine for this test.
                e => {
                    println!("Received event {:?}", e);
                }
            }
        }

        assert!(stopped);

        // Invalidate the ptr from the service to the host.
        let invalidate_ptr_packet = DnsPointer::new(
            my_service.get_type(),
            RRType::PTR,
            CLASS_IN,
            0,
            my_service.get_fullname().to_string(),
        );

        let mut packet_buffer = DnsOutgoing::new(FLAGS_QR_RESPONSE | FLAGS_AA);
        packet_buffer.add_additional_answer(invalidate_ptr_packet);

        for intf in intfs {
            let sock = new_socket_bind(&intf, true).unwrap();
            send_dns_outgoing(&packet_buffer, &intf, &sock);
        }

        println!(
            "Sent PTR record invalidation. Starting second browse for {}",
            service
        );

        // Restart the browse to force the sender to re-send the announcements.
        let browse_chan = d.browse(service).unwrap();

        resolved = false;
        while let Ok(event) = browse_chan.recv_timeout(timeout) {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    resolved = true;
                    println!("Resolved a service of {}", &info.get_fullname());
                    break;
                }
                e => {
                    println!("Received event {:?}", e);
                }
            }
        }

        assert!(resolved);
        d.shutdown().unwrap();
    }

    #[test]
    fn test_expired_srv() {
        // construct service info
        let service_type = "_expired-srv._udp.local.";
        let instance = "test_instance";
        let host_name = "expired_srv_host.local.";
        let mut my_service = ServiceInfo::new(service_type, instance, host_name, "", 5023, None)
            .unwrap()
            .enable_addr_auto();
        // let fullname = my_service.get_fullname().to_string();

        // set SRV to expire soon.
        let new_ttl = 3; // for testing only.
        my_service._set_host_ttl(new_ttl);

        // register my service
        let mdns_server = ServiceDaemon::new().expect("Failed to create mdns server");
        let result = mdns_server.register(my_service);
        assert!(result.is_ok());

        let mdns_client = ServiceDaemon::new().expect("Failed to create mdns client");
        let browse_chan = mdns_client.browse(service_type).unwrap();
        let timeout = Duration::from_secs(2);
        let mut resolved = false;

        while let Ok(event) = browse_chan.recv_timeout(timeout) {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    resolved = true;
                    println!("Resolved a service of {}", &info.get_fullname());
                    break;
                }
                _ => {}
            }
        }

        assert!(resolved);

        // Exit the server so that no more responses.
        mdns_server.shutdown().unwrap();

        // SRV record in the client cache will expire.
        let expire_timeout = Duration::from_secs(new_ttl as u64);
        while let Ok(event) = browse_chan.recv_timeout(expire_timeout) {
            match event {
                ServiceEvent::ServiceRemoved(service_type, full_name) => {
                    println!("Service removed: {}: {}", &service_type, &full_name);
                    break;
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_hostname_resolution_address_removed() {
        // Create a mDNS server
        let server = ServiceDaemon::new().expect("Failed to create server");
        let hostname = "addr_remove_host._tcp.local.";
        let service_ip_addr = my_ip_interfaces()
            .iter()
            .find(|iface| iface.ip().is_ipv4())
            .map(|iface| iface.ip())
            .unwrap();

        let mut my_service = ServiceInfo::new(
            "_host_res_test._tcp.local.",
            "my_instance",
            hostname,
            &service_ip_addr,
            1234,
            None,
        )
        .expect("invalid service info");

        // Set a short TTL for addresses for testing.
        let addr_ttl = 2;
        my_service._set_host_ttl(addr_ttl); // Expire soon

        server.register(my_service).unwrap();

        // Create a mDNS client for resolving the hostname.
        let client = ServiceDaemon::new().expect("Failed to create client");
        let event_receiver = client.resolve_hostname(hostname, None).unwrap();
        let resolved = loop {
            match event_receiver.recv() {
                Ok(HostnameResolutionEvent::AddressesFound(found_hostname, addresses)) => {
                    assert!(found_hostname == hostname);
                    assert!(addresses.contains(&service_ip_addr));
                    println!("address found: {:?}", &addresses);
                    break true;
                }
                Ok(HostnameResolutionEvent::SearchStopped(_)) => break false,
                Ok(_event) => {}
                Err(_) => break false,
            }
        };

        assert!(resolved);

        // Shutdown the server so no more responses / refreshes for addresses.
        server.shutdown().unwrap();

        // Wait till hostname address record expires, with 1 second grace period.
        let timeout = Duration::from_secs(addr_ttl as u64 + 1);
        let removed = loop {
            match event_receiver.recv_timeout(timeout) {
                Ok(HostnameResolutionEvent::AddressesRemoved(removed_host, addresses)) => {
                    assert!(removed_host == hostname);
                    assert!(addresses.contains(&service_ip_addr));

                    println!(
                        "address removed: hostname: {} addresses: {:?}",
                        &hostname, &addresses
                    );
                    break true;
                }
                Ok(_event) => {}
                Err(_) => {
                    break false;
                }
            }
        };

        assert!(removed);

        client.shutdown().unwrap();
    }

    #[test]
    fn test_refresh_ptr() {
        // construct service info
        let service_type = "_refresh-ptr._udp.local.";
        let instance = "test_instance";
        let host_name = "refresh_ptr_host.local.";
        let service_ip_addr = my_ip_interfaces()
            .iter()
            .find(|iface| iface.ip().is_ipv4())
            .map(|iface| iface.ip())
            .unwrap();

        let mut my_service = ServiceInfo::new(
            service_type,
            instance,
            host_name,
            &service_ip_addr,
            5023,
            None,
        )
        .unwrap();

        let new_ttl = 3; // for testing only.
        my_service._set_other_ttl(new_ttl);

        // register my service
        let mdns_server = ServiceDaemon::new().expect("Failed to create mdns server");
        let result = mdns_server.register(my_service);
        assert!(result.is_ok());

        let mdns_client = ServiceDaemon::new().expect("Failed to create mdns client");
        let browse_chan = mdns_client.browse(service_type).unwrap();
        let timeout = Duration::from_millis(1500); // Give at least 1 second for the service probing.
        let mut resolved = false;

        // resolve the service first.
        while let Ok(event) = browse_chan.recv_timeout(timeout) {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    resolved = true;
                    println!("Resolved a service of {}", &info.get_fullname());
                    break;
                }
                _ => {}
            }
        }

        assert!(resolved);

        // wait over 80% of TTL, and refresh PTR should be sent out.
        let timeout = Duration::from_millis(new_ttl as u64 * 1000 * 90 / 100);
        while let Ok(event) = browse_chan.recv_timeout(timeout) {
            println!("event: {:?}", &event);
        }

        // verify refresh counter.
        let metrics_chan = mdns_client.get_metrics().unwrap();
        let metrics = metrics_chan.recv_timeout(timeout).unwrap();
        let refresh_counter = metrics["cache-refresh-ptr"];
        assert_eq!(refresh_counter, 1);

        // Exit the server so that no more responses.
        mdns_server.shutdown().unwrap();
        mdns_client.shutdown().unwrap();
    }

    #[test]
    fn test_name_change() {
        assert_eq!(name_change("foo.local."), "foo (2).local.");
        assert_eq!(name_change("foo (2).local."), "foo (3).local.");
        assert_eq!(name_change("foo (9).local."), "foo (10).local.");
        assert_eq!(name_change("foo"), "foo (2)");
        assert_eq!(name_change("foo (2)"), "foo (3)");
        assert_eq!(name_change(""), " (2)");

        // Additional edge cases
        assert_eq!(name_change("foo (abc)"), "foo (abc) (2)"); // Invalid number
        assert_eq!(name_change("foo (2"), "foo (2 (2)"); // Missing closing parenthesis
        assert_eq!(name_change("foo (2) extra"), "foo (2) extra (2)"); // Extra text after number
    }

    #[test]
    fn test_hostname_change() {
        assert_eq!(hostname_change("foo.local."), "foo-2.local.");
        assert_eq!(hostname_change("foo"), "foo-2");
        assert_eq!(hostname_change("foo-2.local."), "foo-3.local.");
        assert_eq!(hostname_change("foo-9"), "foo-10");
        assert_eq!(hostname_change("test-42.domain."), "test-43.domain.");
    }
}
