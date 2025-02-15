//! Define `ServiceInfo` to represent a service and its operations.

#[cfg(feature = "logging")]
use crate::log::debug;
use crate::{
    dns_parser::{DnsRecordBox, DnsRecordExt, DnsSrv, RRType},
    Error, Result,
};
use if_addrs::{IfAddr, Interface};
use std::{
    cmp,
    collections::{HashMap, HashSet},
    convert::TryInto,
    fmt,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

/// Default TTL values in seconds
const DNS_HOST_TTL: u32 = 120; // 2 minutes for host records (A, SRV etc) per RFC6762
const DNS_OTHER_TTL: u32 = 4500; // 75 minutes for non-host records (PTR, TXT etc) per RFC6762

/// Complete info about a Service Instance.
///
/// We can construct some PTR, one SRV and one TXT record from this info,
/// as well as A (IPv4 Address) and AAAA (IPv6 Address) records.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    ty_domain: String, // <service>.<domain>

    /// See RFC6763 section 7.1 about "Subtypes":
    /// <https://datatracker.ietf.org/doc/html/rfc6763#section-7.1>
    sub_domain: Option<String>, // <subservice>._sub.<service>.<domain>

    fullname: String, // <instance>.<service>.<domain>
    server: String,   // fully qualified name for service host
    addresses: HashSet<IpAddr>,
    port: u16,
    host_ttl: u32,  // used for SRV and Address records
    other_ttl: u32, // used for PTR and TXT records
    priority: u16,
    weight: u16,
    txt_properties: TxtProperties,
    addr_auto: bool, // Let the system update addresses automatically.

    status: HashMap<Interface, ServiceStatus>,

    /// Whether we need to probe names before announcing this service.
    requires_probe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServiceStatus {
    Probing,
    Announced,
    Unknown,
}

impl ServiceInfo {
    /// Creates a new service info.
    ///
    /// `ty_domain` is the service type and the domain label, for example
    /// "_my-service._udp.local.".
    ///
    /// `my_name` is the instance name, without the service type suffix.
    ///
    /// `host_name` is the "host" in the context of DNS. It is used as the "name"
    /// in the address records (i.e. TYPE_A and TYPE_AAAA records). It means that
    /// for the same hostname in the same local network, the service resolves in
    /// the same addresses. Be sure to check it if you see unexpected addresses resolved.
    ///
    /// `properties` can be `None` or key/value string pairs, in a type that
    /// implements [`IntoTxtProperties`] trait. It supports:
    /// - `HashMap<String, String>`
    /// - `Option<HashMap<String, String>>`
    /// - slice of tuple: `&[(K, V)]` where `K` and `V` are [`std::string::ToString`].
    ///
    /// Note: The maximum length of a single property string is `255`, Property that exceed the length are truncated.
    /// > `len(key + value) < u8::MAX`
    ///
    /// `ip` can be one or more IP addresses, in a type that implements
    /// [`AsIpAddrs`] trait. It supports:
    ///
    /// - Single IPv4: `"192.168.0.1"`
    /// - Single IPv6: `"2001:0db8::7334"`
    /// - Multiple IPv4 separated by comma: `"192.168.0.1,192.168.0.2"`
    /// - Multiple IPv6 separated by comma: `"2001:0db8::7334,2001:0db8::7335"`
    /// - A slice of IPv4: `&["192.168.0.1", "192.168.0.2"]`
    /// - A slice of IPv6: `&["2001:0db8::7334", "2001:0db8::7335"]`
    /// - A mix of IPv4 and IPv6: `"192.168.0.1,2001:0db8::7334"`
    /// - All the above formats with [IpAddr] or `String` instead of `&str`.
    ///
    /// The host TTL and other TTL are set to default values.
    pub fn new<Ip: AsIpAddrs, P: IntoTxtProperties>(
        ty_domain: &str,
        my_name: &str,
        host_name: &str,
        ip: Ip,
        port: u16,
        properties: P,
    ) -> Result<Self> {
        let (ty_domain, sub_domain) = split_sub_domain(ty_domain);

        let fullname = format!("{}.{}", my_name, ty_domain);
        let ty_domain = ty_domain.to_string();
        let sub_domain = sub_domain.map(str::to_string);
        let server = normalize_hostname(host_name.to_string());
        let addresses = ip.as_ip_addrs()?;
        let txt_properties = properties.into_txt_properties();

        // RFC6763 section 6.4: https://www.rfc-editor.org/rfc/rfc6763#section-6.4
        // The characters of a key MUST be printable US-ASCII values (0x20-0x7E)
        // [RFC20], excluding '=' (0x3D).
        for prop in txt_properties.iter() {
            let key = prop.key();
            if !key.is_ascii() {
                return Err(Error::Msg(format!(
                    "TXT property key {} is not ASCII",
                    prop.key()
                )));
            }
            if key.contains('=') {
                return Err(Error::Msg(format!(
                    "TXT property key {} contains '='",
                    prop.key()
                )));
            }
        }

        let this = Self {
            ty_domain,
            sub_domain,
            fullname,
            server,
            addresses,
            port,
            host_ttl: DNS_HOST_TTL,
            other_ttl: DNS_OTHER_TTL,
            priority: 0,
            weight: 0,
            txt_properties,
            addr_auto: false,
            status: HashMap::new(),
            requires_probe: true,
        };

        Ok(this)
    }

    /// Indicates that the library should automatically
    /// update the addresses of this service, when IP
    /// address(es) are added or removed on the host.
    pub const fn enable_addr_auto(mut self) -> Self {
        self.addr_auto = true;
        self
    }

    /// Returns if the service's addresses will be updated
    /// automatically when the host IP addrs change.
    pub const fn is_addr_auto(&self) -> bool {
        self.addr_auto
    }

    /// Set whether this service info requires name probing for potential name conflicts.
    ///
    /// By default, it is true (i.e. requires probing) for every service info. You
    /// set it to `false` only when you are sure there are no conflicts, or for testing purposes.
    pub fn set_requires_probe(&mut self, enable: bool) {
        self.requires_probe = enable;
    }

    /// Returns whether this service info requires name probing for potential name conflicts.
    ///
    /// By default, it returns true for every service info.
    pub const fn requires_probe(&self) -> bool {
        self.requires_probe
    }

    /// Returns the service type including the domain label.
    ///
    /// For example: "_my-service._udp.local.".
    #[inline]
    pub fn get_type(&self) -> &str {
        &self.ty_domain
    }

    /// Returns the service subtype including the domain label,
    /// if subtype has been defined.
    ///
    /// For example: "_printer._sub._http._tcp.local.".
    #[inline]
    pub const fn get_subtype(&self) -> &Option<String> {
        &self.sub_domain
    }

    /// Returns a reference of the service fullname.
    ///
    /// This is useful, for example, in unregister.
    #[inline]
    pub fn get_fullname(&self) -> &str {
        &self.fullname
    }

    /// Returns the properties from TXT records.
    #[inline]
    pub const fn get_properties(&self) -> &TxtProperties {
        &self.txt_properties
    }

    /// Returns a property for a given `key`, where `key` is
    /// case insensitive.
    ///
    /// Returns `None` if `key` does not exist.
    pub fn get_property(&self, key: &str) -> Option<&TxtProperty> {
        self.txt_properties.get(key)
    }

    /// Returns a property value for a given `key`, where `key` is
    /// case insensitive.
    ///
    /// Returns `None` if `key` does not exist.
    pub fn get_property_val(&self, key: &str) -> Option<Option<&[u8]>> {
        self.txt_properties.get_property_val(key)
    }

    /// Returns a property value string for a given `key`, where `key` is
    /// case insensitive.
    ///
    /// Returns `None` if `key` does not exist.
    pub fn get_property_val_str(&self, key: &str) -> Option<&str> {
        self.txt_properties.get_property_val_str(key)
    }

    /// Returns the service's hostname.
    #[inline]
    pub fn get_hostname(&self) -> &str {
        &self.server
    }

    /// Returns the service's port.
    #[inline]
    pub const fn get_port(&self) -> u16 {
        self.port
    }

    /// Returns the service's addresses
    #[inline]
    pub const fn get_addresses(&self) -> &HashSet<IpAddr> {
        &self.addresses
    }

    /// Returns the service's IPv4 addresses only.
    pub fn get_addresses_v4(&self) -> HashSet<&Ipv4Addr> {
        let mut ipv4_addresses = HashSet::new();

        for ip in &self.addresses {
            if let IpAddr::V4(ipv4) = ip {
                ipv4_addresses.insert(ipv4);
            }
        }

        ipv4_addresses
    }

    /// Returns the service's TTL used for SRV and Address records.
    #[inline]
    pub const fn get_host_ttl(&self) -> u32 {
        self.host_ttl
    }

    /// Returns the service's TTL used for PTR and TXT records.
    #[inline]
    pub const fn get_other_ttl(&self) -> u32 {
        self.other_ttl
    }

    /// Returns the service's priority used in SRV records.
    #[inline]
    pub const fn get_priority(&self) -> u16 {
        self.priority
    }

    /// Returns the service's weight used in SRV records.
    #[inline]
    pub const fn get_weight(&self) -> u16 {
        self.weight
    }

    /// Returns a list of addresses that are in the same LAN as
    /// the interface `intf`.
    pub(crate) fn get_addrs_on_intf(&self, intf: &Interface) -> Vec<IpAddr> {
        self.addresses
            .iter()
            // Allow loopback addresses to support registering services on loopback interfaces,
            // which is required by some use cases (e.g., OSCQuery) that publish via mDNS.
            .filter(|a| (a.is_loopback() || valid_ip_on_intf(a, intf)))
            .copied()
            .collect()
    }

    /// Returns whether the service info is ready to be resolved.
    pub(crate) fn is_ready(&self) -> bool {
        let some_missing = self.ty_domain.is_empty()
            || self.fullname.is_empty()
            || self.server.is_empty()
            || self.addresses.is_empty();
        !some_missing
    }

    /// Insert `addr` into service info addresses.
    pub(crate) fn insert_ipaddr(&mut self, addr: IpAddr) {
        self.addresses.insert(addr);
    }

    pub(crate) fn remove_ipaddr(&mut self, addr: &IpAddr) {
        self.addresses.remove(addr);
    }

    pub(crate) fn generate_txt(&self) -> Vec<u8> {
        encode_txt(self.get_properties().iter())
    }

    pub(crate) fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    pub(crate) fn set_hostname(&mut self, hostname: String) {
        self.server = normalize_hostname(hostname);
    }

    /// Returns true if properties are updated.
    pub(crate) fn set_properties_from_txt(&mut self, txt: &[u8]) -> bool {
        let properties = decode_txt_unique(txt);
        if self.txt_properties.properties != properties {
            self.txt_properties = TxtProperties { properties };
            true
        } else {
            false
        }
    }

    pub(crate) fn set_subtype(&mut self, subtype: String) {
        self.sub_domain = Some(subtype);
    }

    /// host_ttl is for SRV and address records
    /// currently only used for testing.
    pub(crate) fn _set_host_ttl(&mut self, ttl: u32) {
        self.host_ttl = ttl;
    }

    /// other_ttl is for PTR and TXT records.
    pub(crate) fn _set_other_ttl(&mut self, ttl: u32) {
        self.other_ttl = ttl;
    }

    pub(crate) fn set_status(&mut self, intf: &Interface, status: ServiceStatus) {
        match self.status.get_mut(intf) {
            Some(service_status) => {
                *service_status = status;
            }
            None => {
                self.status.entry(intf.clone()).or_insert(status);
            }
        }
    }

    pub(crate) fn get_status(&self, intf: &Interface) -> ServiceStatus {
        self.status
            .get(intf)
            .cloned()
            .unwrap_or(ServiceStatus::Unknown)
    }

    /// Consumes self and returns a resolved service, i.e. a lite version of `ServiceInfo`.
    pub fn as_resolved_service(self) -> ResolvedService {
        ResolvedService {
            ty_domain: self.ty_domain,
            sub_ty_domain: self.sub_domain,
            fullname: self.fullname,
            host: self.server,
            port: self.port,
            addresses: self.addresses,
            txt_properties: self.txt_properties,
        }
    }
}

/// Removes potentially duplicated ".local." at the end of "hostname".
fn normalize_hostname(mut hostname: String) -> String {
    if hostname.ends_with(".local.local.") {
        let new_len = hostname.len() - "local.".len();
        hostname.truncate(new_len);
    }
    hostname
}

/// This trait allows for parsing an input into a set of one or multiple [`Ipv4Addr`].
pub trait AsIpAddrs {
    fn as_ip_addrs(&self) -> Result<HashSet<IpAddr>>;
}

impl<T: AsIpAddrs> AsIpAddrs for &T {
    fn as_ip_addrs(&self) -> Result<HashSet<IpAddr>> {
        (*self).as_ip_addrs()
    }
}

/// Supports one address or multiple addresses separated by `,`.
/// For example: "127.0.0.1,127.0.0.2".
///
/// If the string is empty, will return an empty set.
impl AsIpAddrs for &str {
    fn as_ip_addrs(&self) -> Result<HashSet<IpAddr>> {
        let mut addrs = HashSet::new();

        if !self.is_empty() {
            let iter = self.split(',').map(str::trim).map(IpAddr::from_str);
            for addr in iter {
                let addr = addr.map_err(|err| Error::ParseIpAddr(err.to_string()))?;
                addrs.insert(addr);
            }
        }

        Ok(addrs)
    }
}

impl AsIpAddrs for String {
    fn as_ip_addrs(&self) -> Result<HashSet<IpAddr>> {
        self.as_str().as_ip_addrs()
    }
}

/// Support slice. Example: &["127.0.0.1", "127.0.0.2"]
impl<I: AsIpAddrs> AsIpAddrs for &[I] {
    fn as_ip_addrs(&self) -> Result<HashSet<IpAddr>> {
        let mut addrs = HashSet::new();

        for result in self.iter().map(I::as_ip_addrs) {
            addrs.extend(result?);
        }

        Ok(addrs)
    }
}

/// Optimization for zero sized/empty values, as `()` will never take up any space or evaluate to
/// anything, helpful in contexts where we just want an empty value.
impl AsIpAddrs for () {
    fn as_ip_addrs(&self) -> Result<HashSet<IpAddr>> {
        Ok(HashSet::new())
    }
}

impl AsIpAddrs for std::net::IpAddr {
    fn as_ip_addrs(&self) -> Result<HashSet<IpAddr>> {
        let mut ips = HashSet::new();
        ips.insert(*self);

        Ok(ips)
    }
}

/// Represents properties in a TXT record.
///
/// The key string of a property is case insensitive, and only
/// one [`TxtProperty`] is stored for the same key.
///
/// [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763#section-6.4):
/// "A given key SHOULD NOT appear more than once in a TXT record."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtProperties {
    // Use `Vec` instead of `HashMap` to keep the order of insertions.
    properties: Vec<TxtProperty>,
}

impl TxtProperties {
    /// Returns an iterator for all properties.
    pub fn iter(&self) -> impl Iterator<Item = &TxtProperty> {
        self.properties.iter()
    }

    /// Returns the number of properties.
    pub fn len(&self) -> usize {
        self.properties.len()
    }

    /// Returns if the properties are empty.
    pub fn is_empty(&self) -> bool {
        self.properties.is_empty()
    }

    /// Returns a property for a given `key`, where `key` is
    /// case insensitive.
    pub fn get(&self, key: &str) -> Option<&TxtProperty> {
        let key = key.to_lowercase();
        self.properties
            .iter()
            .find(|&prop| prop.key.to_lowercase() == key)
    }

    /// Returns a property value for a given `key`, where `key` is
    /// case insensitive.
    ///
    /// Returns `None` if `key` does not exist.
    /// Returns `Some(Option<&u8>)` for its value.
    pub fn get_property_val(&self, key: &str) -> Option<Option<&[u8]>> {
        self.get(key).map(|x| x.val())
    }

    /// Returns a property value string for a given `key`, where `key` is
    /// case insensitive.
    ///
    /// Returns `None` if `key` does not exist.
    /// Returns `Some("")` if its value is `None` or is empty.
    pub fn get_property_val_str(&self, key: &str) -> Option<&str> {
        self.get(key).map(|x| x.val_str())
    }

    /// Consumes properties and returns a hashmap, where the keys are the properties keys.
    ///
    /// If a property value is empty, return an empty string (because RFC 6763 allows empty values).
    /// If a property value is non-empty but not valid UTF-8, skip the property and log a message.
    pub fn into_property_map_str(self) -> HashMap<String, String> {
        self.properties
            .into_iter()
            .filter_map(|property| {
                let val_string = property.val.map_or(Some(String::new()), |val| {
                    String::from_utf8(val)
                        .map_err(|e| {
                            debug!("Property value contains invalid UTF-8: {e}");
                        })
                        .ok()
                })?;
                Some((property.key, val_string))
            })
            .collect()
    }
}

impl fmt::Display for TxtProperties {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let delimiter = ", ";
        let props: Vec<String> = self.properties.iter().map(|p| p.to_string()).collect();
        write!(f, "({})", props.join(delimiter))
    }
}

/// Represents a property in a TXT record.
#[derive(Clone, PartialEq, Eq)]
pub struct TxtProperty {
    /// The name of the property. The original cases are kept.
    key: String,

    /// RFC 6763 says values are bytes, not necessarily UTF-8.
    /// It is also possible that there is no value, in which case
    /// the key is a boolean key.
    val: Option<Vec<u8>>,
}

impl TxtProperty {
    /// Returns the key of a property.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the value of a property, which could be `None`.
    ///
    /// To obtain a `&str` of the value, use `val_str()` instead.
    pub fn val(&self) -> Option<&[u8]> {
        self.val.as_deref()
    }

    /// Returns the value of a property as str.
    pub fn val_str(&self) -> &str {
        self.val
            .as_ref()
            .map_or("", |v| std::str::from_utf8(&v[..]).unwrap_or_default())
    }
}

/// Supports constructing from a tuple.
impl<K, V> From<&(K, V)> for TxtProperty
where
    K: ToString,
    V: ToString,
{
    fn from(prop: &(K, V)) -> Self {
        Self {
            key: prop.0.to_string(),
            val: Some(prop.1.to_string().into_bytes()),
        }
    }
}

impl<K, V> From<(K, V)> for TxtProperty
where
    K: ToString,
    V: AsRef<[u8]>,
{
    fn from(prop: (K, V)) -> Self {
        Self {
            key: prop.0.to_string(),
            val: Some(prop.1.as_ref().into()),
        }
    }
}

/// Support a property that has no value.
impl From<&str> for TxtProperty {
    fn from(key: &str) -> Self {
        Self {
            key: key.to_string(),
            val: None,
        }
    }
}

impl fmt::Display for TxtProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.key, self.val_str())
    }
}

/// Mimic the default debug output for a struct, with a twist:
/// - If self.var is UTF-8, will output it as a string in double quotes.
/// - If self.var is not UTF-8, will output its bytes as in hex.
impl fmt::Debug for TxtProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val_string = self.val.as_ref().map_or_else(
            || "None".to_string(),
            |v| {
                std::str::from_utf8(&v[..]).map_or_else(
                    |_| format!("Some({})", u8_slice_to_hex(&v[..])),
                    |s| format!("Some(\"{}\")", s),
                )
            },
        );

        write!(
            f,
            "TxtProperty {{key: \"{}\", val: {}}}",
            &self.key, &val_string,
        )
    }
}

const HEX_TABLE: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Create a hex string from `slice`, with a "0x" prefix.
///
/// For example, [1u8, 2u8] -> "0x0102"
fn u8_slice_to_hex(slice: &[u8]) -> String {
    let mut hex = String::with_capacity(slice.len() * 2 + 2);
    hex.push_str("0x");
    for b in slice {
        hex.push(HEX_TABLE[(b >> 4) as usize]);
        hex.push(HEX_TABLE[(b & 0x0F) as usize]);
    }
    hex
}

/// This trait allows for converting inputs into [`TxtProperties`].
pub trait IntoTxtProperties {
    fn into_txt_properties(self) -> TxtProperties;
}

impl IntoTxtProperties for HashMap<String, String> {
    fn into_txt_properties(mut self) -> TxtProperties {
        let properties = self
            .drain()
            .map(|(key, val)| TxtProperty {
                key,
                val: Some(val.into_bytes()),
            })
            .collect();
        TxtProperties { properties }
    }
}

/// Mainly for backward compatibility.
impl IntoTxtProperties for Option<HashMap<String, String>> {
    fn into_txt_properties(self) -> TxtProperties {
        self.map_or_else(
            || TxtProperties {
                properties: Vec::new(),
            },
            |h| h.into_txt_properties(),
        )
    }
}

/// Support Vec like `[("k1", "v1"), ("k2", "v2")]`.
impl<'a, T: 'a> IntoTxtProperties for &'a [T]
where
    TxtProperty: From<&'a T>,
{
    fn into_txt_properties(self) -> TxtProperties {
        let mut properties = Vec::new();
        let mut keys = HashSet::new();
        for t in self.iter() {
            let prop = TxtProperty::from(t);
            let key = prop.key.to_lowercase();
            if keys.insert(key) {
                // Only push a new entry if the key did not exist.
                //
                // RFC 6763: https://www.rfc-editor.org/rfc/rfc6763#section-6.4
                //
                // "If a client receives a TXT record containing the same key more than
                //    once, then the client MUST silently ignore all but the first
                //    occurrence of that attribute. "
                properties.push(prop);
            }
        }
        TxtProperties { properties }
    }
}

impl IntoTxtProperties for Vec<TxtProperty> {
    fn into_txt_properties(self) -> TxtProperties {
        TxtProperties { properties: self }
    }
}

// Convert from properties key/value pairs to DNS TXT record content
fn encode_txt<'a>(properties: impl Iterator<Item = &'a TxtProperty>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for prop in properties {
        let mut s = prop.key.clone().into_bytes();
        if let Some(v) = &prop.val {
            s.extend(b"=");
            s.extend(v);
        }

        // Property that exceed the length are truncated
        let sz: u8 = s.len().try_into().unwrap_or_else(|_| {
            debug!("Property {} is too long, truncating to 255 bytes", prop.key);
            s.resize(u8::MAX as usize, 0);
            u8::MAX
        });

        // TXT uses (Length,Value) format for each property,
        // i.e. the first byte is the length.
        bytes.push(sz);
        bytes.extend(s);
    }
    if bytes.is_empty() {
        bytes.push(0);
    }
    bytes
}

// Convert from DNS TXT record content to key/value pairs
pub(crate) fn decode_txt(txt: &[u8]) -> Vec<TxtProperty> {
    let mut properties = Vec::new();
    let mut offset = 0;
    while offset < txt.len() {
        let length = txt[offset] as usize;
        if length == 0 {
            break; // reached the end
        }
        offset += 1; // move over the length byte

        let offset_end = offset + length;
        if offset_end > txt.len() {
            debug!("DNS TXT record contains invalid data: Size given for property would be out of range. (offset={}, length={}, offset_end={}, record length={})", offset, length, offset_end, txt.len());
            break; // Skipping the rest of the record content, as the size for this property would already be out of range.
        }
        let kv_bytes = &txt[offset..offset_end];

        // split key and val using the first `=`
        let (k, v) = kv_bytes.iter().position(|&x| x == b'=').map_or_else(
            || (kv_bytes.to_vec(), None),
            |idx| (kv_bytes[..idx].to_vec(), Some(kv_bytes[idx + 1..].to_vec())),
        );

        // Make sure the key can be stored in UTF-8.
        match String::from_utf8(k) {
            Ok(k_string) => {
                properties.push(TxtProperty {
                    key: k_string,
                    val: v,
                });
            }
            Err(e) => debug!("failed to convert to String from key: {}", e),
        }

        offset += length;
    }

    properties
}

fn decode_txt_unique(txt: &[u8]) -> Vec<TxtProperty> {
    let mut properties = decode_txt(txt);

    // Remove duplicated keys and retain only the first appearance
    // of each key.
    let mut keys = HashSet::new();
    properties.retain(|p| {
        let key = p.key().to_lowercase();
        keys.insert(key) // returns True if key is new.
    });
    properties
}

/// Returns true if `addr` is in the same network of `intf`.
pub fn valid_ip_on_intf(addr: &IpAddr, intf: &Interface) -> bool {
    match (addr, &intf.addr) {
        (IpAddr::V4(addr), IfAddr::V4(intf)) => {
            let netmask = u32::from(intf.netmask);
            let intf_net = u32::from(intf.ip) & netmask;
            let addr_net = u32::from(*addr) & netmask;
            addr_net == intf_net
        }
        (IpAddr::V6(addr), IfAddr::V6(intf)) => {
            let netmask = u128::from(intf.netmask);
            let intf_net = u128::from(intf.ip) & netmask;
            let addr_net = u128::from(*addr) & netmask;
            addr_net == intf_net
        }
        _ => false,
    }
}

/// Returns true if `addr_a` and `addr_b` are in the same network as `intf`.
pub fn valid_two_addrs_on_intf(addr_a: &IpAddr, addr_b: &IpAddr, intf: &Interface) -> bool {
    match (addr_a, addr_b, &intf.addr) {
        (IpAddr::V4(ipv4_a), IpAddr::V4(ipv4_b), IfAddr::V4(intf)) => {
            let netmask = u32::from(intf.netmask);
            let intf_net = u32::from(intf.ip) & netmask;
            let net_a = u32::from(*ipv4_a) & netmask;
            let net_b = u32::from(*ipv4_b) & netmask;
            net_a == intf_net && net_b == intf_net
        }
        (IpAddr::V6(ipv6_a), IpAddr::V6(ipv6_b), IfAddr::V6(intf)) => {
            let netmask = u128::from(intf.netmask);
            let intf_net = u128::from(intf.ip) & netmask;
            let net_a = u128::from(*ipv6_a) & netmask;
            let net_b = u128::from(*ipv6_b) & netmask;
            net_a == intf_net && net_b == intf_net
        }
        _ => false,
    }
}

/// A probing for a particular name.
#[derive(Debug)]
pub(crate) struct Probe {
    /// All records probing for the same name.
    pub(crate) records: Vec<DnsRecordBox>,

    /// The fullnames of services that are probing these records.
    /// These are the original service names, will not change per conflicts.
    pub(crate) waiting_services: HashSet<String>,

    /// The time (T) to send the first query .
    pub(crate) start_time: u64,

    /// The time to send the next (including the first) query.
    pub(crate) next_send: u64,
}

impl Probe {
    pub(crate) fn new(start_time: u64) -> Self {
        // RFC 6762: https://datatracker.ietf.org/doc/html/rfc6762#section-8.1:
        //
        // "250 ms after the first query, the host should send a second; then,
        //   250 ms after that, a third.  If, by 250 ms after the third probe, no
        //   conflicting Multicast DNS responses have been received, the host may
        //   move to the next step, announcing. "
        let next_send = start_time;

        Self {
            records: Vec::new(),
            waiting_services: HashSet::new(),
            start_time,
            next_send,
        }
    }

    /// Add a new record with the same probing name in a sorted order.
    pub(crate) fn insert_record(&mut self, record: DnsRecordBox) {
        /*
        RFC 6762: https://datatracker.ietf.org/doc/html/rfc6762#section-8.2.1

        " The records are sorted using the same lexicographical order as
        described above, that is, if the record classes differ, the record
        with the lower class number comes first.  If the classes are the same
        but the rrtypes differ, the record with the lower rrtype number comes
        first."
         */
        let insert_position = self
            .records
            .binary_search_by(
                |existing| match existing.get_class().cmp(&record.get_class()) {
                    std::cmp::Ordering::Equal => existing.get_type().cmp(&record.get_type()),
                    other => other,
                },
            )
            .unwrap_or_else(|pos| pos);

        self.records.insert(insert_position, record);
    }

    /// Compares with `incoming` records. Returns `Less` if we yield.
    pub(crate) fn tiebreaking(&self, incoming: &[&DnsRecordBox]) -> cmp::Ordering {
        /*
        RFC 6762: https://datatracker.ietf.org/doc/html/rfc6762#section-8.2

        " If the host finds that its
            own data is lexicographically earlier, then it defers to the winning
            host by waiting one second, and then begins probing for this record
            again."
         */
        let min_len = self.records.len().min(incoming.len());

        // Compare elements up to the length of the shorter vector
        for (i, incoming_record) in incoming.iter().enumerate().take(min_len) {
            match self.records[i].compare(incoming_record.as_ref()) {
                cmp::Ordering::Equal => continue,
                other => return other,
            }
        }

        self.records.len().cmp(&incoming.len())
    }

    pub(crate) fn update_next_send(&mut self, now: u64) {
        self.next_send = now + 250;
    }

    /// Returns whether this probe is finished.
    pub(crate) fn expired(&self, now: u64) -> bool {
        // The 2nd query is T + 250ms, the 3rd query is T + 500ms,
        // The expire time is T + 750ms
        now >= self.start_time + 750
    }
}

/// DNS records of all the registered services.
pub(crate) struct DnsRegistry {
    /// keyed by the name of all related records.
    /*
     When a host is probing for a group of related records with the same
    name (e.g., the SRV and TXT record describing a DNS-SD service), only
    a single question need be placed in the Question Section, since query
    type "ANY" (255) is used, which will elicit answers for all records
    with that name.  However, for tiebreaking to work correctly in all
    cases, the Authority Section must contain *all* the records and
    proposed rdata being probed for uniqueness.
     */
    pub(crate) probing: HashMap<String, Probe>,

    /// Already done probing, or no need to probe.
    pub(crate) active: HashMap<String, Vec<DnsRecordBox>>,

    /// timers of the newly added probes.
    pub(crate) new_timers: Vec<u64>,

    /// Mapping from original names to new names.
    pub(crate) name_changes: HashMap<String, String>,
}

impl DnsRegistry {
    pub(crate) fn new() -> Self {
        Self {
            probing: HashMap::new(),
            active: HashMap::new(),
            new_timers: Vec::new(),
            name_changes: HashMap::new(),
        }
    }

    pub(crate) fn is_probing_done<T>(
        &mut self,
        answer: &T,
        service_name: &str,
        start_time: u64,
    ) -> bool
    where
        T: DnsRecordExt + Send + 'static,
    {
        if let Some(active_records) = self.active.get(answer.get_name()) {
            for record in active_records.iter() {
                if answer.matches(record.as_ref()) {
                    debug!(
                        "found active record {} {}",
                        answer.get_type(),
                        answer.get_name(),
                    );
                    return true;
                }
            }
        }

        let probe = self
            .probing
            .entry(answer.get_name().to_string())
            .or_insert_with(|| {
                debug!("new probe of {}", answer.get_name());
                Probe::new(start_time)
            });

        self.new_timers.push(probe.next_send);

        for record in probe.records.iter() {
            if answer.matches(record.as_ref()) {
                debug!(
                    "found existing record {} in probe of '{}'",
                    answer.get_type(),
                    answer.get_name(),
                );
                probe.waiting_services.insert(service_name.to_string());
                return false; // Found existing probe for the same record.
            }
        }

        debug!(
            "insert record {} into probe of {}",
            answer.get_type(),
            answer.get_name(),
        );
        probe.insert_record(answer.clone_box());
        probe.waiting_services.insert(service_name.to_string());

        false
    }

    /// check all records in "probing" and "active":
    /// if the record is SRV, and hostname is set to original, remove it.
    /// and create a new SRV with "host" set to "new_name" and put into "probing".
    pub(crate) fn update_hostname(
        &mut self,
        original: &str,
        new_name: &str,
        probe_time: u64,
    ) -> bool {
        let mut found_records = Vec::new();
        let mut new_timer_added = false;

        for (_name, probe) in self.probing.iter_mut() {
            probe.records.retain(|record| {
                if record.get_type() == RRType::SRV {
                    if let Some(srv) = record.any().downcast_ref::<DnsSrv>() {
                        if srv.host() == original {
                            let mut new_record = srv.clone();
                            new_record.set_host(new_name.to_string());
                            found_records.push(new_record);
                            return false;
                        }
                    }
                }
                true
            });
        }

        for (_name, records) in self.active.iter_mut() {
            records.retain(|record| {
                if record.get_type() == RRType::SRV {
                    if let Some(srv) = record.any().downcast_ref::<DnsSrv>() {
                        if srv.host() == original {
                            let mut new_record = srv.clone();
                            new_record.set_host(new_name.to_string());
                            found_records.push(new_record);
                            return false;
                        }
                    }
                }
                true
            });
        }

        for record in found_records {
            let probe = match self.probing.get_mut(record.get_name()) {
                Some(p) => {
                    p.start_time = probe_time; // restart this probe.
                    p
                }
                None => {
                    let new_probe = self
                        .probing
                        .entry(record.get_name().to_string())
                        .or_insert_with(|| Probe::new(probe_time));
                    new_timer_added = true;
                    new_probe
                }
            };

            debug!(
                "insert record {} with new hostname {new_name} into probe for: {}",
                record.get_type(),
                record.get_name()
            );
            probe.insert_record(Box::new(record));
        }

        new_timer_added
    }
}

/// Returns a tuple of (service_type_domain, optional_sub_domain)
pub(crate) fn split_sub_domain(domain: &str) -> (&str, Option<&str>) {
    if let Some((_, ty_domain)) = domain.rsplit_once("._sub.") {
        (ty_domain, Some(domain))
    } else {
        (domain, None)
    }
}

/// Represents a resolved service as a plain data struct.
/// This is from a client (i.e. querier) point of view.
#[non_exhaustive]
pub struct ResolvedService {
    /// Service type and domain. For example, "_http._tcp.local."
    pub ty_domain: String,

    /// Optional service subtype and domain.
    ///
    /// See RFC6763 section 7.1 about "Subtypes":
    /// <https://datatracker.ietf.org/doc/html/rfc6763#section-7.1>
    /// For example, "_printer._sub._http._tcp.local."
    pub sub_ty_domain: Option<String>,

    /// Full name of the service. For example, "my-service._http._tcp.local."
    pub fullname: String,

    /// Host name of the service. For example, "my-server1.local."
    pub host: String,

    /// Port of the service. I.e. TCP or UDP port.
    pub port: u16,

    /// Addresses of the service. IPv4 or IPv6 addresses.
    pub addresses: HashSet<IpAddr>,

    /// Properties of the service, decoded from TXT record.
    pub txt_properties: TxtProperties,
}

impl ResolvedService {
    /// Returns true if the service data is valid, i.e. ready to be used.
    pub fn is_valid(&self) -> bool {
        let some_missing = self.ty_domain.is_empty()
            || self.fullname.is_empty()
            || self.host.is_empty()
            || self.addresses.is_empty();
        !some_missing
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_txt, encode_txt, u8_slice_to_hex, valid_two_addrs_on_intf, ServiceInfo, TxtProperty,
    };
    use if_addrs::{IfAddr, Ifv4Addr, Ifv6Addr, Interface};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_txt_encode_decode() {
        let properties = vec![
            TxtProperty::from(&("key1", "value1")),
            TxtProperty::from(&("key2", "value2")),
        ];

        // test encode
        let property_count = properties.len();
        let encoded = encode_txt(properties.iter());
        assert_eq!(
            encoded.len(),
            "key1=value1".len() + "key2=value2".len() + property_count
        );
        assert_eq!(encoded[0] as usize, "key1=value1".len());

        // test decode
        let decoded = decode_txt(&encoded);
        assert!(properties[..] == decoded[..]);

        // test empty value
        let properties = vec![TxtProperty::from(&("key3", ""))];
        let property_count = properties.len();
        let encoded = encode_txt(properties.iter());
        assert_eq!(encoded.len(), "key3=".len() + property_count);

        let decoded = decode_txt(&encoded);
        assert_eq!(properties, decoded);

        // test non-string value
        let binary_val: Vec<u8> = vec![123, 234, 0];
        let binary_len = binary_val.len();
        let properties = vec![TxtProperty::from(("key4", binary_val))];
        let property_count = properties.len();
        let encoded = encode_txt(properties.iter());
        assert_eq!(encoded.len(), "key4=".len() + binary_len + property_count);

        let decoded = decode_txt(&encoded);
        assert_eq!(properties, decoded);

        // test value that contains '='
        let properties = vec![TxtProperty::from(("key5", "val=5"))];
        let property_count = properties.len();
        let encoded = encode_txt(properties.iter());
        assert_eq!(
            encoded.len(),
            "key5=".len() + "val=5".len() + property_count
        );

        let decoded = decode_txt(&encoded);
        assert_eq!(properties, decoded);

        // test a property that has no value.
        let properties = vec![TxtProperty::from("key6")];
        let property_count = properties.len();
        let encoded = encode_txt(properties.iter());
        assert_eq!(encoded.len(), "key6".len() + property_count);
        let decoded = decode_txt(&encoded);
        assert_eq!(properties, decoded);

        // test very long property.
        let properties = vec![TxtProperty::from(
            String::from_utf8(vec![0x30; 1024]).unwrap().as_str(), // A long string of 0 char
        )];
        let property_count = properties.len();
        let encoded = encode_txt(properties.iter());
        assert_eq!(encoded.len(), 255 + property_count);
        let decoded = decode_txt(&encoded);
        assert_eq!(
            vec![TxtProperty::from(
                String::from_utf8(vec![0x30; 255]).unwrap().as_str()
            )],
            decoded
        );
    }

    #[test]
    fn test_set_properties_from_txt() {
        // Three duplicated keys.
        let properties = vec![
            TxtProperty::from(&("one", "1")),
            TxtProperty::from(&("ONE", "2")),
            TxtProperty::from(&("One", "3")),
        ];
        let encoded = encode_txt(properties.iter());

        // Simple decode does not remove duplicated keys.
        let decoded = decode_txt(&encoded);
        assert_eq!(decoded.len(), 3);

        // ServiceInfo removes duplicated keys and keeps only the first one.
        let mut service_info =
            ServiceInfo::new("_test._tcp", "prop_test", "localhost", "", 1234, None).unwrap();
        service_info.set_properties_from_txt(&encoded);
        assert_eq!(service_info.get_properties().len(), 1);

        // Verify the only one property.
        let prop = service_info.get_properties().iter().next().unwrap();
        assert_eq!(prop.key, "one");
        assert_eq!(prop.val_str(), "1");
    }

    #[test]
    fn test_u8_slice_to_hex() {
        let bytes = [0x01u8, 0x02u8, 0x03u8];
        let hex = u8_slice_to_hex(&bytes);
        assert_eq!(hex.as_str(), "0x010203");

        let slice = "abcdefghijklmnopqrstuvwxyz";
        let hex = u8_slice_to_hex(slice.as_bytes());
        assert_eq!(hex.len(), slice.len() * 2 + 2);
        assert_eq!(
            hex.as_str(),
            "0x6162636465666768696a6b6c6d6e6f707172737475767778797a"
        );
    }

    #[test]
    fn test_txt_property_debug() {
        // Test UTF-8 property value.
        let prop_1 = TxtProperty {
            key: "key1".to_string(),
            val: Some("val1".to_string().into()),
        };
        let prop_1_debug = format!("{:?}", &prop_1);
        assert_eq!(
            prop_1_debug,
            "TxtProperty {key: \"key1\", val: Some(\"val1\")}"
        );

        // Test non-UTF-8 property value.
        let prop_2 = TxtProperty {
            key: "key2".to_string(),
            val: Some(vec![150u8, 151u8, 152u8]),
        };
        let prop_2_debug = format!("{:?}", &prop_2);
        assert_eq!(
            prop_2_debug,
            "TxtProperty {key: \"key2\", val: Some(0x969798)}"
        );
    }

    #[test]
    fn test_txt_decode_property_size_out_of_bounds() {
        // Construct a TXT record with an invalid property length that would be out of bounds.
        let encoded: Vec<u8> = vec![
            0x0b, // Length 11
            b'k', b'e', b'y', b'1', b'=', b'v', b'a', b'l', b'u', b'e',
            b'1', // key1=value1 (Length 11)
            0x10, // Length 16 (Would be out of bounds)
            b'k', b'e', b'y', b'2', b'=', b'v', b'a', b'l', b'u', b'e',
            b'2', // key2=value2 (Length 11)
        ];
        // Decode the record content
        let decoded = decode_txt(&encoded);
        // We expect the out of bounds length for the second property to have caused the rest of the record content to be skipped.
        // Test that we only parsed the first property.
        assert_eq!(decoded.len(), 1);
        // Test that the key of the property we parsed is "key1"
        assert_eq!(decoded[0].key, "key1");
    }

    #[test]
    fn test_valid_two_addrs_on_intf() {
        // test IPv4

        let ipv4_netmask = Ipv4Addr::new(192, 168, 1, 0);
        let ipv4_intf_addr = IfAddr::V4(Ifv4Addr {
            ip: Ipv4Addr::new(192, 168, 1, 10),
            netmask: ipv4_netmask,
            prefixlen: 24,
            broadcast: None,
        });
        let ipv4_intf = Interface {
            name: "e0".to_string(),
            addr: ipv4_intf_addr,
            index: Some(1),
            #[cfg(windows)]
            adapter_name: "ethernet".to_string(),
        };
        let ipv4_a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let ipv4_b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11));

        let result = valid_two_addrs_on_intf(&ipv4_a, &ipv4_b, &ipv4_intf);
        assert!(result);

        let ipv4_c = IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1));
        let result = valid_two_addrs_on_intf(&ipv4_a, &ipv4_c, &ipv4_intf);
        assert!(!result);

        // test IPv6 (generated by AI)

        let ipv6_netmask = Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0); // Equivalent to /32 prefix length
        let ipv6_intf_addr = IfAddr::V6(Ifv6Addr {
            ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            netmask: ipv6_netmask,
            prefixlen: 32,
            broadcast: None,
        });
        let ipv6_intf = Interface {
            name: "eth0".to_string(),
            addr: ipv6_intf_addr,
            index: Some(2),
            #[cfg(windows)]
            adapter_name: "ethernet".to_string(),
        };
        let ipv6_a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ipv6_b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        let result = valid_two_addrs_on_intf(&ipv6_a, &ipv6_b, &ipv6_intf);
        assert!(result); // Expect true since both addresses are in the same subnet

        let ipv6_c = IpAddr::V6(Ipv6Addr::new(0x2002, 0xdb8, 0, 0, 0, 0, 0, 1));
        let result = valid_two_addrs_on_intf(&ipv6_a, &ipv6_c, &ipv6_intf);
        assert!(!result); // Expect false since addresses are in different subnets
    }
}
