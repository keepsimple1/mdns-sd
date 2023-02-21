#[cfg(feature = "logging")]
use crate::log::error;
use crate::{dns_parser::current_time_millis, Error, Result};
use if_addrs::Ifv4Addr;
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    net::Ipv4Addr,
    str::FromStr,
};

/// Default TTL values in seconds
const DNS_HOST_TTL: u32 = 120; // 2 minutes for host records (A, SRV etc) per RFC6762
const DNS_OTHER_TTL: u32 = 4500; // 75 minutes for non-host records (PTR, TXT etc) per RFC6762

/// Complete info about a Service Instance.
///
/// We can construct some PTR, one SRV and one TXT record from this info,
/// as well as A (IPv4 Address) records.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    ty_domain: String,          // <service>.<domain>
    sub_domain: Option<String>, // <subservice>._sub.<service>.<domain>
    fullname: String,           // <instance>.<service>.<domain>
    server: String,             // fully qualified name for service host
    addresses: HashSet<Ipv4Addr>,
    port: u16,
    host_ttl: u32,  // used for SRV and Address records
    other_ttl: u32, // used for PTR and TXT records
    priority: u16,
    weight: u16,
    txt_properties: TxtProperties,
    last_update: u64, // UNIX time in millis
    addr_auto: bool,  // Let the system update addresses automatically.
}

impl ServiceInfo {
    /// Creates a new service info.
    ///
    /// `ty_domain` is the service type and the domain label, for example
    /// "_my-service._udp.local.".
    ///
    /// `my_name` is the instance name, without the service type suffix.
    ///
    /// `properties` can be `None` or key/value string pairs, in a type that
    /// implements [`IntoTxtProperties`] trait. It supports:
    /// - `HashMap<String, String>`
    /// - `Option<HashMap<String, String>>`
    /// - slice of tuple: `&[(K, V)]` where `K` and `V` are [`std::string::ToString`].
    ///
    /// `host_ipv4` can be one or more IPv4 addresses, in a type that implements
    /// [`AsIpv4Addrs`] trait. It supports:
    ///
    /// - Single IPv4: `"192.168.0.1"`
    /// - Multiple IPv4 separated by comma: `"192.168.0.1,192.168.0.2"`
    /// - A slice of IPv4: `&["192.168.0.1", "192.168.0.2"]`
    /// - All the above formats with [Ipv4Addr] or `String` instead of `&str`.
    ///
    /// The host TTL and other TTL are set to default values.
    pub fn new<Ip: AsIpv4Addrs, P: IntoTxtProperties>(
        ty_domain: &str,
        my_name: &str,
        host_name: &str,
        host_ipv4: Ip,
        port: u16,
        properties: P,
    ) -> Result<Self> {
        let (ty_domain, sub_domain) = split_sub_domain(ty_domain);

        let fullname = format!("{}.{}", my_name, ty_domain);
        let ty_domain = ty_domain.to_string();
        let sub_domain = sub_domain.map(str::to_string);
        let server = host_name.to_string();
        let addresses = host_ipv4.as_ipv4_addrs()?;
        let txt_properties = properties.into_txt_properties();
        let last_update = current_time_millis();

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
            last_update,
            addr_auto: false,
        };

        Ok(this)
    }

    /// Indicates that the library should automatically
    /// update the addresses of this service, when IPv4
    /// address(es) are added or removed on the host.
    pub fn enable_addr_auto(mut self) -> Self {
        self.addr_auto = true;
        self
    }

    /// Returns if the service's addresses will be updated
    /// automatically when the host IPv4 addrs change.
    pub fn is_addr_auto(&self) -> bool {
        self.addr_auto
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
    pub fn get_subtype(&self) -> &Option<String> {
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
    pub fn get_properties(&self) -> &TxtProperties {
        &self.txt_properties
    }

    /// Returns a property for a given `key`, where `key` is
    /// case insensitive.
    pub fn get_property(&self, key: &str) -> Option<&TxtProperty> {
        self.txt_properties.get(key)
    }

    /// Returns a property value string for a given `key`, where `key` is
    /// case insensitive.
    #[inline]
    pub fn get_property_val(&self, key: &str) -> Option<&str> {
        self.txt_properties.get_property_val(key)
    }

    /// Returns the service's hostname.
    #[inline]
    pub fn get_hostname(&self) -> &str {
        &self.server
    }

    /// Returns the service's port.
    #[inline]
    pub fn get_port(&self) -> u16 {
        self.port
    }

    /// Returns the service's addresses
    #[inline]
    pub fn get_addresses(&self) -> &HashSet<Ipv4Addr> {
        &self.addresses
    }

    /// Returns the service's TTL used for SRV and Address records.
    #[inline]
    pub fn get_host_ttl(&self) -> u32 {
        self.host_ttl
    }

    /// Returns the service's TTL used for PTR and TXT records.
    #[inline]
    pub fn get_other_ttl(&self) -> u32 {
        self.other_ttl
    }

    /// Returns the service's priority used in SRV records.
    #[inline]
    pub fn get_priority(&self) -> u16 {
        self.priority
    }

    /// Returns the service's weight used in SRV records.
    #[inline]
    pub fn get_weight(&self) -> u16 {
        self.weight
    }

    /// Returns a list of addresses that are in the same LAN as
    /// the interface `intf`.
    pub(crate) fn get_addrs_on_intf(&self, intf: &Ifv4Addr) -> Vec<Ipv4Addr> {
        self.addresses
            .iter()
            .filter(|a| valid_ipv4_on_intf(a, intf))
            .copied()
            .collect()
    }

    /// Returns whether the service info is ready to be resolved.
    pub(crate) fn is_ready(&self) -> bool {
        let some_missing = self.ty_domain.is_empty()
            || self.fullname.is_empty()
            || self.server.is_empty()
            || self.port == 0
            || self.addresses.is_empty();
        !some_missing
    }

    /// Insert `addr` into service info addresses.
    pub(crate) fn insert_ipv4addr(&mut self, addr: Ipv4Addr) {
        self.addresses.insert(addr);
    }

    pub(crate) fn remove_ipv4addr(&mut self, addr: &Ipv4Addr) {
        self.addresses.remove(addr);
    }

    pub(crate) fn generate_txt(&self) -> Vec<u8> {
        encode_txt(self.get_properties().iter())
    }

    pub(crate) fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    pub(crate) fn set_hostname(&mut self, hostname: String) {
        self.server = hostname;
    }

    pub(crate) fn set_properties_from_txt(&mut self, txt: &[u8]) {
        self.txt_properties = TxtProperties {
            properties: decode_txt(txt),
        };
    }

    pub(crate) fn get_last_update(&self) -> u64 {
        self.last_update
    }

    pub(crate) fn set_last_update(&mut self, update: u64) {
        self.last_update = update;
    }
}

/// This trait allows for parsing an input into a set of one or multiple [`Ipv4Addr`].
pub trait AsIpv4Addrs {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>>;
}

impl<T: AsIpv4Addrs> AsIpv4Addrs for &T {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>> {
        (*self).as_ipv4_addrs()
    }
}

/// Supports one address or multiple addresses separated by `,`.
/// For example: "127.0.0.1,127.0.0.2".
///
/// If the string is empty, will return an empty set.
impl AsIpv4Addrs for &str {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>> {
        let mut addrs = HashSet::new();

        if !self.is_empty() {
            let iter = self.split(',').map(str::trim).map(Ipv4Addr::from_str);
            for addr in iter {
                let addr = addr.map_err(|err| Error::ParseIpAddr(err.to_string()))?;
                addrs.insert(addr);
            }
        }

        Ok(addrs)
    }
}

impl AsIpv4Addrs for String {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>> {
        self.as_str().as_ipv4_addrs()
    }
}

/// Support slice. Example: &["127.0.0.1", "127.0.0.2"]
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

impl AsIpv4Addrs for std::net::Ipv4Addr {
    fn as_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>> {
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
#[derive(Debug, Clone)]
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

    /// Returns a property value string for a given `key`, where `key` is
    /// case insensitive.
    pub fn get_property_val(&self, key: &str) -> Option<&str> {
        self.get(key).map(|x| x.val())
    }
}

/// Represents a property in a TXT record.
#[derive(Debug, Clone, PartialEq)]
pub struct TxtProperty {
    /// The name of the property. The original cases are kept.
    key: String,

    /// RFC 6763 says values are bytes, not necessarily UTF-8.
    /// For now we define `val` as UTF-8 for ergnomics benefits.
    val: String,
}

impl TxtProperty {
    /// Returns the key of a property.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the value of a property.
    pub fn val(&self) -> &str {
        &self.val
    }
}

/// Supports constructing from a tuple.
impl<K, V> From<&(K, V)> for TxtProperty
where
    K: ToString,
    V: ToString,
{
    fn from(prop: &(K, V)) -> Self {
        TxtProperty {
            key: prop.0.to_string(),
            val: prop.1.to_string(),
        }
    }
}

/// This trait allows for converting inputs into [`TxtProperties`].
pub trait IntoTxtProperties {
    fn into_txt_properties(self) -> TxtProperties;
}

impl IntoTxtProperties for HashMap<String, String> {
    fn into_txt_properties(mut self) -> TxtProperties {
        let properties = self
            .drain()
            .map(|(key, val)| TxtProperty { key, val })
            .collect();
        TxtProperties { properties }
    }
}

/// Mainly for backward compatibility.
impl IntoTxtProperties for Option<HashMap<String, String>> {
    fn into_txt_properties(self) -> TxtProperties {
        match self {
            None => {
                let properties = Vec::new();
                TxtProperties { properties }
            }
            Some(h) => h.into_txt_properties(),
        }
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

// Convert from properties key/value pairs to DNS TXT record content
fn encode_txt<'a>(properties: impl Iterator<Item = &'a TxtProperty>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for prop in properties {
        let s = format!("{}={}", prop.key, prop.val);
        bytes.push(s.len().try_into().unwrap());
        bytes.extend_from_slice(s.as_bytes());
    }
    if bytes.is_empty() {
        bytes.push(0);
    }
    bytes
}

// Convert from DNS TXT record content to key/value pairs
fn decode_txt(txt: &[u8]) -> Vec<TxtProperty> {
    let mut properties = Vec::new();
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
                    properties.push(TxtProperty {
                        key: k.to_string(),
                        val: v.to_string(),
                    });
                }
                None => error!("cannot find = sign inside {}", &kv_string),
            },
            Err(e) => error!("failed to convert to String from key/value pair: {}", e),
        }
        offset += length;
    }

    properties
}

/// Returns a tuple of (service_type_domain, optional_sub_domain)
pub(crate) fn split_sub_domain(domain: &str) -> (&str, Option<&str>) {
    if let Some((_, ty_domain)) = domain.rsplit_once("._sub.") {
        (ty_domain, Some(domain))
    } else {
        (domain, None)
    }
}

/// Returns true if `addr` is in the same network of `intf`.
pub(crate) fn valid_ipv4_on_intf(addr: &Ipv4Addr, intf: &Ifv4Addr) -> bool {
    let netmask = u32::from(intf.netmask);
    let intf_net = u32::from(intf.ip) & netmask;
    let addr_net = u32::from(*addr) & netmask;
    addr_net == intf_net
}

#[cfg(test)]
mod tests {
    use super::{decode_txt, encode_txt};
    use crate::service_info::TxtProperty;

    #[test]
    fn test_txt_encode_decode() {
        let properties = vec![
            TxtProperty {
                key: "key1".to_string(),
                val: "value1".to_string(),
            },
            TxtProperty {
                key: "key2".to_string(),
                val: "value2".to_string(),
            },
        ];

        // test encode
        let encoded = encode_txt(properties.iter());
        assert_eq!(
            encoded.len(),
            "key1=".len() + "value1".len() + "key2=".len() + "value2".len() + 2
        );
        assert_eq!(encoded[0] as usize, "key1=".len() + "value1".len());

        // test decode
        let decoded = decode_txt(&encoded);
        assert!(&properties[..] == &decoded[..]);
    }
}
