//! DNS parsing utility.
//!
//! [DnsIncoming] is the logic representation of an incoming DNS packet.
//! [DnsOutgoing] is the logic representation of an outgoing DNS message of one or more packets.
//! [DnsOutPacket] is the encoded one packet for [DnsOutgoing].

#[cfg(feature = "logging")]
use crate::log::debug;
use crate::{
    service_info::{decode_txt, valid_ip_on_intf},
    Error, Result, ServiceInfo,
};
use if_addrs::Interface;
use std::{
    any::Any,
    cmp,
    collections::HashMap,
    convert::TryInto,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str,
    time::SystemTime,
};

pub const TYPE_A: u16 = 1; // IPv4 address
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_HINFO: u16 = 13;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28; // IPv6 address
pub const TYPE_SRV: u16 = 33;
pub const TYPE_NSEC: u16 = 47; // Negative responses
pub const TYPE_ANY: u16 = 255;

pub(crate) const fn rr_type_name(rr_type: u16) -> &'static str {
    match rr_type {
        TYPE_A => "TYPE_A",
        TYPE_CNAME => "TYPE_CNAME",
        TYPE_PTR => "TYPE_PTR",
        TYPE_HINFO => "TYPE_HINFO",
        TYPE_TXT => "TYPE_TXT",
        TYPE_AAAA => "TYPE_AAAA",
        TYPE_SRV => "TYPE_SRV",
        TYPE_NSEC => "TYPE_NSEC",
        TYPE_ANY => "TYPE_ANY",
        _ => "type_others",
    }
}

pub const CLASS_IN: u16 = 1;
pub const CLASS_MASK: u16 = 0x7FFF;
pub const CLASS_CACHE_FLUSH: u16 = 0x8000;

/// Max size of UDP datagram payload: 9000 bytes - IP header 20 bytes - UDP header 8 bytes.
/// Reference: RFC6762: https://datatracker.ietf.org/doc/html/rfc6762#section-17
pub const MAX_MSG_ABSOLUTE: usize = 8972;

const MSG_HEADER_LEN: usize = 12;

// Definitions for DNS message header "flags" field
//
// The "flags" field is 16-bit long, in this format:
// (RFC 1035 section 4.1.1)
//
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//
pub const FLAGS_QR_MASK: u16 = 0x8000; // mask for query/response bit
pub const FLAGS_QR_QUERY: u16 = 0x0000;
pub const FLAGS_QR_RESPONSE: u16 = 0x8000;

/// mask for Authoritative answer bit
pub const FLAGS_AA: u16 = 0x0400;

/// mask for TC(Truncated) bit
///
/// 2024-08-10: currently this flag is only supported on the querier side,
///             not supported on the responder side. I.e. the responder only
///             handles the first packet and ignore this bit. Since the
///             additional packets have 0 questions, the processing of them
///             is no-op.
///             In practice, this means the responder supports Known-Answer
///             only with single packet, not multi-packet. The querier supports
///             both single packet and multi-packet.
pub const FLAGS_TC: u16 = 0x0200;

pub(crate) type DnsRecordBox = Box<dyn DnsRecordExt>;

const U16_SIZE: usize = 2;

#[inline]
pub const fn ip_address_to_type(address: &IpAddr) -> u16 {
    match address {
        IpAddr::V4(_) => TYPE_A,
        IpAddr::V6(_) => TYPE_AAAA,
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct DnsEntry {
    pub(crate) name: String, // always lower case.
    pub(crate) ty: u16,
    class: u16,
    cache_flush: bool,
}

impl DnsEntry {
    const fn new(name: String, ty: u16, class: u16) -> Self {
        Self {
            name,
            ty,
            class: class & CLASS_MASK,
            cache_flush: (class & CLASS_CACHE_FLUSH) != 0,
        }
    }
}

/// A DNS question entry
#[derive(Debug)]
pub struct DnsQuestion {
    pub(crate) entry: DnsEntry,
}

/// A DNS Resource Record - like a DNS entry, but has a TTL.
/// RFC: https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1
///      https://www.rfc-editor.org/rfc/rfc1035#section-4.1.3
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub(crate) entry: DnsEntry,
    ttl: u32,     // in seconds, 0 means this record should not be cached
    created: u64, // UNIX time in millis
    expires: u64, // expires at this UNIX time in millis

    /// Support re-query an instance before its PTR record expires.
    /// See https://datatracker.ietf.org/doc/html/rfc6762#section-5.2
    refresh: u64, // UNIX time in millis

    /// If conflict resolution decides to change the name, this is the new one.
    new_name: Option<String>,
}

impl DnsRecord {
    fn new(name: &str, ty: u16, class: u16, ttl: u32) -> Self {
        let created = current_time_millis();

        // From RFC 6762 section 5.2:
        // "... The querier should plan to issue a query at 80% of the record
        // lifetime, and then if no answer is received, at 85%, 90%, and 95%."
        let refresh = get_expiration_time(created, ttl, 80);

        let expires = get_expiration_time(created, ttl, 100);

        Self {
            entry: DnsEntry::new(name.to_string(), ty, class),
            ttl,
            created,
            expires,
            refresh,
            new_name: None,
        }
    }

    pub(crate) const fn get_expire_time(&self) -> u64 {
        self.expires
    }

    pub(crate) const fn get_refresh_time(&self) -> u64 {
        self.refresh
    }

    pub(crate) const fn is_expired(&self, now: u64) -> bool {
        now >= self.expires
    }

    pub(crate) const fn refresh_due(&self, now: u64) -> bool {
        now >= self.refresh
    }

    /// Returns whether `now` (in millis) has passed half of TTL.
    pub(crate) fn halflife_passed(&self, now: u64) -> bool {
        let halflife = get_expiration_time(self.created, self.ttl, 50);
        now > halflife
    }

    pub(crate) fn is_unique(&self) -> bool {
        self.entry.cache_flush
    }

    /// Updates the refresh time to be the same as the expire time so that
    /// this record will not refresh again and will just expire.
    pub(crate) fn refresh_no_more(&mut self) {
        self.refresh = get_expiration_time(self.created, self.ttl, 100);
    }

    /// Returns if this record is due for refresh. If yes, `refresh` time is updated.
    pub(crate) fn refresh_maybe(&mut self, now: u64) -> bool {
        if self.is_expired(now) || !self.refresh_due(now) {
            return false;
        }

        debug!(
            "{} qtype {} is due to refresh",
            &self.entry.name, self.entry.ty
        );

        // From RFC 6762 section 5.2:
        // "... The querier should plan to issue a query at 80% of the record
        // lifetime, and then if no answer is received, at 85%, 90%, and 95%."
        //
        // If the answer is received in time, 'refresh' will be reset outside
        // this function, back to 80% of the new TTL.
        if self.refresh == get_expiration_time(self.created, self.ttl, 80) {
            self.refresh = get_expiration_time(self.created, self.ttl, 85);
        } else if self.refresh == get_expiration_time(self.created, self.ttl, 85) {
            self.refresh = get_expiration_time(self.created, self.ttl, 90);
        } else if self.refresh == get_expiration_time(self.created, self.ttl, 90) {
            self.refresh = get_expiration_time(self.created, self.ttl, 95);
        } else {
            self.refresh_no_more();
        }

        true
    }

    /// Returns the remaining TTL in seconds
    fn get_remaining_ttl(&self, now: u64) -> u32 {
        let remaining_millis = get_expiration_time(self.created, self.ttl, 100) - now;
        cmp::max(0, remaining_millis / 1000) as u32
    }

    /// Return the absolute time for this record being created
    const fn get_created(&self) -> u64 {
        self.created
    }

    /// Set the absolute expiration time in millis
    fn set_expire(&mut self, expire_at: u64) {
        self.expires = expire_at;
    }

    fn reset_ttl(&mut self, other: &Self) {
        self.ttl = other.ttl;
        self.created = other.created;
        self.refresh = get_expiration_time(self.created, self.ttl, 80);
        self.expires = get_expiration_time(self.created, self.ttl, 100);
    }

    /// Modify TTL to reflect the remaining life time from `now`.
    pub(crate) fn update_ttl(&mut self, now: u64) {
        if now > self.created {
            let elapsed = now - self.created;
            self.ttl -= (elapsed / 1000) as u32;
        }
    }

    pub(crate) fn set_new_name(&mut self, new_name: String) {
        if new_name == self.entry.name {
            self.new_name = None;
        } else {
            self.new_name = Some(new_name);
        }
    }

    pub(crate) fn get_new_name(&self) -> Option<&str> {
        self.new_name.as_deref()
    }

    /// Return the new name if exists, otherwise the regular name in DnsEntry.
    pub(crate) fn get_name(&self) -> &str {
        self.new_name.as_deref().unwrap_or(&self.entry.name)
    }

    pub(crate) fn get_original_name(&self) -> &str {
        &self.entry.name
    }
}

impl PartialEq for DnsRecord {
    fn eq(&self, other: &Self) -> bool {
        self.entry == other.entry
    }
}

pub(crate) trait DnsRecordExt: fmt::Debug {
    fn get_record(&self) -> &DnsRecord;
    fn get_record_mut(&mut self) -> &mut DnsRecord;
    fn write(&self, packet: &mut DnsOutPacket);
    fn any(&self) -> &dyn Any;

    /// Returns whether `other` record is considered the same except TTL.
    fn matches(&self, other: &dyn DnsRecordExt) -> bool;

    /// Returns whether `other` record has the same rdata.
    fn rrdata_match(&self, other: &dyn DnsRecordExt) -> bool;

    /// Returns the result based on a byte-level comparison of `rdata`.
    /// If `other` is not valid, returns `Greater`.
    fn compare_rdata(&self, other: &dyn DnsRecordExt) -> cmp::Ordering;

    /// Returns the result based on "lexicographically later" defined below.
    fn compare(&self, other: &dyn DnsRecordExt) -> cmp::Ordering {
        /*
        RFC 6762: https://datatracker.ietf.org/doc/html/rfc6762#section-8.2

        ... The determination of "lexicographically later" is performed by first
        comparing the record class (excluding the cache-flush bit described
        in Section 10.2), then the record type, then raw comparison of the
        binary content of the rdata without regard for meaning or structure.
        If the record classes differ, then the numerically greater class is
        considered "lexicographically later".  Otherwise, if the record types
        differ, then the numerically greater type is considered
        "lexicographically later".  If the rrtype and rrclass both match,
        then the rdata is compared. ...
        */
        match self.get_class().cmp(&other.get_class()) {
            cmp::Ordering::Equal => match self.get_type().cmp(&other.get_type()) {
                cmp::Ordering::Equal => self.compare_rdata(other),
                not_equal => not_equal,
            },
            not_equal => not_equal,
        }
    }

    /// Returns a human-readable string of rdata.
    fn rdata_print(&self) -> String;

    /// Returns the class only, excluding class_flush / unique bit.
    fn get_class(&self) -> u16 {
        self.get_record().entry.class
    }

    fn get_cache_flush(&self) -> bool {
        self.get_record().entry.cache_flush
    }

    /// Return the new name if exists, otherwise the regular name in DnsEntry.
    fn get_name(&self) -> &str {
        self.get_record().get_name()
    }

    fn get_original_name(&self) -> &str {
        self.get_record().get_original_name()
    }

    fn get_type(&self) -> u16 {
        self.get_record().entry.ty
    }

    /// Resets TTL using `other` record.
    /// `self.refresh` and `self.expires` are also reset.
    fn reset_ttl(&mut self, other: &dyn DnsRecordExt) {
        self.get_record_mut().reset_ttl(other.get_record());
    }

    fn get_created(&self) -> u64 {
        self.get_record().get_created()
    }

    fn get_expire(&self) -> u64 {
        self.get_record().get_expire_time()
    }

    fn set_expire(&mut self, expire_at: u64) {
        self.get_record_mut().set_expire(expire_at);
    }

    /// Given `now`, if the record is due to refresh, this method updates the refresh time
    /// and returns the new refresh time. Otherwise, returns None.
    fn updated_refresh_time(&mut self, now: u64) -> Option<u64> {
        if self.get_record_mut().refresh_maybe(now) {
            Some(self.get_record().get_refresh_time())
        } else {
            None
        }
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

    fn clone_box(&self) -> Box<dyn DnsRecordExt>;
}

impl Clone for Box<dyn DnsRecordExt> {
    fn clone(&self) -> Box<dyn DnsRecordExt> {
        self.clone_box()
    }
}

#[derive(Debug, Clone)]
pub struct DnsAddress {
    pub(crate) record: DnsRecord,
    pub(crate) address: IpAddr,
}

impl DnsAddress {
    pub(crate) fn new(name: &str, ty: u16, class: u16, ttl: u32, address: IpAddr) -> Self {
        let record = DnsRecord::new(name, ty, class, ttl);
        Self { record, address }
    }

    /// Returns whether this address is in the same subnet of `intf`.
    pub(crate) fn in_subnet(&self, intf: &Interface) -> bool {
        valid_ip_on_intf(&self.address, intf)
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
        match self.address {
            IpAddr::V4(addr) => packet.write_bytes(addr.octets().as_ref()),
            IpAddr::V6(addr) => packet.write_bytes(addr.octets().as_ref()),
        };
    }

    fn any(&self) -> &dyn Any {
        self
    }

    fn matches(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_a) = other.any().downcast_ref::<Self>() {
            return self.address == other_a.address && self.record.entry == other_a.record.entry;
        }
        false
    }

    fn rrdata_match(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_a) = other.any().downcast_ref::<Self>() {
            return self.address == other_a.address;
        }
        false
    }

    fn compare_rdata(&self, other: &dyn DnsRecordExt) -> cmp::Ordering {
        if let Some(other_a) = other.any().downcast_ref::<Self>() {
            self.address.cmp(&other_a.address)
        } else {
            cmp::Ordering::Greater
        }
    }

    fn rdata_print(&self) -> String {
        format!("{}", self.address)
    }

    fn clone_box(&self) -> Box<dyn DnsRecordExt> {
        Box::new(self.clone())
    }
}

/// A DNS pointer record
#[derive(Debug, Clone)]
pub struct DnsPointer {
    record: DnsRecord,
    pub(crate) alias: String, // the full name of Service Instance
}

impl DnsPointer {
    pub(crate) fn new(name: &str, ty: u16, class: u16, ttl: u32, alias: String) -> Self {
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
        if let Some(other_ptr) = other.any().downcast_ref::<Self>() {
            return self.alias == other_ptr.alias && self.record.entry == other_ptr.record.entry;
        }
        false
    }

    fn rrdata_match(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_ptr) = other.any().downcast_ref::<Self>() {
            return self.alias == other_ptr.alias;
        }
        false
    }

    fn compare_rdata(&self, other: &dyn DnsRecordExt) -> cmp::Ordering {
        if let Some(other_ptr) = other.any().downcast_ref::<Self>() {
            self.alias.cmp(&other_ptr.alias)
        } else {
            cmp::Ordering::Greater
        }
    }

    fn rdata_print(&self) -> String {
        self.alias.clone()
    }

    fn clone_box(&self) -> Box<dyn DnsRecordExt> {
        Box::new(self.clone())
    }
}

// In common cases, there is one and only one SRV record for a particular fullname.
#[derive(Debug, Clone)]
pub struct DnsSrv {
    pub(crate) record: DnsRecord,
    pub(crate) priority: u16,
    // lower number means higher priority. Should be 0 in common cases.
    pub(crate) weight: u16,
    // Should be 0 in common cases
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl DnsSrv {
    pub(crate) fn new(
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
        if let Some(other_svc) = other.any().downcast_ref::<Self>() {
            return self.host == other_svc.host
                && self.port == other_svc.port
                && self.weight == other_svc.weight
                && self.priority == other_svc.priority
                && self.record.entry == other_svc.record.entry;
        }
        false
    }

    fn rrdata_match(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_srv) = other.any().downcast_ref::<Self>() {
            return self.host == other_srv.host
                && self.port == other_srv.port
                && self.weight == other_srv.weight
                && self.priority == other_srv.priority;
        }
        false
    }

    fn compare_rdata(&self, other: &dyn DnsRecordExt) -> cmp::Ordering {
        let Some(other_srv) = other.any().downcast_ref::<Self>() else {
            return cmp::Ordering::Greater;
        };

        // 1. compare `priority`
        match self
            .priority
            .to_be_bytes()
            .cmp(&other_srv.priority.to_be_bytes())
        {
            cmp::Ordering::Equal => {
                // 2. compare `weight`
                match self
                    .weight
                    .to_be_bytes()
                    .cmp(&other_srv.weight.to_be_bytes())
                {
                    cmp::Ordering::Equal => {
                        // 3. compare `port`.
                        match self.port.to_be_bytes().cmp(&other_srv.port.to_be_bytes()) {
                            cmp::Ordering::Equal => self.host.cmp(&other_srv.host),
                            not_equal => not_equal,
                        }
                    }
                    not_equal => not_equal,
                }
            }
            not_equal => not_equal,
        }
    }

    fn rdata_print(&self) -> String {
        format!(
            "priority: {}, weight: {}, port: {}, host: {}",
            self.priority, self.weight, self.port, self.host
        )
    }

    fn clone_box(&self) -> Box<dyn DnsRecordExt> {
        Box::new(self.clone())
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
#[derive(Clone)]
pub struct DnsTxt {
    pub(crate) record: DnsRecord,
    pub(crate) text: Vec<u8>,
}

impl DnsTxt {
    pub(crate) fn new(name: &str, class: u16, ttl: u32, text: Vec<u8>) -> Self {
        let record = DnsRecord::new(name, TYPE_TXT, class, ttl);
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
        packet.write_bytes(&self.text);
    }

    fn any(&self) -> &dyn Any {
        self
    }

    fn matches(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_txt) = other.any().downcast_ref::<Self>() {
            return self.text == other_txt.text && self.record.entry == other_txt.record.entry;
        }
        false
    }

    fn rrdata_match(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_txt) = other.any().downcast_ref::<Self>() {
            return self.text == other_txt.text;
        }
        false
    }

    fn compare_rdata(&self, other: &dyn DnsRecordExt) -> cmp::Ordering {
        if let Some(other_txt) = other.any().downcast_ref::<Self>() {
            self.text.cmp(&other_txt.text)
        } else {
            cmp::Ordering::Greater
        }
    }

    fn rdata_print(&self) -> String {
        format!("{:?}", decode_txt(&self.text))
    }

    fn clone_box(&self) -> Box<dyn DnsRecordExt> {
        Box::new(self.clone())
    }
}

impl fmt::Debug for DnsTxt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let properties = decode_txt(&self.text);
        write!(
            f,
            "DnsTxt {{ record: {:?}, text: {:?} }}",
            self.record, properties
        )
    }
}

/// A DNS host information record
#[derive(Debug, Clone)]
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
        if let Some(other_hinfo) = other.any().downcast_ref::<Self>() {
            return self.cpu == other_hinfo.cpu
                && self.os == other_hinfo.os
                && self.record.entry == other_hinfo.record.entry;
        }
        false
    }

    fn rrdata_match(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_hinfo) = other.any().downcast_ref::<Self>() {
            return self.cpu == other_hinfo.cpu && self.os == other_hinfo.os;
        }
        false
    }

    fn compare_rdata(&self, other: &dyn DnsRecordExt) -> cmp::Ordering {
        if let Some(other_hinfo) = other.any().downcast_ref::<Self>() {
            match self.cpu.cmp(&other_hinfo.cpu) {
                cmp::Ordering::Equal => self.os.cmp(&other_hinfo.os),
                ordering => ordering,
            }
        } else {
            cmp::Ordering::Greater
        }
    }

    fn rdata_print(&self) -> String {
        format!("cpu: {}, os: {}", self.cpu, self.os)
    }

    fn clone_box(&self) -> Box<dyn DnsRecordExt> {
        Box::new(self.clone())
    }
}

/// Record for negative responses
///
/// [RFC4034 section 4.1](https://datatracker.ietf.org/doc/html/rfc4034#section-4.1)
/// and
/// [RFC6762 section 6.1](https://datatracker.ietf.org/doc/html/rfc6762#section-6.1)
#[derive(Debug, Clone)]
pub struct DnsNSec {
    record: DnsRecord,
    next_domain: String,
    type_bitmap: Vec<u8>,
}

impl DnsNSec {
    fn new(name: &str, class: u16, ttl: u32, next_domain: String, type_bitmap: Vec<u8>) -> Self {
        let record = DnsRecord::new(name, TYPE_NSEC, class, ttl);
        Self {
            record,
            next_domain,
            type_bitmap,
        }
    }

    /// Returns the types marked by `type_bitmap`
    pub(crate) fn _types(&self) -> Vec<u16> {
        // From RFC 4034: 4.1.2 The Type Bit Maps Field
        // https://datatracker.ietf.org/doc/html/rfc4034#section-4.1.2
        //
        // Each bitmap encodes the low-order 8 bits of RR types within the
        // window block, in network bit order.  The first bit is bit 0.  For
        // window block 0, bit 1 corresponds to RR type 1 (A), bit 2 corresponds
        // to RR type 2 (NS), and so forth.

        let mut bit_num = 0;
        let mut results = Vec::new();

        for byte in self.type_bitmap.iter() {
            let mut bit_mask: u8 = 0x80; // for bit 0 in network bit order

            // check every bit in this byte, one by one.
            for _ in 0..8 {
                if (byte & bit_mask) != 0 {
                    results.push(bit_num);
                }
                bit_num += 1;
                bit_mask >>= 1; // mask for the next bit
            }
        }
        results
    }
}

impl DnsRecordExt for DnsNSec {
    fn get_record(&self) -> &DnsRecord {
        &self.record
    }

    fn get_record_mut(&mut self) -> &mut DnsRecord {
        &mut self.record
    }

    fn write(&self, packet: &mut DnsOutPacket) {
        packet.write_bytes(self.next_domain.as_bytes());
        packet.write_bytes(&self.type_bitmap);
    }

    fn any(&self) -> &dyn Any {
        self
    }

    fn matches(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_record) = other.any().downcast_ref::<Self>() {
            return self.next_domain == other_record.next_domain
                && self.type_bitmap == other_record.type_bitmap
                && self.record.entry == other_record.record.entry;
        }
        false
    }

    fn rrdata_match(&self, other: &dyn DnsRecordExt) -> bool {
        if let Some(other_record) = other.any().downcast_ref::<Self>() {
            return self.next_domain == other_record.next_domain
                && self.type_bitmap == other_record.type_bitmap;
        }
        false
    }

    fn compare_rdata(&self, other: &dyn DnsRecordExt) -> cmp::Ordering {
        if let Some(other_nsec) = other.any().downcast_ref::<Self>() {
            match self.next_domain.cmp(&other_nsec.next_domain) {
                cmp::Ordering::Equal => self.type_bitmap.cmp(&other_nsec.type_bitmap),
                ordering => ordering,
            }
        } else {
            cmp::Ordering::Greater
        }
    }

    fn rdata_print(&self) -> String {
        format!(
            "next_domain: {}, type_bitmap len: {}",
            self.next_domain,
            self.type_bitmap.len()
        )
    }

    fn clone_box(&self) -> Box<dyn DnsRecordExt> {
        Box::new(self.clone())
    }
}

#[derive(PartialEq)]
enum PacketState {
    Init = 0,
    Finished = 1,
}

/// A single packet for outgoing DNS message.
pub(crate) struct DnsOutPacket {
    /// All bytes in `data` concatenated is the actual packet on the wire.
    data: Vec<Vec<u8>>,

    /// Current logical size of the packet. It starts with the size of the mandatory header.
    size: usize,

    /// An internal state, not defined by DNS.
    state: PacketState,

    /// k: name, v: offset
    names: HashMap<String, u16>,
}

impl DnsOutPacket {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            size: MSG_HEADER_LEN, // Header is mandatory.
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
    /// Returns false if the packet exceeds the max size with this record, nothing is written to the packet.
    /// otherwise returns true.
    fn write_record(&mut self, record_ext: &dyn DnsRecordExt, now: u64) -> bool {
        let start_data_length = self.data.len();
        let start_size = self.size;

        let record = record_ext.get_record();
        self.write_name(record.get_name());
        self.write_short(record.entry.ty);
        if record.entry.cache_flush {
            // check "multicast"
            self.write_short(record.entry.class | CLASS_CACHE_FLUSH);
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

    pub(crate) fn insert_short(&mut self, index: usize, value: u16) {
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
            match self.names.get(remaining) {
                Some(offset) => {
                    let pointer = *offset | POINTER_MASK;
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
                    let stop = remaining.find('.').map_or(end, |i| here + i);
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

    /// Writes the header fields and finish the packet.
    /// This function should be only called when finishing a packet.
    ///
    /// The header format is based on RFC 1035 section 4.1.1:
    /// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    //
    //                                  1  1  1  1  1  1
    //    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //    |                      ID                       |
    //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //    |                    QDCOUNT                    |
    //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //    |                    ANCOUNT                    |
    //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //    |                    NSCOUNT                    |
    //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //    |                    ARCOUNT                    |
    //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //
    fn write_header(
        &mut self,
        id: u16,
        flags: u16,
        q_count: u16,
        a_count: u16,
        auth_count: u16,
        addi_count: u16,
    ) {
        self.insert_short(0, addi_count);
        self.insert_short(0, auth_count);
        self.insert_short(0, a_count);
        self.insert_short(0, q_count);
        self.insert_short(0, flags);
        self.insert_short(0, id);

        // Adjust the size as it was already initialized to include the header.
        self.size -= MSG_HEADER_LEN;

        self.state = PacketState::Finished;
    }
}

/// Representation of one or more outgoing packet(s). The actual encoded packet
/// is [DnsOutPacket].
pub(crate) struct DnsOutgoing {
    flags: u16,
    pub(crate) id: u16,
    multicast: bool,
    pub(crate) questions: Vec<DnsQuestion>,
    pub(crate) answers: Vec<(DnsRecordBox, u64)>,
    pub(crate) authorities: Vec<DnsRecordBox>,
    pub(crate) additionals: Vec<DnsRecordBox>,
    pub(crate) known_answer_count: i64, // for internal maintenance only
}

impl DnsOutgoing {
    pub(crate) fn new(flags: u16) -> Self {
        Self {
            flags,
            id: 0,
            multicast: true,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            known_answer_count: 0,
        }
    }

    pub(crate) const fn is_query(&self) -> bool {
        (self.flags & FLAGS_QR_MASK) == FLAGS_QR_QUERY
    }

    const fn is_response(&self) -> bool {
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
    pub(crate) fn add_additional_answer(&mut self, answer: impl DnsRecordExt + 'static) {
        debug!("add_additional_answer: {:?}", &answer);
        self.additionals.push(Box::new(answer));
    }

    /// A workaround as Rust doesn't allow us to pass DnsRecordBox in as `impl DnsRecordExt`
    pub(crate) fn add_answer_box(&mut self, answer_box: DnsRecordBox) {
        self.answers.push((answer_box, 0));
    }

    pub(crate) fn add_authority(&mut self, record: DnsRecordBox) {
        self.authorities.push(record);
    }

    /// Returns true if `answer` is added to the outgoing msg.
    /// Returns false if `answer` was not added as it expired or suppressed by the incoming `msg`.
    pub(crate) fn add_answer(
        &mut self,
        msg: &DnsIncoming,
        answer: impl DnsRecordExt + Send + 'static,
    ) -> bool {
        debug!("Check for add_answer");
        if answer.suppressed_by(msg) {
            debug!("my answer is suppressed by incoming msg");
            self.known_answer_count += 1;
            return false;
        }

        self.add_answer_at_time(answer, 0)
    }

    /// Returns true if `answer` is added to the outgoing msg.
    /// Returns false if the answer is expired `now` hence not added.
    /// If `now` is 0, do not check if the answer expires.
    pub(crate) fn add_answer_at_time(
        &mut self,
        answer: impl DnsRecordExt + Send + 'static,
        now: u64,
    ) -> bool {
        if now == 0 || !answer.get_record().is_expired(now) {
            debug!("add_answer push: {:?}", &answer);
            self.answers.push((Box::new(answer), now));
            return true;
        }
        false
    }

    /// Adds PTR answer and SRV, TXT, ADDR answers.
    /// See https://tools.ietf.org/html/rfc6763#section-12.1
    ///
    /// If there are no addresses on the LAN of `intf`, we will not
    /// add any answers for `service`. In other words, we only
    /// add addresses that are valid on `intf`.
    pub(crate) fn add_answer_with_additionals(
        &mut self,
        msg: &DnsIncoming,
        service: &ServiceInfo,
        intf: &Interface,
    ) {
        let intf_addrs = service.get_addrs_on_intf(intf);
        if intf_addrs.is_empty() {
            debug!("No addrs on LAN of intf {:?}", intf);
            return;
        }

        let ptr_added = self.add_answer(
            msg,
            DnsPointer::new(
                service.get_type(),
                TYPE_PTR,
                CLASS_IN,
                service.get_other_ttl(),
                service.get_fullname().to_string(),
            ),
        );

        if !ptr_added {
            debug!("answer was not added for msg {:?}", msg);
            return;
        }

        if let Some(sub) = service.get_subtype() {
            debug!("Adding subdomain {}", sub);
            self.add_additional_answer(DnsPointer::new(
                sub,
                TYPE_PTR,
                CLASS_IN,
                service.get_other_ttl(),
                service.get_fullname().to_string(),
            ));
        }

        // Add recommended additional answers according to
        // https://tools.ietf.org/html/rfc6763#section-12.1.
        self.add_additional_answer(DnsSrv::new(
            service.get_fullname(),
            CLASS_IN | CLASS_CACHE_FLUSH,
            service.get_host_ttl(),
            service.get_priority(),
            service.get_weight(),
            service.get_port(),
            service.get_hostname().to_string(),
        ));

        self.add_additional_answer(DnsTxt::new(
            service.get_fullname(),
            CLASS_IN | CLASS_CACHE_FLUSH,
            service.get_host_ttl(),
            service.generate_txt(),
        ));

        for address in intf_addrs {
            self.add_additional_answer(DnsAddress::new(
                service.get_hostname(),
                ip_address_to_type(&address),
                CLASS_IN | CLASS_CACHE_FLUSH,
                service.get_host_ttl(),
                address,
            ));
        }
    }

    pub(crate) fn add_question(&mut self, name: &str, qtype: u16) {
        let q = DnsQuestion {
            entry: DnsEntry::new(name.to_string(), qtype, CLASS_IN),
        };
        self.questions.push(q);
    }

    /// Returns a list of actual DNS packet data to be sent on the wire.
    pub(crate) fn to_data_on_wire(&self) -> Vec<Vec<u8>> {
        let packet_list = self.to_packets();
        packet_list.iter().map(|p| p.data.concat()).collect()
    }

    /// Encode self into one or more packets.
    pub(crate) fn to_packets(&self) -> Vec<DnsOutPacket> {
        let mut packet_list = Vec::new();
        let mut packet = DnsOutPacket::new();

        let mut question_count = self.questions.len() as u16;
        let mut answer_count = 0;
        let mut auth_count = 0;
        let mut addi_count = 0;
        let id = if self.multicast { 0 } else { self.id };

        for question in self.questions.iter() {
            packet.write_question(question);
        }

        for (answer, time) in self.answers.iter() {
            if packet.write_record(answer.as_ref(), *time) {
                answer_count += 1;
            }
        }

        for auth in self.authorities.iter() {
            auth_count += u16::from(packet.write_record(auth.as_ref(), 0));
        }

        for addi in self.additionals.iter() {
            if packet.write_record(addi.as_ref(), 0) {
                addi_count += 1;
                continue;
            }

            // No more processing for response packets.
            if self.is_response() {
                break;
            }

            // For query, the current packet exceeds its max size due to known answers,
            // need to truncate.

            // finish the current packet first.
            packet.write_header(
                id,
                self.flags | FLAGS_TC,
                question_count,
                answer_count,
                auth_count,
                addi_count,
            );

            packet_list.push(packet);

            // create a new packet and reset counts.
            packet = DnsOutPacket::new();
            packet.write_record(addi.as_ref(), 0);

            question_count = 0;
            answer_count = 0;
            auth_count = 0;
            addi_count = 1;
        }

        packet.write_header(
            id,
            self.flags,
            question_count,
            answer_count,
            auth_count,
            addi_count,
        );

        packet_list.push(packet);
        packet_list
    }
}

#[derive(Debug)]
pub struct DnsIncoming {
    offset: usize,
    data: Vec<u8>,
    pub(crate) questions: Vec<DnsQuestion>,
    pub(crate) answers: Vec<DnsRecordBox>,
    pub(crate) authorities: Vec<DnsRecordBox>,
    pub(crate) additional: Vec<DnsRecordBox>,
    pub(crate) id: u16,
    flags: u16,
    pub(crate) num_questions: u16,
    pub(crate) num_answers: u16,
    pub(crate) num_authorities: u16,
    pub(crate) num_additionals: u16,
}

impl DnsIncoming {
    pub(crate) fn new(data: Vec<u8>) -> Result<Self> {
        let mut incoming = Self {
            offset: 0,
            data,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
            id: 0,
            flags: 0,
            num_questions: 0,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        };

        /*
        RFC 1035 section 4.1: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
        ...
        All communications inside of the domain protocol are carried in a single
        format called a message.  The top level format of message is divided
        into 5 sections (some of which are empty in certain cases) shown below:

            +---------------------+
            |        Header       |
            +---------------------+
            |       Question      | the question for the name server
            +---------------------+
            |        Answer       | RRs answering the question
            +---------------------+
            |      Authority      | RRs pointing toward an authority
            +---------------------+
            |      Additional     | RRs holding additional information
            +---------------------+
         */
        incoming.read_header()?;
        incoming.read_questions()?;
        incoming.read_answers()?;
        incoming.read_authorities()?;
        incoming.read_additional()?;

        Ok(incoming)
    }

    pub(crate) const fn is_query(&self) -> bool {
        (self.flags & FLAGS_QR_MASK) == FLAGS_QR_QUERY
    }

    pub(crate) const fn is_response(&self) -> bool {
        (self.flags & FLAGS_QR_MASK) == FLAGS_QR_RESPONSE
    }

    fn read_header(&mut self) -> Result<()> {
        if self.data.len() < MSG_HEADER_LEN {
            return Err(Error::Msg(format!(
                "DNS incoming: header is too short: {} bytes",
                self.data.len()
            )));
        }

        let data = &self.data[0..];
        self.id = u16_from_be_slice(&data[..2]);
        self.flags = u16_from_be_slice(&data[2..4]);
        self.num_questions = u16_from_be_slice(&data[4..6]);
        self.num_answers = u16_from_be_slice(&data[6..8]);
        self.num_authorities = u16_from_be_slice(&data[8..10]);
        self.num_additionals = u16_from_be_slice(&data[10..12]);

        self.offset = MSG_HEADER_LEN;

        debug!(
            "read_header: id {}, {} questions {} answers {} authorities {} additionals",
            self.id,
            self.num_questions,
            self.num_answers,
            self.num_authorities,
            self.num_additionals
        );
        Ok(())
    }

    fn read_questions(&mut self) -> Result<()> {
        debug!("read_questions: {}", &self.num_questions);
        for i in 0..self.num_questions {
            let name = self.read_name()?;

            let data = &self.data[self.offset..];
            if data.len() < 4 {
                return Err(Error::Msg(format!(
                    "DNS incoming: question idx {} too short: {}",
                    i,
                    data.len()
                )));
            }
            let ty = u16_from_be_slice(&data[..2]);
            let class = u16_from_be_slice(&data[2..4]);
            self.offset += 4;

            self.questions.push(DnsQuestion {
                entry: DnsEntry::new(name, ty, class),
            });
        }
        Ok(())
    }

    fn read_answers(&mut self) -> Result<()> {
        self.answers = self.read_rr_records(self.num_answers)?;
        Ok(())
    }

    fn read_authorities(&mut self) -> Result<()> {
        self.authorities = self.read_rr_records(self.num_authorities)?;
        Ok(())
    }

    fn read_additional(&mut self) -> Result<()> {
        self.additional = self.read_rr_records(self.num_additionals)?;
        Ok(())
    }

    /// Decodes a sequence of RR records (in answers, authorities and additionals).
    fn read_rr_records(&mut self, count: u16) -> Result<Vec<DnsRecordBox>> {
        debug!("read_rr_records: {}", count);
        let mut rr_records = Vec::new();

        // RFC 1035: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.1
        //
        // All RRs have the same top level format shown below:
        //                               1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                                               |
        // /                                               /
        // /                      NAME                     /
        // |                                               |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      TYPE                     |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                     CLASS                     |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      TTL                      |
        // |                                               |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                   RDLENGTH                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        // /                     RDATA                     /
        // /                                               /
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        // Muse have at least TYPE, CLASS, TTL, RDLENGTH fields: 10 bytes.
        const RR_HEADER_REMAIN: usize = 10;

        for _ in 0..count {
            let name = self.read_name()?;
            let slice = &self.data[self.offset..];

            if slice.len() < RR_HEADER_REMAIN {
                return Err(Error::Msg(format!(
                    "read_others: RR '{}' is too short after name: {} bytes",
                    &name,
                    slice.len()
                )));
            }

            let ty = u16_from_be_slice(&slice[..2]);
            let class = u16_from_be_slice(&slice[2..4]);
            let mut ttl = u32_from_be_slice(&slice[4..8]);
            if ttl == 0 && self.is_response() {
                // RFC 6762 section 10.1:
                // "...Queriers receiving a Multicast DNS response with a TTL of zero SHOULD
                // NOT immediately delete the record from the cache, but instead record
                // a TTL of 1 and then delete the record one second later."
                // See https://datatracker.ietf.org/doc/html/rfc6762#section-10.1

                ttl = 1;
            }
            let rdata_len = u16_from_be_slice(&slice[8..10]) as usize;
            self.offset += RR_HEADER_REMAIN;
            let next_offset = self.offset + rdata_len;

            // Sanity check for RDATA length.
            if next_offset > self.data.len() {
                return Err(Error::Msg(format!(
                    "RR {name} RDATA length {rdata_len} is invalid: remain data len: {}",
                    self.data.len() - self.offset
                )));
            }

            // decode RDATA based on the record type.
            let rec: Option<DnsRecordBox> = match ty {
                TYPE_CNAME | TYPE_PTR => Some(Box::new(DnsPointer::new(
                    &name,
                    ty,
                    class,
                    ttl,
                    self.read_name()?,
                ))),
                TYPE_TXT => Some(Box::new(DnsTxt::new(
                    &name,
                    class,
                    ttl,
                    self.read_vec(rdata_len),
                ))),
                TYPE_SRV => Some(Box::new(DnsSrv::new(
                    &name,
                    class,
                    ttl,
                    self.read_u16()?,
                    self.read_u16()?,
                    self.read_u16()?,
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
                TYPE_A => Some(Box::new(DnsAddress::new(
                    &name,
                    ty,
                    class,
                    ttl,
                    self.read_ipv4().into(),
                ))),
                TYPE_AAAA => Some(Box::new(DnsAddress::new(
                    &name,
                    ty,
                    class,
                    ttl,
                    self.read_ipv6().into(),
                ))),
                TYPE_NSEC => Some(Box::new(DnsNSec::new(
                    &name,
                    class,
                    ttl,
                    self.read_name()?,
                    self.read_type_bitmap()?,
                ))),
                x => {
                    debug!("Unknown DNS record type: {} name: {}", x, &name);
                    self.offset += rdata_len;
                    None
                }
            };

            // sanity check.
            if self.offset != next_offset {
                return Err(Error::Msg(format!(
                    "read_rr_records: decode offset error for RData type {} record: {:?} offset: {} expected offset: {}",
                    ty, &rec, self.offset, next_offset,
                )));
            }

            if let Some(record) = rec {
                debug!("read_rr_records: {:?}", &record);
                rr_records.push(record);
            }
        }

        Ok(rr_records)
    }

    fn read_char_string(&mut self) -> String {
        let length = self.data[self.offset];
        self.offset += 1;
        self.read_string(length as usize)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let slice = &self.data[self.offset..];
        if slice.len() < U16_SIZE {
            return Err(Error::Msg(format!(
                "read_u16: slice len is only {}",
                slice.len()
            )));
        }
        let num = u16_from_be_slice(&slice[..U16_SIZE]);
        self.offset += U16_SIZE;
        Ok(num)
    }

    /// Reads the "Type Bit Map" block for a DNS NSEC record.
    fn read_type_bitmap(&mut self) -> Result<Vec<u8>> {
        // From RFC 6762: 6.1.  Negative Responses
        // https://datatracker.ietf.org/doc/html/rfc6762#section-6.1
        //   o The Type Bit Map block number is 0.
        //   o The Type Bit Map block length byte is a value in the range 1-32.
        //   o The Type Bit Map data is 1-32 bytes, as indicated by length
        //     byte.
        let block_num = self.data[self.offset];
        self.offset += 1;
        if block_num != 0 {
            return Err(Error::Msg(format!(
                "NSEC block number is not 0: {}",
                block_num
            )));
        }

        let block_len = self.data[self.offset] as usize;
        if !(1..=32).contains(&block_len) {
            return Err(Error::Msg(format!(
                "NSEC block length must be in the range 1-32: {}",
                block_len
            )));
        }
        self.offset += 1;

        let end = self.offset + block_len;
        if end > self.data.len() {
            return Err(Error::Msg(format!(
                "NSEC block overflow: {} over RData len {}",
                end,
                self.data.len()
            )));
        }
        let bitmap = self.data[self.offset..end].to_vec();
        self.offset += block_len;

        Ok(bitmap)
    }

    fn read_vec(&mut self, length: usize) -> Vec<u8> {
        let v = self.data[self.offset..self.offset + length].to_vec();
        self.offset += length;
        v
    }

    fn read_ipv4(&mut self) -> Ipv4Addr {
        let bytes: [u8; 4] = (&self.data)[self.offset..self.offset + 4]
            .try_into()
            .unwrap();
        self.offset += bytes.len();
        Ipv4Addr::from(bytes)
    }

    fn read_ipv6(&mut self) -> Ipv6Addr {
        let bytes: [u8; 16] = (&self.data)[self.offset..self.offset + 16]
            .try_into()
            .unwrap();
        self.offset += bytes.len();
        Ipv6Addr::from(bytes)
    }

    fn read_string(&mut self, length: usize) -> String {
        let s = str::from_utf8(&self.data[self.offset..self.offset + length]).unwrap();
        self.offset += length;
        s.to_string()
    }

    /// Reads a domain name at the current location of `self.data`.
    ///
    /// See https://datatracker.ietf.org/doc/html/rfc1035#section-3.1 for
    /// domain name encoding.
    fn read_name(&mut self) -> Result<String> {
        let data = &self.data[..];
        let start_offset = self.offset;
        let mut offset = start_offset;
        let mut name = "".to_string();
        let mut at_end = false;

        // From RFC1035:
        // "...Domain names in messages are expressed in terms of a sequence of labels.
        // Each label is represented as a one octet length field followed by that
        // number of octets."
        //
        // "...The compression scheme allows a domain name in a message to be
        // represented as either:
        // - a sequence of labels ending in a zero octet
        // - a pointer
        // - a sequence of labels ending with a pointer"
        loop {
            if offset >= data.len() {
                return Err(Error::Msg(format!(
                    "read_name: offset: {} data len {}. DnsIncoming: {:?}",
                    offset,
                    data.len(),
                    self
                )));
            }
            let length = data[offset];

            // From RFC1035:
            // "...Since every domain name ends with the null label of
            // the root, a domain name is terminated by a length byte of zero."
            if length == 0 {
                if !at_end {
                    self.offset = offset + 1;
                }
                break; // The end of the name
            }

            // Check the first 2 bits for possible "Message compression".
            match length & 0xC0 {
                0x00 => {
                    // regular utf8 string with length
                    offset += 1;
                    let ending = offset + length as usize;

                    // Never read beyond the whole data length.
                    if ending > data.len() {
                        return Err(Error::Msg(format!(
                            "read_name: ending {} exceeds data length {}",
                            ending,
                            data.len()
                        )));
                    }

                    name += str::from_utf8(&data[offset..ending])
                        .map_err(|e| Error::Msg(format!("read_name: from_utf8: {}", e)))?;
                    name += ".";
                    offset += length as usize;
                }
                0xC0 => {
                    // Message compression.
                    // See https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
                    let slice = &data[offset..];
                    if slice.len() < U16_SIZE {
                        return Err(Error::Msg(format!(
                            "read_name: u16 slice len is only {}",
                            slice.len()
                        )));
                    }
                    let pointer = (u16_from_be_slice(slice) ^ 0xC000) as usize;
                    if pointer >= start_offset {
                        // Error: could trigger an infinite loop.
                        return Err(Error::Msg(format!(
                            "Invalid name compression: pointer {} must be less than the start offset {}",
                            &pointer, &start_offset
                        )));
                    }

                    // A pointer marks the end of a domain name.
                    if !at_end {
                        self.offset = offset + U16_SIZE;
                        at_end = true;
                    }
                    offset = pointer;
                }
                _ => {
                    return Err(Error::Msg(format!(
                        "Bad name with invalid length: 0x{:x} offset {}, data (so far): {:x?}",
                        length,
                        offset,
                        &data[..offset]
                    )));
                }
            };
        }

        Ok(name)
    }
}

/// Returns a tuple of (service_type_domain, optional_sub_domain)
pub fn split_sub_domain(domain: &str) -> (&str, Option<&str>) {
    if let Some((_, ty_domain)) = domain.rsplit_once("._sub.") {
        (ty_domain, Some(domain))
    } else {
        (domain, None)
    }
}

/// Returns UNIX time in millis
pub fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("failed to get current UNIX time")
        .as_millis() as u64
}

const fn u16_from_be_slice(bytes: &[u8]) -> u16 {
    let u8_array: [u8; 2] = [bytes[0], bytes[1]];
    u16::from_be_bytes(u8_array)
}

const fn u32_from_be_slice(s: &[u8]) -> u32 {
    let u8_array: [u8; 4] = [s[0], s[1], s[2], s[3]];
    u32::from_be_bytes(u8_array)
}

/// Returns the UNIX time in millis at which this record will have expired
/// by a certain percentage.
const fn get_expiration_time(created: u64, ttl: u32, percent: u32) -> u64 {
    // 'created' is in millis, 'ttl' is in seconds, hence:
    // ttl * 1000 * (percent / 100) => ttl * percent * 10
    created + (ttl * percent * 10) as u64
}

#[cfg(test)]
mod tests {
    use std::iter::repeat_with;

    use super::{
        current_time_millis, get_expiration_time, DnsIncoming, DnsNSec, DnsOutgoing, DnsPointer,
        DnsRecordExt, DnsSrv, DnsTxt, CLASS_CACHE_FLUSH, CLASS_IN, FLAGS_QR_QUERY,
        FLAGS_QR_RESPONSE, MSG_HEADER_LEN, TYPE_A, TYPE_AAAA, TYPE_PTR,
    };

    #[test]
    fn test_read_name_invalid_length() {
        let name = "test_read";
        let mut out = DnsOutgoing::new(FLAGS_QR_QUERY);
        out.add_question(name, TYPE_PTR);
        let data = out.to_data_on_wire().remove(0);

        // construct invalid data.
        let max_len = data.len() as u8;
        let mut data_with_invalid_name_length = data.clone();
        let mut data_with_larger_name_length = data.clone();
        let name_length_offset = 12;

        // 0x9 is the length of `name`
        // 0x80 (0b1000_0000) has two leading bits `10`, which is invalid.
        data_with_invalid_name_length[name_length_offset] = 0x9 | 0b1000_0000;

        // The original data is fine.
        let incoming = DnsIncoming::new(data);
        assert!(incoming.is_ok());

        // The data with invalid name length is not fine.
        let invalid = DnsIncoming::new(data_with_invalid_name_length);
        assert!(invalid.is_err());
        if let Err(e) = invalid {
            println!("error: {}", e);
        }

        // Another error case: `length`` is larger than the actual string length.
        data_with_larger_name_length[name_length_offset] = max_len + 1;
        let invalid = DnsIncoming::new(data_with_larger_name_length);
        assert!(invalid.is_err());
        if let Err(e) = invalid {
            println!("error: {}", e);
        }
    }

    // `read_name` must not go into an infinite loop when the data is corrupted
    // with a "name compression loop".
    #[test]
    fn test_read_name_compression_loop() {
        let name = "test_loop";
        let mut out = DnsOutgoing::new(FLAGS_QR_QUERY);
        out.add_question(name, TYPE_PTR);
        let mut data = out.to_data_on_wire().remove(0);

        let name_length_offset = 12; // start of the name in the message.

        // The "name" terminates with a "length 0" byte.
        // Note that the "name length" itself is one byte.
        let zero_length_offset = name_length_offset + 1 + name.len();

        // Verify the "name length" byte and the "length 0" byte.
        assert_eq!(data[name_length_offset], name.len() as u8);
        assert_eq!(data[zero_length_offset], 0);

        // Modify `data` to create a "name compression loop":
        //
        // Changing the "length 0" byte into a "pointer" byte,
        // followed by the "offset pointed" byte.
        data[zero_length_offset] = 0b1100_0000; // first two bits indicates a "pointer"
        data[zero_length_offset + 1] = name_length_offset as u8; // points back to "name"

        let result = DnsIncoming::new(data);
        assert!(result.is_err());
        if let Err(e) = result {
            println!("Error: {}", e);
        }
    }

    /// Tests DnsIncoming::read_others()
    #[test]
    fn test_rr_too_short_after_name() {
        let name = "test_rr_too_short._udp.local.";
        let mut response = DnsOutgoing::new(FLAGS_QR_RESPONSE);
        response.add_additional_answer(DnsSrv::new(
            name,
            CLASS_IN | CLASS_CACHE_FLUSH,
            1,
            1,
            1,
            9000,
            "instance1".to_string(),
        ));
        let data = response.to_data_on_wire().remove(0);
        let mut data_too_short = data.clone();

        // verify the original data is good.
        let incoming = DnsIncoming::new(data);
        assert!(incoming.is_ok());

        // verify that truncated data will cause an error.
        data_too_short.truncate(MSG_HEADER_LEN + name.len() + 2);
        let invalid = DnsIncoming::new(data_too_short);
        assert!(invalid.is_err());
        if let Err(e) = invalid {
            println!("error: {}", e);
        }
    }

    #[test]
    fn test_rr_read_u16_error() {
        let name = "rr_read_u16_err._udp.local.";
        let host = "read_u16_err_host";
        let mut response = DnsOutgoing::new(FLAGS_QR_RESPONSE);
        response.add_additional_answer(DnsSrv::new(
            name,
            CLASS_IN | CLASS_CACHE_FLUSH,
            1,
            1,
            1,
            9000,
            host.to_string(),
        ));
        let data = response.to_data_on_wire().remove(0);
        let data_len = data.len();
        let mut data_too_short = data.clone();

        // verify the original data is good.
        let incoming = DnsIncoming::new(data);
        assert!(incoming.is_ok());

        // Truncate the 'host' and its associated bytes (length byte, ending null byte),
        // and one more byte off to create an invalid u16.
        data_too_short.truncate(data_len - host.len() - 3);
        let invalid = DnsIncoming::new(data_too_short);

        // Verify the error of decoding.
        assert!(invalid.is_err());
        if let Err(e) = invalid {
            println!("error: {e}");
        }
    }

    #[test]
    fn test_rr_read_vec_error() {
        let mut response = DnsOutgoing::new(FLAGS_QR_RESPONSE);
        let name = "rr_read_vec_err._udp.local.";
        let text = "greeting=hello".as_bytes().to_vec();

        response.add_additional_answer(DnsTxt::new(name, CLASS_IN | CLASS_CACHE_FLUSH, 1, text));

        let data = response.to_data_on_wire().remove(0);
        let data_len = data.len();
        let mut data_too_short = data.clone();

        // verify the original response data is good.
        let incoming = DnsIncoming::new(data);
        assert!(incoming.is_ok());

        // Truncate the data to mimic invalid length.
        data_too_short.truncate(data_len - 5);
        let invalid = DnsIncoming::new(data_too_short);

        // Verify the error of decoding.
        assert!(invalid.is_err());
        if let Err(e) = invalid {
            println!("error: {e}");
        }
    }

    #[test]
    fn test_rr_rand_data_error() {
        const DATA_LEN_MAX: usize = 2048;
        const TEST_TIMES: usize = 100000;

        for _ in 0..TEST_TIMES {
            // Generate a random length of data
            let data_len = fastrand::usize(0..DATA_LEN_MAX);

            // Generate random data
            let rand_data: Vec<u8> = repeat_with(|| fastrand::u8(..)).take(data_len).collect();

            // Decode rand data, it should not panic
            let _ = DnsIncoming::new(rand_data);
        }
    }

    #[test]
    fn test_dns_nsec() {
        let name = "instance1._nsec_test._udp.local.";
        let next_domain = name.to_string();
        let type_bitmap = vec![64, 0, 0, 8]; // Two bits set to '1': bit 1 and bit 28.
        let nsec = DnsNSec::new(
            name,
            CLASS_IN | CLASS_CACHE_FLUSH,
            1,
            next_domain,
            type_bitmap,
        );
        let absent_types = nsec._types();
        assert_eq!(absent_types.len(), 2);
        assert_eq!(absent_types[0], TYPE_A);
        assert_eq!(absent_types[1], TYPE_AAAA);
    }

    #[test]
    fn test_refresh_maybe() {
        let name = "test_refresh._udp.local.";
        let ttl = 2;
        let hostname = "instance1.local.";
        let mut srv = DnsSrv::new(name, CLASS_IN, ttl, 0, 0, 0, hostname.to_string());

        // refresh is not due yet.
        let now = current_time_millis();
        let refreshed = srv.get_record_mut().refresh_maybe(now);
        assert!(!refreshed);

        // sleep for 80 percent of TTL in millis to reach "refresh" time.
        let sleep_in_mills = (ttl * 80 * 10) as u64;
        std::thread::sleep(std::time::Duration::from_millis(sleep_in_mills));

        // refresh is due.
        let now = current_time_millis();
        let refreshed = srv.get_record_mut().refresh_maybe(now);
        assert!(refreshed);

        // refresh time is updated.
        let dns_record = srv.get_record();
        let new_refresh = get_expiration_time(dns_record.get_created(), dns_record.ttl, 85);
        assert_eq!(new_refresh, dns_record.get_refresh_time());
    }

    #[test]
    fn test_packet_size() {
        let mut outgoing = DnsOutgoing::new(FLAGS_QR_QUERY);
        outgoing.add_question("test_packet_size", TYPE_PTR);

        let packet = outgoing.to_packets().remove(0);
        println!("packet size: {}", packet.size);
        let data = packet.data.concat();
        println!("data size: {}", data.len());

        assert_eq!(packet.size, data.len());
    }

    #[test]
    fn test_querier_known_answer_multi_packet() {
        let mut query = DnsOutgoing::new(FLAGS_QR_QUERY);
        let name = "test_multi_packet._udp.local.";
        query.add_question(name, TYPE_PTR);

        let known_answer_count = 400;
        for i in 0..known_answer_count {
            let alias = format!("instance{}.{}", i, name);
            let answer = DnsPointer::new(name, TYPE_PTR, CLASS_IN, 0, alias);
            query.add_additional_answer(answer);
        }

        let mut packets = query.to_data_on_wire();
        println!("packets count: {}", packets.len());
        assert_eq!(packets.len(), 2);

        let first_packet = packets.remove(0);
        println!("first packet size: {}", first_packet.len());

        let incoming1 = DnsIncoming::new(first_packet).unwrap();
        println!(
            "first packet know answer count: {}, question count: {}",
            incoming1.num_additionals, incoming1.num_questions
        );

        let second_packet = packets.remove(0);
        println!("second packet size: {}", second_packet.len());

        let incoming2 = DnsIncoming::new(second_packet).unwrap();
        println!(
            "second packet known answer count: {}, question count: {}",
            incoming2.num_additionals, incoming2.num_questions
        );

        assert_eq!(
            incoming1.num_additionals + incoming2.num_additionals,
            known_answer_count
        );

        assert_eq!(incoming1.num_questions, 1);
        assert_eq!(incoming2.num_questions, 0);
    }
}
