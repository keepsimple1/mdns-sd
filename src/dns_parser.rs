//! DNS parsing utility.
//!
//! [DnsIncoming] is the logic representation of an incoming DNS packet.
//! [DnsOutgoing] is the logic representation of an outgoing DNS packet.
//! [DnsOutPacket] is the encoded packet for [DnsOutgoing].

#[cfg(feature = "logging")]
use crate::log::debug;
use crate::{Error, Result, ServiceInfo};
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

pub(crate) const TYPE_A: u16 = 1; // IPv4 address
pub(crate) const TYPE_CNAME: u16 = 5;
pub(crate) const TYPE_PTR: u16 = 12;
pub(crate) const TYPE_HINFO: u16 = 13;
pub(crate) const TYPE_TXT: u16 = 16;
pub(crate) const TYPE_AAAA: u16 = 28; // IPv6 address
pub(crate) const TYPE_SRV: u16 = 33;
pub(crate) const TYPE_ANY: u16 = 255;

pub(crate) const CLASS_IN: u16 = 1;
pub(crate) const CLASS_MASK: u16 = 0x7FFF;
pub(crate) const CLASS_UNIQUE: u16 = 0x8000;

pub(crate) const MAX_MSG_ABSOLUTE: usize = 8966;

// Definitions for DNS message header "flags" field
//
// The "flags" field is 16-bit long, in this format:
// (RFC 1035 section 4.1.1)
//
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//
pub(crate) const FLAGS_QR_MASK: u16 = 0x8000; // mask for query/response bit
pub(crate) const FLAGS_QR_QUERY: u16 = 0x0000;
pub(crate) const FLAGS_QR_RESPONSE: u16 = 0x8000;
pub(crate) const FLAGS_AA: u16 = 0x0400; // mask for Authoritative answer bit

pub(crate) type DnsRecordBox = Box<dyn DnsRecordExt + Send>;

#[derive(PartialEq, Debug)]
pub(crate) struct DnsEntry {
    pub(crate) name: String, // always lower case.
    pub(crate) ty: u16,
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
pub(crate) struct DnsQuestion {
    pub(crate) entry: DnsEntry,
}

/// A DNS Resource Record - like a DNS entry, but has a TTL.
/// RFC: https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1
///      https://www.rfc-editor.org/rfc/rfc1035#section-4.1.3
#[derive(Debug)]
pub(crate) struct DnsRecord {
    pub(crate) entry: DnsEntry,
    ttl: u32,     // in seconds, 0 means this record should not be cached
    created: u64, // UNIX time in millis
    expires: u64, // expires at this UNIX time in millis

    /// Support re-query an instance before its PTR record expires.
    /// See https://datatracker.ietf.org/doc/html/rfc6762#section-5.2
    refresh: u64, // UNIX time in millis
}

impl DnsRecord {
    fn new(name: &str, ty: u16, class: u16, ttl: u32) -> Self {
        let created = current_time_millis();
        let refresh = get_expiration_time(created, ttl, 80);
        let expires = get_expiration_time(created, ttl, 100);
        Self {
            entry: DnsEntry::new(name.to_string(), ty, class),
            ttl,
            created,
            expires,
            refresh,
        }
    }

    pub(crate) fn get_created(&self) -> u64 {
        self.created
    }

    pub(crate) fn get_expire_time(&self) -> u64 {
        self.expires
    }

    pub(crate) fn get_refresh_time(&self) -> u64 {
        self.refresh
    }

    pub(crate) fn is_expired(&self, now: u64) -> bool {
        now >= self.expires
    }

    pub(crate) fn refresh_due(&self, now: u64) -> bool {
        now >= self.refresh
    }

    /// Updates the refresh time to be the same as the expire time so that
    /// this record will not refresh again and will just expire.
    pub(crate) fn refresh_no_more(&mut self) {
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
        self.expires = get_expiration_time(self.created, self.ttl, 100);
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
pub(crate) struct DnsAddress {
    pub(crate) record: DnsRecord,
    pub(crate) address: IpAddr,
}

impl DnsAddress {
    pub(crate) fn new(name: &str, ty: u16, class: u16, ttl: u32, address: IpAddr) -> Self {
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
        match self.address {
            IpAddr::V4(addr) => packet.write_bytes(addr.octets().as_ref()),
            IpAddr::V6(addr) => packet.write_bytes(addr.octets().as_ref()),
        };
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
pub(crate) struct DnsPointer {
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
        if let Some(other_ptr) = other.any().downcast_ref::<DnsPointer>() {
            return self.alias == other_ptr.alias && self.record.entry == other_ptr.record.entry;
        }
        false
    }
}

// In common cases, there is one and only one SRV record for a particular fullname.
#[derive(Debug)]
pub(crate) struct DnsSrv {
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
pub(crate) struct DnsTxt {
    pub(crate) record: DnsRecord,
    pub(crate) text: Vec<u8>,
}

impl DnsTxt {
    pub(crate) fn new(name: &str, ty: u16, class: u16, ttl: u32, text: Vec<u8>) -> Self {
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

#[derive(PartialEq)]
enum PacketState {
    Init = 0,
    Finished = 1,
}

pub(crate) struct DnsOutPacket {
    pub(crate) data: Vec<Vec<u8>>,
    size: usize,
    state: PacketState,
    names: HashMap<String, u16>, // k: name, v: offset
}

impl DnsOutPacket {
    pub(crate) fn new() -> Self {
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

/// Representation of an outgoing packet. The actual encoded packet
/// is [DnsOutPacket].
pub(crate) struct DnsOutgoing {
    flags: u16,
    pub(crate) id: u16,
    multicast: bool,
    pub(crate) questions: Vec<DnsQuestion>,
    pub(crate) answers: Vec<(Box<dyn DnsRecordExt>, u64)>,
    pub(crate) authorities: Vec<DnsPointer>,
    pub(crate) additionals: Vec<DnsRecordBox>,
}

impl DnsOutgoing {
    pub(crate) fn new(flags: u16) -> Self {
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

    pub(crate) fn is_query(&self) -> bool {
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
    pub(crate) fn add_additional_answer(&mut self, answer: DnsRecordBox) {
        debug!("add_additional_answer: {:?}", &answer);
        self.additionals.push(answer);
    }

    /// Returns true if `answer` is added to the outgoing msg.
    /// Returns false if `answer` was not added as it expired or suppressed by the incoming `msg`.
    pub(crate) fn add_answer(&mut self, msg: &DnsIncoming, answer: Box<dyn DnsRecordExt>) -> bool {
        debug!("Check for add_answer");
        if !answer.suppressed_by(msg) {
            return self.add_answer_at_time(answer, 0);
        }
        false
    }

    /// Returns true if `answer` is added to the outgoing msg.
    /// Returns false if the answer is expired `now` hence not added.
    /// If `now` is 0, do not check if the answer expires.
    pub(crate) fn add_answer_at_time(&mut self, answer: Box<dyn DnsRecordExt>, now: u64) -> bool {
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
            Box::new(DnsPointer::new(
                service.get_type(),
                TYPE_PTR,
                CLASS_IN,
                service.get_other_ttl(),
                service.get_fullname().to_string(),
            )),
        );

        if !ptr_added {
            debug!("answer was not added for msg {:?}", msg);
            return;
        }

        if let Some(sub) = service.get_subtype() {
            debug!("Adding subdomain {}", sub);
            self.add_additional_answer(Box::new(DnsPointer::new(
                sub,
                TYPE_PTR,
                CLASS_IN,
                service.get_other_ttl(),
                service.get_fullname().to_string(),
            )));
        }

        // Add recommended additional answers according to
        // https://tools.ietf.org/html/rfc6763#section-12.1.
        self.add_additional_answer(Box::new(DnsSrv::new(
            service.get_fullname(),
            CLASS_IN | CLASS_UNIQUE,
            service.get_host_ttl(),
            service.get_priority(),
            service.get_weight(),
            service.get_port(),
            service.get_hostname().to_string(),
        )));

        self.add_additional_answer(Box::new(DnsTxt::new(
            service.get_fullname(),
            TYPE_TXT,
            CLASS_IN | CLASS_UNIQUE,
            service.get_host_ttl(),
            service.generate_txt(),
        )));

        for address in intf_addrs {
            let t = match address {
                IpAddr::V4(_) => TYPE_A,
                IpAddr::V6(_) => TYPE_AAAA,
            };

            self.add_additional_answer(Box::new(DnsAddress::new(
                service.get_hostname(),
                t,
                CLASS_IN | CLASS_UNIQUE,
                service.get_host_ttl(),
                address,
            )));
        }
    }

    pub(crate) fn add_question(&mut self, name: &str, qtype: u16) {
        let q = DnsQuestion {
            entry: DnsEntry::new(name.to_string(), qtype, CLASS_IN),
        };
        self.questions.push(q);
    }

    pub(crate) fn to_packet_data(&self) -> Vec<u8> {
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
                auth_count += u16::from(packet.write_record(auth, 0));
            }

            let mut addi_count = 0;
            for addi in self.additionals.iter() {
                addi_count += u16::from(packet.write_record(addi.as_ref(), 0));
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

        packet.data.concat()
    }
}

#[derive(Debug)]
pub(crate) struct DnsIncoming {
    offset: usize,
    data: Vec<u8>,
    pub(crate) questions: Vec<DnsQuestion>,
    /// This field includes records in the `answers` section
    /// and in the `additionals` section.
    pub(crate) answers: Vec<DnsRecordBox>,
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
            id: 0,
            flags: 0,
            num_questions: 0,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        };

        incoming.read_header()?;
        incoming.read_questions()?;
        incoming.read_others()?;
        Ok(incoming)
    }

    pub(crate) fn is_query(&self) -> bool {
        (self.flags & FLAGS_QR_MASK) == FLAGS_QR_QUERY
    }

    pub(crate) fn is_response(&self) -> bool {
        (self.flags & FLAGS_QR_MASK) == FLAGS_QR_RESPONSE
    }

    fn read_header(&mut self) -> Result<()> {
        if self.data.len() < 12 {
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

        self.offset = 12;

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

    /// Decodes all answers, authorities and additionals.
    fn read_others(&mut self) -> Result<()> {
        let n = self.num_answers + self.num_authorities + self.num_additionals;
        debug!("read_others: {}", n);

        // RFC 1035: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.1
        //
        // All RRs have the same top level format shown below:
        //         1  1  1  1  1  1
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

        for _ in 0..n {
            let name = self.read_name()?;
            let slice = &self.data[self.offset..];
            let ty = u16_from_be_slice(&slice[..2]);
            let class = u16_from_be_slice(&slice[2..4]);
            let ttl = u32_from_be_slice(&slice[4..8]);
            let length = u16_from_be_slice(&slice[8..10]) as usize;
            self.offset += 10;
            let next_offset = self.offset + length;

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
                _ => {
                    debug!("Unknown DNS record type");
                    self.offset += length;
                    None
                }
            };

            // sanity check.
            if self.offset != next_offset {
                return Err(Error::Msg(format!(
                    "read_others: decode offset error for RData type {} record: {:?} offset: {} expected offset: {}",
                    ty, &rec, self.offset, next_offset,
                )));
            }

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
        let mut offset = self.offset;
        let mut name = "".to_string();
        let mut at_end = false;

        // From RFC1035:
        // "...Domain names in messages are expressed in terms of a sequence of labels.
        // Each label is represented as a one octet length field followed by that
        // number of octets."
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
                    name += str::from_utf8(&data[offset..(offset + length as usize)])
                        .map_err(|e| Error::Msg(format!("read_name: from_utf8: {}", e)))?;
                    name += ".";
                    offset += length as usize;
                }
                0xC0 => {
                    // Message compression.
                    // See https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
                    let pointer = (u16_from_be_slice(&data[offset..]) ^ 0xC000) as usize;
                    if pointer >= offset {
                        return Err(Error::Msg(format!(
                            "Bad name with invalid message compression: pointer {} offset {} data (so far): {:x?}",
                            &pointer, &offset, &data[..offset]
                        )));
                    }

                    if !at_end {
                        self.offset = offset + 2;
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

/// Returns UNIX time in millis
pub(crate) fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("failed to get current UNIX time")
        .as_millis() as u64
}

fn u16_from_be_slice(bytes: &[u8]) -> u16 {
    let u8_array: [u8; 2] = [bytes[0], bytes[1]];
    u16::from_be_bytes(u8_array)
}

fn u32_from_be_slice(s: &[u8]) -> u32 {
    let u8_array: [u8; 4] = [s[0], s[1], s[2], s[3]];
    u32::from_be_bytes(u8_array)
}

/// Returns the time in millis at which this record will have expired
/// by a certain percentage.
fn get_expiration_time(created: u64, ttl: u32, percent: u32) -> u64 {
    created + (ttl * percent * 10) as u64
}

#[cfg(test)]
mod tests {
    use super::{DnsIncoming, DnsOutgoing, FLAGS_QR_QUERY, TYPE_PTR};

    #[test]
    fn test_read_name_invalid_length() {
        let name = "test_read";
        let mut out = DnsOutgoing::new(FLAGS_QR_QUERY);
        out.add_question(name, TYPE_PTR);
        let data = out.to_packet_data();

        // construct invalid data.
        let mut data_with_invalid_name_length = data.clone();
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
    }
}
