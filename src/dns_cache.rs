//! A cache for DNS records.
//!
//! This is an internal implementation, not visible to the public API.

use crate::dns_parser::{
    current_time_millis, split_sub_domain, DnsAddress, DnsPointer, DnsRecordBox, DnsSrv, TYPE_A,
    TYPE_AAAA, TYPE_NSEC, TYPE_PTR, TYPE_SRV, TYPE_TXT,
};
#[cfg(feature = "logging")]
use crate::log::debug;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

/// A cache for all types of DNS records.
pub(crate) struct DnsCache {
    /// DnsPointer records indexed by ty_domain
    ptr: HashMap<String, Vec<DnsRecordBox>>,

    /// DnsSrv records indexed by the fullname of an instance
    srv: HashMap<String, Vec<DnsRecordBox>>,

    /// DnsTxt records indexed by the fullname of an instance
    txt: HashMap<String, Vec<DnsRecordBox>>,

    /// DnsAddr records indexed by the hostname
    addr: HashMap<String, Vec<DnsRecordBox>>,

    /// A reverse lookup table from "instance fullname" to "subtype PTR name"
    subtype: HashMap<String, String>,

    /// Negative responses:
    /// A map from "instance fullname" to DnsNSec.
    nsec: HashMap<String, Vec<DnsRecordBox>>,
}

impl DnsCache {
    pub(crate) fn new() -> Self {
        Self {
            ptr: HashMap::new(),
            srv: HashMap::new(),
            txt: HashMap::new(),
            addr: HashMap::new(),
            subtype: HashMap::new(),
            nsec: HashMap::new(),
        }
    }

    pub(crate) fn all_ptr(&self) -> &HashMap<String, Vec<DnsRecordBox>> {
        &self.ptr
    }

    pub(crate) fn get_ptr(&self, ty_domain: &str) -> Option<&Vec<DnsRecordBox>> {
        self.ptr.get(ty_domain)
    }

    pub(crate) fn get_srv(&self, fullname: &str) -> Option<&Vec<DnsRecordBox>> {
        self.srv.get(fullname)
    }

    pub(crate) fn get_txt(&self, fullname: &str) -> Option<&Vec<DnsRecordBox>> {
        self.txt.get(fullname)
    }

    pub(crate) fn get_addr(&self, hostname: &str) -> Option<&Vec<DnsRecordBox>> {
        self.addr.get(hostname)
    }

    /// A reverse lookup table from "instance fullname" to "subtype PTR name"
    pub(crate) fn get_subtype(&self, fullname: &str) -> Option<&String> {
        self.subtype.get(fullname)
    }

    /// Returns the list of instances that has `host` as its hostname.
    pub(crate) fn get_instances_on_host(&self, host: &str) -> Vec<String> {
        self.srv
            .iter()
            .filter_map(|(instance, srv_list)| {
                if let Some(item) = srv_list.first() {
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

    /// Returns the set of IP addresses for a hostname.
    pub(crate) fn get_addresses_for_host(&self, host: &str) -> HashSet<IpAddr> {
        self.addr
            .get(host)
            .into_iter()
            .flatten()
            .filter_map(|record| {
                record
                    .any()
                    .downcast_ref::<DnsAddress>()
                    .map(|addr| addr.address)
            })
            .collect()
    }

    /// Update a DNSRecord TTL if already exists, otherwise insert a new record.
    ///
    /// Returns `None` if `incoming` is invalid / unrecognized, otherwise returns
    /// (a new record, true) or (existing record with TTL updated, false).
    pub(crate) fn add_or_update(
        &mut self,
        incoming: DnsRecordBox,
    ) -> Option<(&DnsRecordBox, bool)> {
        let entry_name = incoming.get_name().to_string();

        // If it is PTR with subtype, store a mapping from the instance fullname
        // to the subtype in this cache.
        if incoming.get_type() == TYPE_PTR {
            let (_, subtype_opt) = split_sub_domain(&entry_name);
            if let Some(subtype) = subtype_opt {
                if let Some(ptr) = incoming.any().downcast_ref::<DnsPointer>() {
                    if !self.subtype.contains_key(&ptr.alias) {
                        self.subtype.insert(ptr.alias.clone(), subtype.to_string());
                    }
                }
            }
        }

        // get the existing records for the type.
        let record_vec = match incoming.get_type() {
            TYPE_PTR => self.ptr.entry(entry_name).or_default(),
            TYPE_SRV => self.srv.entry(entry_name).or_default(),
            TYPE_TXT => self.txt.entry(entry_name).or_default(),
            TYPE_A | TYPE_AAAA => self.addr.entry(entry_name).or_default(),
            TYPE_NSEC => self.nsec.entry(entry_name).or_default(),
            _ => return None,
        };

        if incoming.get_cache_flush() {
            let now = current_time_millis();
            let class = incoming.get_class();
            let rtype = incoming.get_type();

            record_vec.iter_mut().for_each(|r| {
                // When cache flush is asked, we set expire date to 1 second in the future if:
                // - The record has the same rclass
                // - The record was created more than 1 second ago.
                // - The record expire is more than 1 second away.
                // Ref: RFC 6762 Section 10.2
                //
                // Note: when the updated record actually expires, it will trigger events properly.
                if class == r.get_class()
                    && rtype == r.get_type()
                    && now > r.get_created() + 1000
                    && r.get_expire() > now + 1000
                {
                    debug!("FLUSH one record: {:?}", &r);
                    r.set_expire(now + 1000);
                }
            });
        }

        // update TTL for existing record or create a new record.
        let (idx, updated) = match record_vec
            .iter_mut()
            .enumerate()
            .find(|(_idx, r)| r.matches(incoming.as_ref()))
        {
            Some((i, r)) => {
                // It is possible that this record was just updated in cache_flush
                // processing. That's okay. We can still reset here.
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
    pub(crate) fn remove(&mut self, record: &DnsRecordBox) -> bool {
        let mut found = false;
        let record_name = record.get_name();
        let record_vec = match record.get_type() {
            TYPE_PTR => self.ptr.get_mut(record_name),
            TYPE_SRV => self.srv.get_mut(record_name),
            TYPE_TXT => self.txt.get_mut(record_name),
            TYPE_A | TYPE_AAAA => self.addr.get_mut(record_name),
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

    /// Iterates all ADDR records and remove ones that expired.
    /// Returns the expired ones in a map of names and addresses.
    pub(crate) fn evict_expired_addr(&mut self, now: u64) -> HashMap<String, HashSet<IpAddr>> {
        let mut removed = HashMap::new();

        for records in self.addr.values_mut() {
            records.retain(|addr| {
                let expired = addr.get_record().is_expired(now);
                if expired {
                    if let Some(addr_record) = addr.any().downcast_ref::<DnsAddress>() {
                        removed
                            .entry(addr.get_name().to_string())
                            .or_insert_with(HashSet::new)
                            .insert(addr_record.address);
                    }
                }
                !expired
            })
        }

        removed
    }

    /// Evicts expired PTR and SRV, TXT records for each ty_domain in the cache, and
    /// returns the set of expired instance names for each ty_domain.
    ///
    /// An instance in the returned set indicates its PTR and/or SRV record has expired.
    pub(crate) fn evict_expired_services(&mut self, now: u64) -> HashMap<String, HashSet<String>> {
        let mut expired_instances = HashMap::new();

        // Check all ty_domain in the cache by following all PTR records, regardless
        // if the ty_domain is actively queried or not.
        for (ty_domain, ptr_records) in self.ptr.iter_mut() {
            for ptr in ptr_records.iter() {
                if let Some(dns_ptr) = ptr.any().downcast_ref::<DnsPointer>() {
                    let instance_name = &dns_ptr.alias;

                    // evict expired SRV records of this instance
                    if let Some(srv_records) = self.srv.get_mut(instance_name) {
                        srv_records.retain(|srv| {
                            let expired = srv.get_record().is_expired(now);
                            if expired {
                                debug!("expired SRV: {}: {}", ty_domain, srv.get_name());
                                expired_instances
                                    .entry(ty_domain.to_string())
                                    .or_insert_with(HashSet::new)
                                    .insert(srv.get_name().to_string());
                            }
                            !expired
                        });
                    }

                    // evict expired TXT records of this instance
                    if let Some(txt_records) = self.txt.get_mut(instance_name) {
                        txt_records.retain(|txt| !txt.get_record().is_expired(now))
                    }
                }
            }

            // evict expired PTR records
            ptr_records.retain(|x| {
                let expired = x.get_record().is_expired(now);
                if expired {
                    if let Some(dns_ptr) = x.any().downcast_ref::<DnsPointer>() {
                        debug!("expired PTR: {:?}", dns_ptr);
                        expired_instances
                            .entry(ty_domain.to_string())
                            .or_insert_with(HashSet::new)
                            .insert(dns_ptr.alias.clone());
                    }
                }
                !expired
            });
        }

        expired_instances
    }

    /// Checks refresh due for PTR records of `ty_domain`.
    /// Returns all updated refresh time.
    pub(crate) fn refresh_due_ptr(&mut self, ty_domain: &str) -> HashSet<u64> {
        let now = current_time_millis();

        // Check all PTR records for this ty_domain.
        self.ptr
            .get_mut(ty_domain)
            .into_iter()
            .flatten()
            .filter_map(|record| {
                if record.get_record_mut().refresh_maybe(now) {
                    Some(record.get_record().get_refresh_time())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns the set of SRV instance names that are due for refresh
    /// for a `ty_domain`.
    pub(crate) fn refresh_due_srv(&mut self, ty_domain: &str) -> (HashSet<String>, HashSet<u64>) {
        let now = current_time_millis();

        let mut instances = vec![];

        // find instance names for ty_domain.
        for record in self.ptr.get_mut(ty_domain).into_iter().flatten() {
            if record.get_record().is_expired(now) {
                continue;
            }

            if let Some(ptr) = record.any().downcast_ref::<DnsPointer>() {
                instances.push(ptr.alias.clone());
            }
        }

        // Check SRV records.
        let mut refresh_due = HashSet::new();
        let mut new_timers = HashSet::new();
        for instance in instances {
            let refresh_timers: HashSet<u64> = self
                .srv
                .get_mut(&instance)
                .into_iter()
                .flatten()
                .filter_map(|record| {
                    if record.get_record_mut().refresh_maybe(now) {
                        Some(record.get_record().get_refresh_time())
                    } else {
                        None
                    }
                })
                .collect();

            if !refresh_timers.is_empty() {
                refresh_due.insert(instance);
                new_timers.extend(refresh_timers);
            }
        }

        (refresh_due, new_timers)
    }

    /// Returns the set of A/AAAA records that are due for refresh for a `hostname`.
    ///
    /// For these records, their refresh time will be updated so that they will not refresh again.
    pub(crate) fn refresh_due_hostname_resolutions(
        &mut self,
        hostname: &str,
    ) -> HashSet<(String, IpAddr)> {
        let now = current_time_millis();

        self.addr
            .get_mut(hostname)
            .into_iter()
            .flatten()
            .filter_map(|record| {
                let rec = record.get_record_mut();
                if rec.is_expired(now) || !rec.refresh_due(now) {
                    return None;
                }
                rec.refresh_no_more();

                Some((
                    hostname.to_owned(),
                    record.any().downcast_ref::<DnsAddress>().unwrap().address,
                ))
            })
            .collect()
    }

    /// Returns a list of Known Answer for a given question of `name` with `qtype`.
    /// The timestamp `now` is passed in to check TTL.
    ///
    /// Reference:  RFC 6762 section 7.1
    pub(crate) fn get_known_answers<'a>(
        &'a self,
        name: &str,
        qtype: u16,
        now: u64,
    ) -> Vec<&'a DnsRecordBox> {
        let records_opt = match qtype {
            TYPE_PTR => self.get_ptr(name),
            TYPE_SRV => self.get_srv(name),
            TYPE_A | TYPE_AAAA => self.get_addr(name),
            TYPE_TXT => self.get_txt(name),
            _ => None,
        };

        let records = match records_opt {
            Some(items) => items,
            None => return Vec::new(),
        };

        // From RFC 6762 section 7.1:
        // ..Generally, this applies only to Shared records, not Unique records,..
        //
        // ..a Multicast DNS querier SHOULD NOT include
        // records in the Known-Answer list whose remaining TTL is less than
        // half of their original TTL.
        records
            .iter()
            .filter(move |r| !r.get_record().is_unique() && !r.get_record().halflife_passed(now))
            .collect()
    }
}
