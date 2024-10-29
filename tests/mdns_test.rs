#[cfg(feature = "plugins")]
use flume::bounded;
use if_addrs::{IfAddr, Interface};
#[cfg(feature = "plugins")]
use mdns_sd::PluginCommand;
use mdns_sd::{
    DaemonEvent, DaemonStatus, HostnameResolutionEvent, IfKind, IntoTxtProperties, ServiceDaemon,
    ServiceEvent, ServiceInfo, UnregisterStatus,
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(feature = "plugins")]
use std::sync::Arc;
use std::thread::sleep;
#[cfg(feature = "plugins")]
use std::thread::spawn;
use std::time::{Duration, SystemTime};
// use test_log::test; // commented out for debugging a flaky test in CI.

/// This test covers:
/// register(announce), browse(query), response, unregister, shutdown.
#[test]
fn integration_success() {
    // Create a daemon
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    // Register a service
    let ty_domain = "_mdns-sd-it._udp.local.";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let instance_name = now.as_micros().to_string(); // Create a unique name.

    let all_interfaces = my_ip_interfaces();
    println!("all interfaces count: {}", all_interfaces.len());
    // as we send only once per interface and ip we need a count of unique addresses to verify number of sent unregisters later on
    let mut unique_intf_idx_ip_ver_set = HashSet::new();
    let mut non_idx_count = 0;
    for intf in all_interfaces.iter() {
        let ip_ver = match intf.addr {
            IfAddr::V4(_) => 4u8,
            IfAddr::V6(_) => 6u8,
        };

        // use the same approach as `IntfSock.multicast_send_tracker`
        if let Some(idx) = intf.index {
            if !unique_intf_idx_ip_ver_set.insert((idx, ip_ver)) {
                println!("index {idx} IP v{ip_ver} repeated on interface {}, likely multi-addr on the same interface", intf.name);
            }
        } else {
            non_idx_count += 1;
        }
    }
    let unique_intf_idx_ip_ver_count = unique_intf_idx_ip_ver_set.len() + non_idx_count;

    let ifaddrs_set: HashSet<_> = all_interfaces.iter().map(|intf| intf.ip()).collect();
    let my_ifaddrs: Vec<_> = ifaddrs_set.into_iter().collect();
    let my_addrs_count = my_ifaddrs.len();
    println!("My IP {} addr(s):", my_ifaddrs.len());
    for item in my_ifaddrs.iter() {
        println!("{}", &item);
    }

    let host_name = "integration_host.local.";
    let port = 5200;
    let mut properties = HashMap::new();
    properties.insert("property_1".to_string(), "test".to_string());
    properties.insert("property_2".to_string(), "1".to_string());
    properties.insert("property_3".to_string(), "1234".to_string());

    let my_service = ServiceInfo::new(
        ty_domain,
        &instance_name,
        host_name,
        &my_ifaddrs[..],
        port,
        Some(properties),
    )
    .expect("valid service info");
    let fullname = my_service.get_fullname().to_string();
    d.register(my_service)
        .expect("Failed to register our service");

    // Browse for a service
    let mut resolved_ips: HashSet<IpAddr> = HashSet::new();
    let mut addr_count = 0;

    let browse_chan = d.browse(ty_domain).unwrap();
    let timeout = Duration::from_secs(2);
    while let Ok(event) = browse_chan.recv_timeout(timeout) {
        match event {
            ServiceEvent::SearchStarted(ty_domain) => {
                println!("Search started for {}", &ty_domain);
            }
            ServiceEvent::ServiceFound(_ty_domain, fullname) => {
                println!("Found a new service: {}", &fullname);
            }
            ServiceEvent::ServiceResolved(info) => {
                let addrs = info.get_addresses();
                println!(
                    "Resolved a new service: {} with {} addr(s)",
                    info.get_fullname(),
                    addrs.len()
                );
                for a in addrs.iter() {
                    println!("{}", a);
                }
                if info.get_fullname().contains(&instance_name) {
                    resolved_ips.extend(addrs);
                }
                let hostname = info.get_hostname();
                assert_eq!(hostname, host_name);

                let addr_set = info.get_addresses();
                addr_count = addr_set.len();

                let service_port = info.get_port();
                assert_eq!(service_port, port);

                let properties = info.get_properties();
                assert!(properties.get("property_1").is_some());
                assert!(properties.get("property_2").is_some());
                assert_eq!(properties.len(), 3);
                assert!(info.get_property("property_1").is_some());
                assert!(info.get_property("property_2").is_some());
                assert_eq!(info.get_property_val_str("property_1"), Some("test"));
                assert_eq!(info.get_property_val_str("property_2"), Some("1"));
                assert_eq!(
                    info.get_property_val("property_1").unwrap(),
                    Some("test".as_bytes())
                );

                let host_ttl = info.get_host_ttl();
                assert_eq!(host_ttl, 120); // default value.

                let other_ttl = info.get_other_ttl();
                assert_eq!(other_ttl, 4500); // default value.
            }
            _ => {}
        }
    }

    // All addrs should have been resolved.
    assert_eq!(addr_count, my_addrs_count);

    // IP's can get resolved more than once if fx a cache-flush is asked from the sender of the
    // MDNS records, so we look at unique IP addresses to see if they match the number of the
    // network interfaces.
    assert_eq!(resolved_ips.len(), my_addrs_count);
    assert!(resolved_ips.len() >= 1);

    // Unregister the service
    let receiver = d.unregister(&fullname).unwrap();
    let response = receiver.recv().unwrap();
    assert!(matches!(response, UnregisterStatus::OK));

    let mut remove_count = 0;
    while let Ok(event) = browse_chan.recv_timeout(timeout) {
        match event {
            ServiceEvent::ServiceRemoved(_ty_domain, fullname) => {
                println!("Removed service: {}", &fullname);
                if fullname.contains(&instance_name) {
                    remove_count += 1;
                }
                break;
            }
            _ => {}
        }
    }

    assert_eq!(remove_count, 1);

    // Stop browsing the service.
    d.stop_browse(ty_domain).expect("Failed to stop browsing");

    let mut stopped_count = 0;

    while let Ok(event) = browse_chan.recv_timeout(timeout) {
        match event {
            ServiceEvent::SearchStopped(ty) => {
                println!("Search stopped for {}", &ty);
                stopped_count += 1;
                break;
            }
            _ => {}
        }
    }

    assert_eq!(stopped_count, 1);

    // Verify metrics.
    let metrics_receiver = d.get_metrics().unwrap();
    let metrics = metrics_receiver.recv().unwrap();
    println!("metrics: {:?}", &metrics);
    assert_eq!(metrics["register"], 1);
    assert_eq!(metrics["unregister"], 1);
    assert_eq!(metrics["register-resend"], 1);

    println!("unique interface set: {:?}", unique_intf_idx_ip_ver_set);
    assert_eq!(
        metrics["unregister-resend"],
        unique_intf_idx_ip_ver_count as i64
    );
    assert!(metrics["browse"] >= 2); // browse has been retransmitted.

    // respond has been sent for every browse, or they are suppressed by "known answer".
    let respond_count = metrics.get("respond").unwrap_or(&0);
    let known_answer_count = metrics.get("known-answer-suppression").unwrap_or(&0);
    assert!(*respond_count >= 2 || *known_answer_count > 0);

    // Test the special meta-query of "_services._dns-sd._udp.local."
    let service2_type = "_my-service2._udp.local.";
    let service2_instance = "instance2";
    let service2 = ServiceInfo::new(
        service2_type,
        service2_instance,
        host_name,
        &my_ifaddrs[..],
        port,
        None,
    )
    .expect("valid service info");
    d.register(service2)
        .expect("Failed to register the 2nd service");

    // Browse using the special meta-query.
    let meta_query = "_services._dns-sd._udp.local.";
    let browse_chan = d.browse(meta_query).unwrap();
    let timeout = Duration::from_secs(2);

    loop {
        match browse_chan.recv_timeout(timeout) {
            Ok(event) => match event {
                ServiceEvent::ServiceFound(ty_domain, fullname) => {
                    println!("Found a service of {}: {}", &ty_domain, &fullname);
                    // Among all services found, should have our 2nd service.
                    if fullname == service2_type {
                        break;
                    }
                }
                e => {
                    println!("Received event {:?}", e);
                    sleep(Duration::from_millis(100));
                }
            },
            Err(e) => {
                panic!("browse error: {}", e);
            }
        }
    }

    // Shutdown
    d.shutdown().unwrap();
}

#[test]
fn service_without_properties_with_alter_net_v4() {
    // Create a daemon
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    // Register a service without properties.
    let ty_domain = "_serv-no-prop._tcp.local.";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let instance_name = now.as_micros().to_string(); // Create a unique name.
    let if_addrs: Vec<Interface> = my_ip_interfaces()
        .into_iter()
        .filter(|iface| iface.addr.ip().is_ipv4())
        .collect();
    let first_ip = if_addrs[0].ip();
    let alter_ip = ipv4_alter_net(&if_addrs);
    let host_ip = vec![first_ip, alter_ip];
    let host_name = "serv-no-prop-v4.local.";
    let port = 5201;
    let my_service = ServiceInfo::new(
        ty_domain,
        &instance_name,
        host_name,
        &host_ip[..],
        port,
        None,
    )
    .expect("valid service info");
    let fullname = my_service.get_fullname().to_string();
    d.register(my_service)
        .expect("Failed to register our service");
    println!("Registered service with host_ip: {:?}", &host_ip);

    // Browse for a service
    let browse_chan = d.browse(ty_domain).unwrap();
    let timeout = Duration::from_secs(2);
    let timer = std::time::Instant::now() + timeout;
    let mut found = false;
    while std::time::Instant::now() < timer {
        match browse_chan.recv_timeout(timeout) {
            Ok(event) => match event {
                ServiceEvent::ServiceResolved(info) => {
                    println!(
                        "Resolved a service of {} addr(s): {:?}",
                        &info.get_fullname(),
                        info.get_addresses()
                    );
                    // match only our service and not v6 one
                    if info.get_addresses_v4().is_empty() {
                        continue;
                    }
                    if fullname.as_str() == info.get_fullname() {
                        let addrs = info.get_addresses_v4();
                        assert_eq!(addrs.len(), 1); // first_ipv4 but no alter_ipv.
                        found = true;
                        break;
                    }
                }
                e => {
                    println!("Received event {:?}", e);
                }
            },
            Err(e) => {
                panic!("browse error: {}", e);
            }
        }
    }

    d.shutdown().unwrap();
    assert!(found);
}

#[test]
fn service_without_properties_with_alter_net_v6() {
    // Create a daemon
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    // Register a service without properties.
    let ty_domain = "_serv-no-prop._tcp.local.";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let instance_name = now.as_micros().to_string(); // Create a unique name.
    let if_addrs: Vec<Interface> = my_ip_interfaces()
        .into_iter()
        .filter(|iface| iface.addr.ip().is_ipv6())
        .collect();
    let first_ip = if_addrs[0].ip();
    let alter_ip = ipv6_alter_net(&if_addrs);
    let host_ip = vec![first_ip, alter_ip];
    let host_name = "serv-no-prop-v6.local.";
    let port = 5201;
    let my_service = ServiceInfo::new(
        ty_domain,
        &instance_name,
        host_name,
        &host_ip[..],
        port,
        None,
    )
    .expect("valid service info");
    let fullname = my_service.get_fullname().to_string();
    d.register(my_service)
        .expect("Failed to register our service");
    println!("Registered service with host_ip: {:?}", &host_ip);

    // Browse for a service
    let browse_chan = d.browse(ty_domain).unwrap();
    let timeout = Duration::from_secs(2);
    let timer = std::time::Instant::now() + timeout;
    let mut found = false;
    while std::time::Instant::now() < timer {
        match browse_chan.recv_timeout(timeout) {
            Ok(event) => match event {
                ServiceEvent::ServiceResolved(info) => {
                    println!(
                        "Resolved a service of {} addr(s): {:?}",
                        &info.get_fullname(),
                        info.get_addresses()
                    );
                    // match only our service and not v4 one
                    if fullname.as_str() == info.get_fullname() {
                        let addrs: Vec<&IpAddr> = info
                            .get_addresses()
                            .iter()
                            .filter(|a| a.is_ipv6())
                            .collect();
                        if addrs.is_empty() {
                            continue; // In case IPv4 addr received first.
                        }
                        assert_eq!(addrs.len(), 1); // first_ipv6 but no alter_ipv.
                        found = true;
                        break;
                    }
                }
                e => {
                    println!("Received event {:?}", e);
                }
            },
            Err(e) => {
                panic!("browse error: {}", e);
            }
        }
    }

    d.shutdown().unwrap();
    assert!(found);
}

#[test]
fn service_txt_properties_case_insensitive() {
    // Register a service with properties.
    let domain = "_serv-properties._tcp.local.";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let instance_name = now.as_micros().to_string(); // Create a unique name.
    let host_name = "properties_host.local.";
    let port = 5201;
    let properties = [
        ("prop_CAP_CASE", "one"),
        ("prop_cap_case", "two"),
        ("prop_Cap_Lower", "three"),
    ];

    let my_service = ServiceInfo::new(domain, &instance_name, host_name, "", port, &properties[..])
        .expect("valid service info")
        .enable_addr_auto();
    let props = my_service.get_properties();
    assert_eq!(props.len(), 2);

    // Verify `get_property()` method is case insensitive and returns
    // the first property with the same key.
    let prop_cap_case = my_service.get_property("prop_CAP_CASE").unwrap();
    assert_eq!(prop_cap_case.val_str(), "one");
    assert_eq!(prop_cap_case.val(), Some("one".as_bytes()));

    // Verify the original property name is kept.
    let prop_mixed = my_service.get_property("prop_cap_lower").unwrap();
    assert_eq!(prop_mixed.key(), "prop_Cap_Lower");
}

#[test]
fn service_txt_properties_key_ascii() {
    let domain = "_mdns-ascii._tcp.local.";
    let instance = "test_service_info_key_ascii";
    let port = 5202;

    // Verify that a key must contain ASCII only. E.g. cannot have emojis.
    let properties = [("prop_ascii", "one"), ("prop_🤗", "hugging_face")];
    let my_service = ServiceInfo::new(domain, instance, "myhost", "", port, &properties[..]);
    assert!(my_service.is_err());
    if let Err(e) = my_service {
        let msg = format!("ERROR: {}", e);
        assert!(msg.contains("not ASCII"));
    }

    // Verify that a key cannot contain '='.
    let properties = [("prop_ascii", "one"), ("prop_=", "equal sign")];
    let my_service = ServiceInfo::new(domain, instance, "myhost", "", port, &properties[..]);
    assert!(my_service.is_err());
    if let Err(e) = my_service {
        let msg = format!("ERROR: {}", e);
        assert!(msg.contains('='));
    }

    // Verify that properly formatted keys are OK.
    let properties = [("prop_ascii", "one"), ("prop_2", "two")];
    let my_service = ServiceInfo::new(domain, instance, "myhost", "", port, &properties[..]);
    assert!(my_service.is_ok());
}

#[test]
fn test_into_txt_properties() {
    // Verify (&str, String) tuple is supported.
    let properties = vec![("key1", String::from("val1"))];
    let txt_props = properties.into_txt_properties();
    assert_eq!(txt_props.get_property_val_str("key1").unwrap(), "val1");
    assert_eq!(
        txt_props.get_property_val("key1").unwrap(),
        Some("val1".as_bytes())
    );

    // Verify (String, String) tuple is supported.
    let properties = vec![(String::from("key2"), String::from("val2"))];
    let txt_props = properties.into_txt_properties();
    assert_eq!(txt_props.get_property_val_str("key2").unwrap(), "val2");
}

/// Test enabling an interface using its name, for example "en0".
#[test]
fn service_with_named_interface_only() {
    // Create a daemon
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    // First, disable all interfaces.
    d.disable_interface(IfKind::All).unwrap();

    // Register a service with a name len > 15.
    let my_ty_domain = "_named_intf_only._udp.local.";
    let host_name = "named_intf_host.local.";
    let host_ipv4 = "";
    let port = 5202;
    let my_service = ServiceInfo::new(
        my_ty_domain,
        "my_instance",
        host_name,
        host_ipv4,
        port,
        None,
    )
    .expect("invalid service info")
    .enable_addr_auto();

    d.register(my_service).unwrap();

    // Browse for a service and verify all addresses are IPv4.
    let browse_chan = d.browse(my_ty_domain).unwrap();
    let timeout = Duration::from_secs(2);
    let mut resolved = false;

    while let Ok(event) = browse_chan.recv_timeout(timeout) {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                let addrs = info.get_addresses();
                resolved = true;
                println!(
                    "Resolved a service of {} addr(s): {:?}",
                    &info.get_fullname(),
                    addrs
                );
                break;
            }
            e => {
                println!("Received event {:?}", e);
            }
        }
    }

    assert!(!resolved);

    // Second, find an interface.
    let if_addrs: Vec<Interface> = my_ip_interfaces()
        .into_iter()
        .filter(|iface| iface.addr.ip().is_ipv4())
        .collect();
    let if_name = if_addrs[0].name.clone();

    // Enable the named interface.
    println!("Enable interface with name {}", &if_name);
    d.enable_interface(&if_name).unwrap();

    // Browse again.
    let browse_chan = d.browse(my_ty_domain).unwrap();
    let timeout = Duration::from_secs(2);
    let mut resolved = false;

    while let Ok(event) = browse_chan.recv_timeout(timeout) {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                let addrs = info.get_addresses();
                resolved = true;
                println!(
                    "Resolved a service of {} addr(s): {:?}",
                    &info.get_fullname(),
                    addrs
                );
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
fn service_with_ipv4_only() {
    // Create a daemon
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    // Disable IPv6, so the daemon is IPv4 only now.
    d.disable_interface(IfKind::IPv6).unwrap();

    // Register a service with a name len > 15.
    let service_ipv4_only = "_test_ipv4_only._udp.local.";
    let host_name = "my_host_ipv4_only.local.";
    let host_ipv4 = "";
    let port = 5201;
    let my_service = ServiceInfo::new(
        service_ipv4_only,
        "my_instance",
        host_name,
        host_ipv4,
        port,
        None,
    )
    .expect("invalid service info")
    .enable_addr_auto();
    let result = d.register(my_service);
    assert!(result.is_ok());

    // Browse for a service and verify all addresses are IPv4.
    let browse_chan = d.browse(service_ipv4_only).unwrap();
    let timeout = Duration::from_secs(2);
    let mut resolved = false;

    // run till the timeout and collect the resolved addresses
    // from all enabled interfaces.
    while let Ok(event) = browse_chan.recv_timeout(timeout) {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                let addrs = info.get_addresses();
                resolved = true;
                println!(
                    "Resolved a service of {} addr(s): {:?}",
                    &info.get_fullname(),
                    addrs
                );
                assert!(!info.get_addresses().is_empty());
                for addr in info.get_addresses().iter() {
                    assert!(addr.is_ipv4());
                }
                // We don't break here, as there could be more addresses coming.
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
fn service_with_invalid_addr_v4() {
    // Create a daemon
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    // Register a service without properties.
    let ty_domain = "_invalid-addr._tcp.local.";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let instance_name = now.as_micros().to_string(); // Create a unique name.
    let if_addrs: Vec<Interface> = my_ip_interfaces()
        .into_iter()
        .filter(|iface| iface.addr.ip().is_ipv4())
        .collect();
    let alter_ip = ipv4_alter_net(&if_addrs);
    let host_name = "invalid_ipv4_host.local.";
    let port = 5201;
    let my_service = ServiceInfo::new(ty_domain, &instance_name, host_name, alter_ip, port, None)
        .expect("valid service info");
    d.register(my_service)
        .expect("Failed to register our service");

    // Browse for a service
    let browse_chan = d.browse(ty_domain).unwrap();
    let timeout = Duration::from_secs(2);
    let mut resolved = false;
    loop {
        match browse_chan.recv_timeout(timeout) {
            Ok(event) => match event {
                ServiceEvent::ServiceResolved(info) => {
                    println!(
                        "Resolved a service of {} addr(s): {:?}",
                        &info.get_fullname(),
                        info.get_addresses()
                    );
                    resolved = true;
                    break;
                }
                e => {
                    println!("Received event {:?}", e);
                }
            },
            Err(e) => {
                println!("browse error: {}", e);
                break;
            }
        }
    }

    d.shutdown().unwrap();

    // We cannot resolve the service because the published address
    // is not valid in the LAN.
    assert!(!resolved);
}

#[test]
fn service_with_invalid_addr_v6() {
    // Create a daemon
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    // Register a service without properties.
    let ty_domain = "_invalid-addr._tcp.local.";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let instance_name = now.as_micros().to_string(); // Create a unique name.
    let if_addrs: Vec<Interface> = my_ip_interfaces()
        .into_iter()
        .filter(|iface| iface.addr.ip().is_ipv6())
        .collect();
    let alter_ip = ipv6_alter_net(&if_addrs);
    let host_name = "my_host.local.";
    let port = 5201;
    let my_service = ServiceInfo::new(ty_domain, &instance_name, host_name, alter_ip, port, None)
        .expect("valid service info");
    d.register(my_service)
        .expect("Failed to register our service");

    // Browse for a service
    let browse_chan = d.browse(ty_domain).unwrap();
    let timeout = Duration::from_secs(2);
    let mut resolved = false;
    loop {
        match browse_chan.recv_timeout(timeout) {
            Ok(event) => match event {
                ServiceEvent::ServiceResolved(info) => {
                    println!(
                        "Resolved a service of {} addr(s): {:?}",
                        &info.get_fullname(),
                        info.get_addresses()
                    );
                    resolved = true;
                    break;
                }
                e => {
                    println!("Received event {:?}", e);
                }
            },
            Err(e) => {
                println!("browse error: {}", e);
                break;
            }
        }
    }

    d.shutdown().unwrap();

    // We cannot resolve the service because the published address
    // is not valid in the LAN.
    assert!(!resolved);
}

#[test]
fn subtype() {
    // Create a daemon
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    // Register a service with a subdomain
    let subtype_domain = "_directory._sub._test._tcp.local.";
    let ty_domain = "_test._tcp.local.";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let instance_name = now.as_micros().to_string(); // Create a unique name.
    let host_ipv4 = my_ip_interfaces()[0].ip().to_string();
    let host_name = "my_host.local.";
    let port = 5201;
    let my_service = ServiceInfo::new(
        subtype_domain,
        &instance_name,
        host_name,
        host_ipv4,
        port,
        None,
    )
    .expect("valid service info");
    let fullname = my_service.get_fullname().to_string();
    d.register(my_service)
        .expect("Failed to register our service");

    // Browse for the service via ty_domain and subtype_domain
    for domain in [ty_domain, subtype_domain].iter() {
        let browse_chan = d.browse(domain).unwrap();
        let timeout = Duration::from_secs(2);
        loop {
            match browse_chan.recv_timeout(timeout) {
                Ok(event) => match event {
                    ServiceEvent::ServiceResolved(info) => {
                        println!(
                            "Resolved a service of {} subdomain {:?}",
                            &info.get_fullname(),
                            info.get_subtype()
                        );
                        assert_eq!(fullname.as_str(), info.get_fullname());
                        assert_eq!(subtype_domain, info.get_subtype().as_ref().unwrap());
                        break;
                    }
                    e => {
                        println!("Received event {:?}", e);
                    }
                },
                Err(e) => {
                    panic!("browse error: {}", e);
                }
            }
        }
    }

    d.shutdown().unwrap();
}

/// Verify service name has to be valid.
#[test]
fn service_name_check() {
    // Create a daemon for the server.
    let server_daemon = ServiceDaemon::new().expect("Failed to create server daemon");
    let monitor = server_daemon.monitor().unwrap();
    // Register a service with a name len > 15.
    let service_name_too_long = "_service-name-too-long._udp.local.";
    let host_ipv4 = "";
    let host_name = "my_host.local.";
    let port = 5200;
    let my_service = ServiceInfo::new(
        service_name_too_long,
        "my_instance",
        host_name,
        host_ipv4,
        port,
        None,
    )
    .expect("valid service info")
    .enable_addr_auto();
    let result = server_daemon.register(my_service.clone());
    assert!(result.is_ok());

    // Verify that the daemon reported error.
    let event = monitor.recv_timeout(Duration::from_millis(500)).unwrap();
    assert!(matches!(event, DaemonEvent::Error(_)));
    if let DaemonEvent::Error(e) = event {
        println!("Daemon error: {}", e)
    }

    // Verify that we can increase the service name length max.
    server_daemon.set_service_name_len_max(30).unwrap();
    let result = server_daemon.register(my_service);
    assert!(result.is_ok());

    // Verify that the service was published successfully.
    let event = monitor.recv_timeout(Duration::from_millis(500)).unwrap();
    assert!(matches!(event, DaemonEvent::Announce(_, _)));

    // Check for the internal upper limit of service name length max.
    let r = server_daemon.set_service_name_len_max(31);
    assert!(r.is_err());

    server_daemon.shutdown().unwrap();
}

#[test]
fn service_new_publish_after_browser() {
    let service_type = "_new-pub._udp.local.";
    let daemon = ServiceDaemon::new().expect("Failed to create a new daemon");

    // First, starts the browser.
    let receiver = daemon.browse(service_type).unwrap();

    sleep(Duration::from_millis(1000));

    let txt_properties = [("key1", "value1")];
    let service_info = ServiceInfo::new(
        "_new-pub._udp.local.",
        "test1",
        "my_host.local.",
        "",
        1234,
        &txt_properties[..],
    )
    .expect("valid service info")
    .enable_addr_auto();

    // Second, publish a service.
    let result = daemon.register(service_info);
    assert!(result.is_ok());

    let mut resolved = false;
    let timeout = Duration::from_secs(2);
    loop {
        match receiver.recv_timeout(timeout) {
            Ok(event) => match event {
                ServiceEvent::ServiceResolved(info) => {
                    println!(
                        "Resolved a service of {} addr(s): {:?} props: {:?}",
                        &info.get_fullname(),
                        info.get_addresses(),
                        info.get_properties()
                    );
                    resolved = true;
                    break;
                }
                e => {
                    println!("Received event {:?}", e);
                }
            },
            Err(e) => {
                println!("browse error: {}", e);
                break;
            }
        }
    }

    assert!(resolved);
    daemon.shutdown().unwrap();
}

// This test covers the sanity check in `read_others` decoding RDATA.
#[test]
fn instance_name_two_dots() {
    // Create a daemon for the server.
    let server_daemon = ServiceDaemon::new().expect("Failed to create server daemon");
    let monitor = server_daemon.monitor().unwrap();

    // Register an instance name with a ending dot.
    // Then the full name will have two dots in the middle.
    // This would create a PTR record RDATA with a skewed name field.
    let service_type = "_two-dots._udp.local.";
    let instance_name = "my_instance.";
    let host_ipv4 = "";
    let host_name = "my_host.local.";
    let port = 5200;
    let my_service = ServiceInfo::new(
        service_type,
        instance_name,
        host_name,
        host_ipv4,
        port,
        None,
    )
    .expect("valid service info")
    .enable_addr_auto();
    let result = server_daemon.register(my_service.clone());
    assert!(result.is_ok());

    // Verify that the service was published successfully.
    let event = monitor.recv_timeout(Duration::from_millis(500)).unwrap();
    assert!(matches!(event, DaemonEvent::Announce(_, _)));

    // Browseing the service.
    let receiver = server_daemon.browse(service_type).unwrap();
    let mut resolved = false;
    let timeout = Duration::from_secs(2);
    loop {
        match receiver.recv_timeout(timeout) {
            Ok(event) => match event {
                ServiceEvent::ServiceResolved(_) => {
                    resolved = true;
                    break;
                }
                e => {
                    println!("Received event {:?}", e);
                }
            },
            Err(e) => {
                println!("browse error: {}", e);
                break;
            }
        }
    }

    assert!(!resolved);
    server_daemon.shutdown().unwrap();
}

fn my_ip_interfaces() -> Vec<Interface> {
    // Use a random port for binding test.
    let test_port = fastrand::u16(8000u16..9000u16);

    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| {
            if i.is_loopback() {
                None
            } else {
                match &i.addr {
                    IfAddr::V4(ifv4) =>
                    // Use a 'bind' to check if this is a valid IPv4 addr.
                    {
                        match std::net::UdpSocket::bind((ifv4.ip, test_port)) {
                            Ok(_) => Some(i),
                            Err(e) => {
                                println!("failed to bind {}: {e}, skipped.", ifv4.ip);
                                None
                            }
                        }
                    }
                    IfAddr::V6(ifv6) =>
                    // Use a 'bind' to check if this is a valid IPv6 addr.
                    {
                        let mut sock = std::net::SocketAddrV6::new(ifv6.ip, test_port, 0, 0);
                        if i.is_link_local() {
                            // Only link local IPv6 address requires to specify scope_id
                            sock.set_scope_id(i.index.unwrap_or(0));
                        }

                        match std::net::UdpSocket::bind(sock) {
                            Ok(_) => Some(i),
                            Err(e) => {
                                println!("failed to bind {}: {e}, skipped.", ifv6.ip);
                                None
                            }
                        }
                    }
                }
            }
        })
        .collect()
}

/// Returns a made-up IPv4 address "net.1.1.1", where
/// `net` is one higher than any of IPv4 addresses on the host.
///
/// The idea is that this made-up address does not belong to
/// the same network as any of the host addresses.
fn ipv4_alter_net(if_addrs: &[Interface]) -> IpAddr {
    let mut net_max = 0;
    for if_addr in if_addrs.iter() {
        match &if_addr.addr {
            IfAddr::V4(iface) => {
                let net = iface.ip.octets()[0];
                if net > net_max {
                    net_max = net;
                }
            }
            _ => panic!(),
        }
    }
    Ipv4Addr::new(net_max + 1, 1, 1, 1).into()
}

/// Returns a made-up IPv6 address "net:1:1:1:1:1:1:1", where
/// `net` is one higher than any of IPv6 addresses on the host.
///
/// The idea is that this made-up address does not belong to
/// the same network as any of the host addresses.
fn ipv6_alter_net(if_addrs: &[Interface]) -> IpAddr {
    let mut net_max = 0;
    for if_addr in if_addrs.iter() {
        match &if_addr.addr {
            IfAddr::V6(iface) => {
                let net = iface.ip.octets()[0];
                if net > net_max {
                    net_max = net;
                }
            }
            _ => panic!(),
        }
    }
    Ipv6Addr::new(net_max as u16 + 1, 1, 1, 1, 1, 1, 1, 1).into()
}

#[test]
fn test_shutdown() {
    let mdns = ServiceDaemon::new().unwrap();

    // Check the status.
    let receiver = mdns.status().unwrap();
    let status = receiver.recv().unwrap();
    assert!(matches!(status, DaemonStatus::Running));

    // Shutdown the daemon immediately.
    let receiver = mdns.shutdown().unwrap();
    let status = receiver.recv().unwrap();
    println!("daemon status: {:?}", status);

    // Try to register and it should fail.
    let service_type = "_mdns-sd-my-test._udp.local.";
    let instance_name = "my_instance";
    let ip = "192.168.1.12";
    let host_name = "192.168.1.12.local.";
    let port = 5200;
    let properties = [("property_1", "test"), ("property_2", "1234")];

    let my_service = ServiceInfo::new(
        service_type,
        instance_name,
        host_name,
        ip,
        port,
        &properties[..],
    )
    .unwrap();

    let result = mdns.register(my_service);
    assert!(result.is_err());

    // Check the status again.
    let receiver = mdns.status().unwrap();
    let status = receiver.recv().unwrap();
    assert!(matches!(status, DaemonStatus::Shutdown));
}

#[test]
fn test_hostname_resolution() {
    let d = ServiceDaemon::new().expect("Failed to create daemon");
    let hostname = "my_host._tcp.local.";
    let service_ip_addr = my_ip_interfaces()
        .iter()
        .find(|iface| iface.ip().is_ipv4())
        .map(|iface| iface.ip())
        .unwrap();

    let my_service = ServiceInfo::new(
        "_host_res_test._tcp.local.",
        "my_instance",
        hostname,
        &[service_ip_addr] as &[IpAddr],
        1234,
        None,
    )
    .expect("invalid service info");
    d.register(my_service).unwrap();

    let event_receiver = d.resolve_hostname(hostname, Some(2000)).unwrap();
    let resolved = loop {
        match event_receiver.recv() {
            Ok(HostnameResolutionEvent::AddressesFound(found_hostname, addresses)) => {
                assert!(found_hostname == hostname);
                assert!(addresses.contains(&service_ip_addr));
                break true;
            }
            Ok(HostnameResolutionEvent::SearchStopped(_)) => break false,
            Ok(event) => println!("Received event {:?}", event),
            Err(_) => break false,
        }
    };

    assert!(resolved);
    d.shutdown().unwrap();
}

#[test]
fn hostname_resolution_timeout() {
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    let hostname = "nonexistent._tcp.local.";

    let before = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("failed to get current UNIX time")
        .as_millis() as u64;
    let event_receiver = d.resolve_hostname(hostname, Some(2000)).unwrap();
    let resolved = loop {
        match event_receiver.recv() {
            Ok(HostnameResolutionEvent::AddressesFound(found_hostname, _addresses)) => {
                assert!(found_hostname == hostname);
                break true;
            }
            Ok(HostnameResolutionEvent::SearchTimeout(_)) => break false,
            Ok(event) => println!("Received event {:?}", event),
            Err(_) => break false,
        }
    };
    let after = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("failed to get current UNIX time")
        .as_millis() as u64;

    assert!(!resolved);

    println!("Time spent resolving: {} ms", after - before);
    assert!(after - before >= 2000 - 5);
    assert!(after - before < 2000 + 1000);

    d.shutdown().unwrap();
}

#[test_log::test]
fn test_cache_flush_record() {
    // Create a daemon
    let server = ServiceDaemon::new().expect("Failed to create server");
    let service = "_test_cache_ptr._udp.local.";
    let host_name = "my_host_tmp_cache_flush.local.";

    // use a single IPv4 addr
    let mut service_ip_addr = my_ip_interfaces()
        .iter()
        .find(|iface| iface.ip().is_ipv4())
        .map(|iface| iface.ip())
        .unwrap();

    let port = 5201;
    let properties = vec![("key", "value")];
    let mut my_service = ServiceInfo::new(
        service,
        "my_instance",
        host_name,
        &service_ip_addr,
        port,
        &properties[..],
    )
    .expect("invalid service info");
    let result = server.register(my_service.clone());
    assert!(result.is_ok());

    // Browse for a service
    let client = ServiceDaemon::new().expect("Failed to create client");
    let browse_chan = client.browse(service).unwrap();
    let timeout = Duration::from_secs(2);
    let mut resolved = false;

    while let Ok(event) = browse_chan.recv_timeout(timeout) {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                resolved = true;
                timed_println(format!("Resolved a service of {}", &info.get_fullname()));
                timed_println(format!("JLN service: {:?}", info));
                break;
            }
            e => {
                println!("Received event {:?}", e);
            }
        }
    }

    assert!(resolved);

    // Stop browsing for a moment.
    client.stop_browse(service).unwrap();
    sleep(Duration::from_secs(2)); // Let the cache record be surely older than 1 second.

    // Modify the IPv4 address for the service.
    if let IpAddr::V4(ipv4) = service_ip_addr {
        let bytes = ipv4.octets();
        service_ip_addr = IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3] + 1));
    } else {
        assert!(false);
    }

    // Re-register the service to update the IPv4 addr.
    my_service = ServiceInfo::new(
        service,
        "my_instance",
        host_name,
        &service_ip_addr,
        port,
        &properties[..],
    )
    .unwrap();
    let result = server.register(my_service);
    assert!(result.is_ok());

    timed_println(format!(
        "Re-registered with updated IPv4 addr: {}",
        &service_ip_addr
    ));

    // Wait for the new registration sent out and cache flushed.
    sleep(Duration::from_secs(2));

    // Browse for the updated IPv4 address.
    let browse_chan = client.browse(service).unwrap();
    resolved = false;
    while let Ok(event) = browse_chan.recv_timeout(timeout) {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                // Verify the address flushed and updated.
                let new_addrs = info.get_addresses();
                timed_println(format!("new address resolved: {:?}", new_addrs));
                if new_addrs.len() == 1 {
                    let first_addr = new_addrs.iter().next().unwrap();
                    assert_eq!(first_addr, &service_ip_addr);
                    resolved = true;
                    break;
                }
            }
            e => {
                timed_println(format!("Received event {:?}", e));
            }
        }
    }

    assert!(resolved);
    server.shutdown().unwrap();
    client.shutdown().unwrap();
}

#[test]
fn test_cache_flush_remove_one_addr() {
    // Create a daemon
    let server = ServiceDaemon::new().expect("Failed to create server");
    let service = "_remove_one_addr._udp.local.";
    let host_name = "remove_one_addr_host.local.";

    // Get a single IPv4 address
    let ip_addr1 = my_ip_interfaces()
        .iter()
        .find(|iface| iface.ip().is_ipv4())
        .map(|iface| iface.ip())
        .unwrap();

    // Make 2nd IPv4 address for the service.
    let ip_addr2 = match ip_addr1 {
        IpAddr::V4(ipv4) => {
            let bytes = ipv4.octets();
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3] + 1))
        }
        _ => {
            panic!()
        }
    };

    let port = 5201;
    let mut my_service = ServiceInfo::new(
        service,
        "my_instance",
        host_name,
        &[ip_addr1, ip_addr2][..],
        port,
        None,
    )
    .expect("invalid service info");
    let result = server.register(my_service.clone());
    assert!(result.is_ok());

    // Browse for a service
    let client = ServiceDaemon::new().expect("Failed to create client");
    let browse_chan = client.browse(service).unwrap();
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

    // Stop browsing for a moment.
    client.stop_browse(service).unwrap();
    sleep(Duration::from_secs(2)); // Wait 1 more second for the 2nd annoucement

    // Re-register the service to have only 1 addr.
    my_service =
        ServiceInfo::new(service, "my_instance", host_name, &ip_addr1, port, None).unwrap();
    let result = server.register(my_service.clone());
    assert!(result.is_ok());

    println!("Re-registered with updated IPv4 addr");

    // Wait for the new registration sent out and cache flushed.
    sleep(Duration::from_secs(2));

    // Browse for the updated IPv4 address.
    let browse_chan = client.browse(service).unwrap();
    resolved = false;
    while let Ok(event) = browse_chan.recv_timeout(timeout) {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                // Verify the address flushed and updated.
                let new_addrs = info.get_addresses();
                if new_addrs.len() == 1 {
                    let first_addr = new_addrs.iter().next().unwrap();
                    assert_eq!(first_addr, &ip_addr1);
                    resolved = true;
                    break;
                }
            }
            e => {
                println!("Received event {:?}", e);
            }
        }
    }

    assert!(resolved);
    server.shutdown().unwrap();
    client.shutdown().unwrap();
}

#[test]
fn test_known_answer_suppression() {
    // Create a daemon
    let mdns_server = ServiceDaemon::new().expect("Failed to create mdns server");

    // Register a service
    let ty_domain = "_known-answer._udp.local.";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let instance_name = now.as_micros().to_string(); // Create a unique name.

    // Get a single IPv4 address
    let ip_addr1 = my_ip_interfaces()
        .iter()
        .find(|iface| iface.ip().is_ipv4())
        .map(|iface| iface.ip())
        .unwrap();

    let host_name = "known_answer_server.local.";
    let port = 5200;

    // Publish the service
    let my_service = ServiceInfo::new(ty_domain, &instance_name, host_name, &ip_addr1, port, None)
        .expect("valid service info");
    mdns_server
        .register(my_service)
        .expect("Failed to register my service");

    // Browse the service
    let client = ServiceDaemon::new().expect("Failed to create mdns client");
    let browse_chan = client.browse(ty_domain).unwrap();
    let timeout = Duration::from_secs(2);
    let mut resolved = false;

    while let Ok(event) = browse_chan.recv_timeout(timeout) {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                resolved = true;
                println!("Resolved a service of {}", &info.get_fullname());
                break;
            }
            other => {
                println!("Received event {:?}", other);
            }
        }
    }
    assert!(resolved);

    // Browse again to trigger Known Answer Suppression for sure.
    let browse_chan = client.browse(ty_domain).unwrap();
    resolved = false;

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

    // Give the server daemon chances to handle the browse query again.
    sleep(Duration::from_secs(1));

    // Verify Known Answer Suppression happened.
    let metrics_receiver = mdns_server.get_metrics().unwrap();
    let metrics = metrics_receiver.recv().unwrap();
    println!("metrics: {:?}", &metrics);
    assert!(metrics["known-answer-suppression"] > 0);
}

#[test]
fn test_domain_suffix_in_browse() {
    let mdns_client = ServiceDaemon::new().expect("failed to create mDNS client");
    assert!(mdns_client.browse("_service-name._tcp.local").is_err());
    assert!(mdns_client.browse("_service-name._tcp.local.").is_ok());
    mdns_client.shutdown().unwrap();
}

#[test]
#[cfg(feature = "plugins")]
fn plugin_support_test() {
    let mdns_server = ServiceDaemon::new().expect("failed to create mdns server");
    let mdns_client = ServiceDaemon::new().expect("Failed to create mdns client");

    let mut ips = vec![];

    for i in my_ip_interfaces() {
        mdns_server.enable_interface(&i.name).unwrap();
        mdns_client.enable_interface(&i.name).unwrap();
        ips.push(i.ip().to_string());
    }

    let (papi_send, papi_recv) = bounded(100);

    mdns_server
        .register_plugin("test".to_string(), papi_send)
        .expect("failed to register plugin");

    let cmd_registered = papi_recv.recv().expect("failed to receive command");

    match cmd_registered {
        PluginCommand::Registered => {}
        _ => panic!("Wrong plugin command received"),
    };

    spawn(move || {
        let service_info_arc = Arc::new({
            let service_type = "somehost._tcp.local.";
            let instance_name = "somehost";
            let ip = ips.join(",");
            let host_name = "somehost.local.";
            let port = 5200;
            let properties = [("property_1", "test"), ("property_2", "1234")];

            ServiceInfo::new(
                service_type,
                instance_name,
                host_name,
                ip,
                port,
                &properties[..],
            )
            .unwrap()
        });

        loop {
            let cmd = papi_recv.recv();

            match cmd {
                Ok(PluginCommand::Registered) => {}
                Ok(PluginCommand::Exit(sender)) => {
                    sender.send(()).unwrap();
                    return;
                }
                Ok(PluginCommand::ListServices(sender)) => {
                    let mut map = HashMap::new();

                    map.insert("somehost.local.".to_string(), service_info_arc.clone());

                    sender.send(map).unwrap();
                }
                Err(_) => return,
            }
        }
    });

    let browse_chan = mdns_client
        .resolve_hostname("somehost.local.", None)
        .unwrap();

    let mut resolved = false;

    while let Ok(event) = browse_chan.recv() {
        match event {
            HostnameResolutionEvent::AddressesFound(host, _addresses) => {
                resolved = true;
                println!("Resolved a service of {}", &host);
                break;
            }
            other => {
                println!("Received event {:?}", other);
            }
        }
    }
    assert!(resolved);

    mdns_server.shutdown().unwrap();
    mdns_client.shutdown().unwrap();
}

/// A helper function to include a timestamp for println.
fn timed_println(msg: String) {
    let now = SystemTime::now();
    let formatted_time = humantime::format_rfc3339(now);
    println!("[{}] {}", formatted_time, msg);
}
