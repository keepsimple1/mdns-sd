use if_addrs::{IfAddr, Interface};
use mdns_sd::{
    DaemonEvent, IfKind, IntoTxtProperties, ServiceDaemon, ServiceEvent, ServiceInfo,
    UnregisterStatus,
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, SystemTime};

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

    let ifaddrs_set: HashSet<_> = my_ip_interfaces().iter().map(|intf| intf.ip()).collect();
    let my_ifaddrs: Vec<_> = ifaddrs_set.into_iter().collect();
    let my_addrs_count = my_ifaddrs.len();
    println!("My IP {} addr(s):", my_ifaddrs.len());
    for item in my_ifaddrs.iter() {
        println!("{}", &item);
    }

    let host_name = "my_host.";
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
    let resolve_count = Arc::new(Mutex::new(0));
    let resolve_count_clone = resolve_count.clone();
    let remove_count = Arc::new(Mutex::new(0));
    let remove_count_clone = remove_count.clone();
    let stopped_count = Arc::new(Mutex::new(0));
    let stopped_count_clone = stopped_count.clone();
    let addr_count = Arc::new(Mutex::new(0));
    let addr_count_clone = addr_count.clone();

    let browse_chan = d.browse(ty_domain).unwrap();
    std::thread::spawn(move || {
        while let Ok(event) = browse_chan.recv() {
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
                        let mut num = resolve_count_clone.lock().unwrap();
                        *num += 1;
                    }
                    let hostname = info.get_hostname();
                    assert_eq!(hostname, host_name);

                    let addr_set = info.get_addresses();
                    let mut count = addr_count_clone.lock().unwrap();
                    *count = addr_set.len();

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
                ServiceEvent::ServiceRemoved(_ty_domain, fullname) => {
                    println!("Removed service: {}", &fullname);
                    if fullname.contains(&instance_name) {
                        let mut num = remove_count_clone.lock().unwrap();
                        *num += 1;
                    }
                }
                ServiceEvent::SearchStopped(ty) => {
                    println!("Search stopped for {}", &ty);
                    let mut num = stopped_count_clone.lock().unwrap();
                    *num += 1;
                    break;
                }
            }
        }
    });

    // Wait a bit to let the daemon process commands in the channel.
    sleep(Duration::from_secs(2));

    // Unregister the service
    let receiver = d.unregister(&fullname).unwrap();
    let response = receiver.recv().unwrap();
    assert!(matches!(response, UnregisterStatus::OK));

    sleep(Duration::from_secs(2));

    // All addrs should have been resolved.
    let count = addr_count.lock().unwrap();
    assert_eq!(*count, my_addrs_count);

    // `resolve_count` is not guaranteed to always be 1
    // or `my_addrs_count`. If `my_addrs_count` > 1, these
    // addrs could be resolved in a single message from
    // the daemon, or in separate messages.
    let count = resolve_count.lock().unwrap();
    assert!(*count >= 1);
    assert!(*count <= my_addrs_count);

    let count = remove_count.lock().unwrap();
    assert_eq!(*count, 1);

    // Stop browsing the service.
    d.stop_browse(ty_domain).expect("Failed to stop browsing");

    sleep(Duration::from_secs(1));

    let count = stopped_count.lock().unwrap();
    assert_eq!(*count, 1);

    // Verify metrics.
    let metrics_receiver = d.get_metrics().unwrap();
    let metrics = metrics_receiver.recv().unwrap();
    println!("metrics: {:?}", &metrics);
    assert_eq!(metrics["register"], 1);
    assert_eq!(metrics["unregister"], 1);
    assert_eq!(metrics["register-resend"], 1);
    assert_eq!(metrics["unregister-resend"], my_ifaddrs.len() as i64);
    assert!(metrics["browse"] >= 2); // browse has been retransmitted.
    assert!(metrics["respond"] >= 2); // respond has been sent for every browse.

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
                println!("browse error: {}", e);
                assert!(false);
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
    let host_name = "serv-no-prop-v4.";
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
                println!("browse error: {}", e);
                assert!(false);
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
    let host_name = "serv-no-prop-v6.";
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
                            .into_iter()
                            .filter(|a| a.is_ipv6())
                            .collect();
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
                println!("browse error: {}", e);
                assert!(false);
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
    let host_name = "properties_host.";
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
        assert!(msg.contains("="));
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
    let host_name = "my_host.";
    let host_ipv4 = "";
    let port = 5202;
    let my_service = ServiceInfo::new(
        my_ty_domain,
        "my_instance",
        host_name,
        &host_ipv4,
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

    loop {
        match browse_chan.recv_timeout(timeout) {
            Ok(event) => match event {
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
            },
            Err(_) => {
                break;
            }
        }
    }

    assert!(resolved == false);

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

    loop {
        match browse_chan.recv_timeout(timeout) {
            Ok(event) => match event {
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
            },
            Err(_) => {
                break;
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
    let host_name = "my_host_ipv4_only.";
    let host_ipv4 = "";
    let port = 5201;
    let my_service = ServiceInfo::new(
        service_ipv4_only,
        "my_instance",
        host_name,
        &host_ipv4,
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

    loop {
        match browse_chan.recv_timeout(timeout) {
            Ok(event) => match event {
                ServiceEvent::ServiceResolved(info) => {
                    let addrs = info.get_addresses();
                    resolved = true;
                    println!(
                        "Resolved a service of {} addr(s): {:?}",
                        &info.get_fullname(),
                        addrs
                    );
                    assert!(info.get_addresses().len() > 0);
                    for addr in info.get_addresses().iter() {
                        assert!(addr.is_ipv4());
                    }
                    break;
                }
                e => {
                    println!("Received event {:?}", e);
                }
            },
            Err(_) => {
                break;
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
    let host_name = "my_host.";
    let port = 5201;
    let my_service = ServiceInfo::new(ty_domain, &instance_name, host_name, &alter_ip, port, None)
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
    assert_eq!(resolved, false);
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
    let host_name = "my_host.";
    let port = 5201;
    let my_service = ServiceInfo::new(ty_domain, &instance_name, host_name, &alter_ip, port, None)
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
    assert_eq!(resolved, false);
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
    let host_name = "my_host.";
    let port = 5201;
    let my_service = ServiceInfo::new(
        subtype_domain,
        &instance_name,
        host_name,
        &host_ipv4,
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
                    println!("browse error: {}", e);
                    assert!(false);
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
    let host_name = "my_host.";
    let port = 5200;
    let my_service = ServiceInfo::new(
        service_name_too_long,
        "my_instance",
        host_name,
        &host_ipv4,
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
    match event {
        DaemonEvent::Error(e) => println!("Daemon error: {}", e),
        _ => {}
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

    let txt_properties = vec![("key1", "value1")];
    let service_info = ServiceInfo::new(
        "_new-pub._udp.local.",
        "test1",
        "my_host.",
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
    let host_name = "my_host.";
    let port = 5200;
    let my_service = ServiceInfo::new(
        service_type,
        instance_name,
        host_name,
        &host_ipv4,
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
                                println!("bind {}: {}, skipped.", ifv4.ip, e);
                                None
                            }
                        }
                    }
                    IfAddr::V6(ifv6) =>
                    // Use a 'bind' to check if this is a valid IPv6 addr.
                    {
                        let mut sock = std::net::SocketAddrV6::new(ifv6.ip, test_port, 0, 0);
                        sock.set_scope_id(i.index.unwrap_or(0));
                        match std::net::UdpSocket::bind(sock) {
                            Ok(_) => Some(i),
                            Err(e) => {
                                println!("bind {}: {}, skipped.", ifv6.ip, e);
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
