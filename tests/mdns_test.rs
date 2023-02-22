use if_addrs::{IfAddr, Ifv4Addr};
use mdns_sd::{
    Error, IntoTxtProperties, ServiceDaemon, ServiceEvent, ServiceInfo, UnregisterStatus,
};
use std::collections::HashMap;
use std::net::Ipv4Addr;
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

    let my_ifaddrs = my_ipv4_interfaces();
    println!("My IPv4 addr(s): {:?}", &my_ifaddrs);

    let host_ipv4 = my_ifaddrs[0].ip.to_string();
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
        &host_ipv4,
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
                    println!(
                        "Resolved a new service: {} addr(s): {:?}",
                        info.get_fullname(),
                        info.get_addresses()
                    );
                    if info.get_fullname().contains(&instance_name) {
                        let mut num = resolve_count_clone.lock().unwrap();
                        *num += 1;
                    }
                    let hostname = info.get_hostname();
                    assert_eq!(hostname, host_name);

                    let addr_set = info.get_addresses();
                    assert_eq!(addr_set.len(), 1);

                    let service_port = info.get_port();
                    assert_eq!(service_port, port);

                    let properties = info.get_properties();
                    assert!(properties.get("property_1").is_some());
                    assert!(properties.get("property_2").is_some());
                    assert_eq!(properties.len(), 3);
                    assert!(info.get_property("property_1").is_some());
                    assert!(info.get_property("property_2").is_some());
                    assert_eq!(info.get_property_val("property_1"), Some("test"));
                    assert_eq!(info.get_property_val("property_2"), Some("1"));

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

    // Try to flood the browsing until we got Error::Again.
    loop {
        match d.browse(ty_domain) {
            Ok(_chan) => {}
            Err(Error::Again) => break,
            Err(_e) => assert!(false), // Should not happen.
        }
    }
    println!("Service browse ({}) returns Error::Again", &ty_domain);

    // Wait a bit to let the daemon process commands in the channel.
    sleep(Duration::from_millis(1200));

    // Unregister the service
    let receiver = d.unregister(&fullname).unwrap();
    let response = receiver.recv().unwrap();
    assert!(matches!(response, UnregisterStatus::OK));

    sleep(Duration::from_secs(1));

    let count = resolve_count.lock().unwrap();
    assert_eq!(*count, 1);

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
        host_ipv4,
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
fn service_without_properties_with_alter_net() {
    // Create a daemon
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    // Register a service without properties.
    let ty_domain = "_serv-no-prop._tcp.local.";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let instance_name = now.as_micros().to_string(); // Create a unique name.
    let ifv4_addrs = &my_ipv4_interfaces();
    let first_ipv4 = ifv4_addrs[0].ip;
    let alter_ipv4 = ipv4_alter_net(ifv4_addrs);
    let host_ipv4 = vec![first_ipv4, alter_ipv4];
    let host_name = "my_host.";
    let port = 5201;
    let my_service = ServiceInfo::new(
        ty_domain,
        &instance_name,
        host_name,
        &host_ipv4[..],
        port,
        None,
    )
    .expect("valid service info");
    let fullname = my_service.get_fullname().to_string();
    d.register(my_service)
        .expect("Failed to register our service");
    println!("Registered service with host_ipv4: {:?}", &host_ipv4);

    // Browse for a service
    let browse_chan = d.browse(ty_domain).unwrap();
    let timeout = Duration::from_secs(2);
    loop {
        match browse_chan.recv_timeout(timeout) {
            Ok(event) => match event {
                ServiceEvent::ServiceResolved(info) => {
                    println!(
                        "Resolved a service of {} addr(s): {:?}",
                        &info.get_fullname(),
                        info.get_addresses()
                    );
                    assert_eq!(fullname.as_str(), info.get_fullname());
                    let addrs = info.get_addresses();
                    assert_eq!(addrs.len(), 1); // first_ipv4 but no alter_ipv4.
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

    d.shutdown().unwrap();
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
    assert_eq!(prop_cap_case.val(), "one");

    // Verify the original property name is kept.
    let prop_mixed = my_service.get_property("prop_cap_lower").unwrap();
    assert_eq!(prop_mixed.key(), "prop_Cap_Lower");
}

#[test]
fn test_into_txt_properties() {
    // Verify (&str, String) tuple is supported.
    let properties = vec![("key1", String::from("val1"))];
    let txt_props = properties.into_txt_properties();
    assert_eq!(txt_props.get_property_val("key1").unwrap(), "val1");

    // Verify (String, String) tuple is supported.
    let properties = vec![(String::from("key2"), String::from("val2"))];
    let txt_props = properties.into_txt_properties();
    assert_eq!(txt_props.get_property_val("key2").unwrap(), "val2");
}

#[test]
fn service_with_invalid_addr() {
    // Create a daemon
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    // Register a service without properties.
    let ty_domain = "_invalid-addr._tcp.local.";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let instance_name = now.as_micros().to_string(); // Create a unique name.
    let ifv4_addrs = &my_ipv4_interfaces();
    let alter_ipv4 = ipv4_alter_net(ifv4_addrs);
    let host_name = "my_host.";
    let port = 5201;
    let my_service = ServiceInfo::new(
        ty_domain,
        &instance_name,
        host_name,
        &alter_ipv4,
        port,
        None,
    )
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
    let host_ipv4 = my_ipv4_interfaces()[0].ip.to_string();
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
                        println!("Resolved a service of {}", &info.get_fullname());
                        assert_eq!(fullname.as_str(), info.get_fullname());
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
    // Register a service with a name len > 15.
    let service_name_too_long = "_service-name-too-long._udp.local.";
    let host_ipv4 = "127.0.0.1";
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
    .expect("valid service info");
    let result = server_daemon.register(my_service);
    assert!(result.is_err());
    if let Err(e) = result {
        println!("register error: {}", &e);
    }

    server_daemon.shutdown().unwrap();
}

fn my_ipv4_interfaces() -> Vec<Ifv4Addr> {
    // Use a random port for binding test.
    let test_port = fastrand::u16(8000u16..9000u16);

    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| {
            if i.is_loopback() {
                None
            } else {
                match i.addr {
                    IfAddr::V4(ifv4) =>
                    // Use a 'bind' to check if this is a valid IPv4 addr.
                    {
                        match std::net::UdpSocket::bind((ifv4.ip, test_port)) {
                            Ok(_) => Some(ifv4),
                            Err(e) => {
                                println!("bind {}: {}, skipped.", ifv4.ip, e);
                                None
                            }
                        }
                    }
                    _ => None,
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
fn ipv4_alter_net(ifv4_addrs: &Vec<Ifv4Addr>) -> Ipv4Addr {
    let mut net_max = 0;
    for ifv4_addr in ifv4_addrs.iter() {
        let net = ifv4_addr.ip.octets()[0];
        if net > net_max {
            net_max = net;
        }
    }
    Ipv4Addr::new(net_max + 1, 1, 1, 1)
}
