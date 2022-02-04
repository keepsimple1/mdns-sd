use mdns_sd::{Error, ServiceDaemon, ServiceEvent, ServiceInfo, UnregisterStatus};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread::sleep,
    time::{Duration, SystemTime},
};

/// This test covers:
/// register(announce), browse(query), response, unregister, shutdown.
#[test]
fn integration_success() {
    // Create a daemon
    let d = ServiceDaemon::new().expect("Failed to create daemon");

    // Register a service
    let ty_domain = "_mdns-sd-my-test._udp.local.";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let instance_name = now.as_micros().to_string(); // Create a unique name.
    let host_ipv4 = "192.168.1.12";
    let host_name = "192.168.1.12.";
    let port = 5200;
    let mut properties = HashMap::new();
    properties.insert("property_1".to_string(), "test".to_string());
    properties.insert("property_2".to_string(), "1".to_string());
    properties.insert("property_3".to_string(), "1234".to_string());

    let my_service = ServiceInfo::new(
        ty_domain,
        &instance_name,
        host_name,
        host_ipv4,
        port,
        Some(properties),
    );
    let fullname = my_service.get_fullname().to_string();
    d.register(my_service)
        .expect("Failed to register our service");

    // Browse for a service
    let resolve_count = Arc::new(Mutex::new(0));
    let resolve_count_clone = resolve_count.clone();
    let remove_count = Arc::new(Mutex::new(0));
    let remove_count_clone = remove_count.clone();

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
                    println!("Resolved a new service: {}", info.get_fullname());
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

    // Wait a bit to let the daemon process commands in the channel.
    sleep(Duration::from_secs(1));

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

    // Verify metrics.
    let metrics_receiver = d.get_metrics().unwrap();
    let metrics = metrics_receiver.recv().unwrap();
    println!("metrics: {:?}", &metrics);
    assert_eq!(metrics["register"], 1);
    assert_eq!(metrics["unregister"], 1);
    assert_eq!(metrics["register-resend"], 1);
    assert_eq!(metrics["unregister-resend"], 1);
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
    );
    d.register(service2)
        .expect("Failed to register the 2nd service");

    // Browse using the special meta-query.
    let meta_query = "_services._dns-sd._udp.local.";
    let browse_chan = d.browse(meta_query).unwrap();

    while let Ok(event) = browse_chan.recv() {
        match event {
            ServiceEvent::ServiceFound(ty_domain, fullname) => {
                println!("Found a service of {}: {}", &ty_domain, &fullname);
                // Among all services found, should have our 2nd service.
                if fullname == service2_type {
                    break;
                }
            }
            _ => sleep(Duration::from_millis(100)),
        }
    }

    // Shutdown
    d.shutdown().unwrap();
}
