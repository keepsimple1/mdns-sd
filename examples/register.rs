//! Registers a mDNS service.
//!
//! Run with:
//!
//! cargo run --example register <service_type> <instance_name>
//!
//! Example:
//!
//! cargo run --example register _my-hello._udp.local. test1
//!

use mdns_sd::{ServiceDaemon, ServiceInfo};

fn main() {
    // Create a new mDNS daemon.
    let mdns = ServiceDaemon::new().expect("Could not create service daemon");
    let service_type = match std::env::args().nth(1) {
        Some(arg) => arg,
        None => {
            println!("ERROR: register requires a service_type as the 1st argument. For example:");
            println!("cargo run --example register _my-hello._udp.local. test1");
            return;
        }
    };
    let instance_name = match std::env::args().nth(2) {
        Some(arg) => arg,
        None => {
            println!("ERROR: require a instance_name as the 2nd argument. For example: ");
            println!("cargo run --example register _my-hello._udp.local. test1");
            return;
        }
    };

    // With `enable_addr_auto()`, we can give empty addrs and let the lib find them.
    // If the caller knows specific addrs to use, then assign the addrs here.
    let my_addrs = "";
    let service_hostname = "mdns-example.local.";
    let port = 3456;

    // The key string in TXT properties is case insensitive. Only the first
    // (key, val) pair will take effect.
    let properties = vec![("PATH", "one"), ("Path", "two"), ("PaTh", "three")];

    // Register a service.
    let service_info = ServiceInfo::new(
        &service_type,
        &instance_name,
        service_hostname,
        my_addrs,
        port,
        &properties[..],
    )
    .expect("valid service info")
    .enable_addr_auto();

    // Optionally, we can monitor the daemon events.
    let monitor = mdns.monitor().expect("Failed to monitor the daemon");

    mdns.register(service_info)
        .expect("Failed to register mDNS service");

    println!("Registered service {}.{}", &instance_name, &service_type);

    // Only do this if we monitor the daemon events, which is optional.
    while let Ok(event) = monitor.recv() {
        println!("Daemon event: {:?}", &event);
    }
}
