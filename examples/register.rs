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
    let service_type = std::env::args()
        .nth(1)
        .expect("require a service_type as the 1st argument");
    let instance_name = std::env::args()
        .nth(2)
        .expect("require a instance_name as the 2nd argument");

    // With `enable_addr_auto()`, we can give empty addrs and let the lib find them.
    // If the caller knows specific addrs to use, then assign the addrs here.
    let my_addrs = "";
    let service_hostname = "mdns-example.local.";
    let port = 3456;

    // Register a service.
    let service_info = ServiceInfo::new(
        &service_type,
        &instance_name,
        service_hostname,
        my_addrs,
        port,
        None,
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
