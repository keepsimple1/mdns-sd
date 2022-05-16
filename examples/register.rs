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
    let service_host_ipv4 = "192.168.1.111";
    let service_hostname = "192.168.1.111.local.";
    let port = 3456;

    // Register a service.
    let service_info = ServiceInfo::new(
        &service_type,
        &instance_name,
        service_hostname,
        service_host_ipv4,
        port,
        None,
    )
    .expect("valid service info");

    mdns.register(service_info)
        .expect("Failed to register mDNS service");

    println!("Registered service {}.{}", &instance_name, &service_type);

    // Running until ctrl-c or killed.
    loop {
        std::thread::sleep(std::time::Duration::from_millis(100))
    }
}
