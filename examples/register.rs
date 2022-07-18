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

use if_addrs::{IfAddr, Ifv4Addr};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::net::Ipv4Addr;

fn main() {
    // Create a new mDNS daemon.
    let mdns = ServiceDaemon::new().expect("Could not create service daemon");
    let service_type = std::env::args()
        .nth(1)
        .expect("require a service_type as the 1st argument");
    let instance_name = std::env::args()
        .nth(2)
        .expect("require a instance_name as the 2nd argument");
    let my_addrs: Vec<Ipv4Addr> = my_ipv4_interfaces().iter().map(|i| i.ip).collect();
    let service_hostname = "mdns-example.local.";
    let port = 3456;

    // Register a service.
    let service_info = ServiceInfo::new(
        &service_type,
        &instance_name,
        service_hostname,
        &my_addrs[..],
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

fn my_ipv4_interfaces() -> Vec<Ifv4Addr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| {
            if i.is_loopback() {
                None
            } else {
                match i.addr {
                    IfAddr::V4(ifv4) => Some(ifv4),
                    _ => None,
                }
            }
        })
        .collect()
}
