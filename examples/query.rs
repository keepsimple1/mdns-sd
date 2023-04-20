//! A mDNS query client.
//!
//! Run with:
//!
//!     cargo run --example query <service_type_without_domain>
//!
//! Example:
//!
//!     cargo run --example query _my-service._udp
//!
//! Note: there is no '.' at the end as the program adds ".local."
//! automatically.
//!
//! Keeps listening for new events.

use mdns_sd::{ServiceDaemon, ServiceEvent};

fn main() {
    // Create a daemon
    let mdns = ServiceDaemon::new().expect("Failed to create daemon");

    let mut service_type = match std::env::args().nth(1) {
        Some(arg) => arg,
        None => {
            println!("ERROR: require a service_type as argument. For example: ");
            println!("cargo run --example query _my-service._udp");
            return;
        }
    };

    // Browse for a service type.
    service_type.push_str(".local.");
    let receiver = mdns.browse(&service_type).expect("Failed to browse");

    let now = std::time::Instant::now();
    while let Ok(event) = receiver.recv() {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                println!(
                    "At {:?}: Resolved a new service: {} host: {} port: {} IP: {:?} TXT properties: {:?}",
                    now.elapsed(),
                    info.get_fullname(),
                    info.get_hostname(),
                    info.get_port(),
                    info.get_addresses(),
                    info.get_properties(),
                );
            }
            other_event => {
                println!(
                    "At {:?} : Received other event: {:?}",
                    now.elapsed(),
                    &other_event
                );
            }
        }
    }
}
