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
    env_logger::builder().format_timestamp_millis().init();

    let mut service_type = match std::env::args().nth(1) {
        Some(arg) => arg,
        None => {
            print_usage();
            return;
        }
    };
    service_type.push_str(".local.");

    // Create a daemon
    let mdns = ServiceDaemon::new().expect("Failed to create daemon");
    mdns.use_service_detailed(true)
        .expect("Failed to use service detailed");

    // Browse for the service type
    let receiver = mdns.browse(&service_type).expect("Failed to browse");

    let now = std::time::Instant::now();
    while let Ok(event) = receiver.recv() {
        match event {
            ServiceEvent::ServiceDetailed(info) => {
                println!(
                    "At {:?}: Resolved a new service: {}\n host: {}\n port: {}",
                    now.elapsed(),
                    info.fullname,
                    info.host,
                    info.port,
                );
                for addr in info.addresses.iter() {
                    println!(" Address: {addr}");
                }
                for prop in info.txt_properties.iter() {
                    println!(" Property: {}", prop);
                }
            }
            other_event => {
                println!("At {:?}: {:?}", now.elapsed(), &other_event);
            }
        }
    }
}

fn print_usage() {
    println!("Usage: cargo run --example query <service_type_without_domain_postfix>");
    println!("Example: ");
    println!("cargo run --example query _my-service._udp");
    println!();
    println!("You can also do a meta-query per RFC 6763 to find which services are available:");
    println!("cargo run --example query _services._dns-sd._udp");
}
