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
//! Options:
//! "--unregister": automatically unregister after 2 seconds.

use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::{env, thread, time::Duration};

fn main() {
    // Simple command line options.
    let args: Vec<String> = env::args().collect();
    let mut should_unreg = false;
    for arg in args.iter() {
        match arg.as_str() {
            "--unregister" => should_unreg = true,
            _ => {}
        }
    }

    // Create a new mDNS daemon.
    let mdns = ServiceDaemon::new().expect("Could not create service daemon");
    let service_type = match args.get(1) {
        Some(arg) => arg,
        None => {
            print_usage();
            return;
        }
    };
    let instance_name = match args.get(2) {
        Some(arg) => arg,
        None => {
            print_usage();
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
    let service_fullname = service_info.get_fullname().to_string();
    mdns.register(service_info)
        .expect("Failed to register mDNS service");

    println!("Registered service {}.{}", &instance_name, &service_type);

    // Only do this if we monitor the daemon events, which is optional.
    if let Ok(event) = monitor.recv() {
        println!("Daemon event: {:?}", &event);
    }

    if should_unreg {
        let wait_in_secs = 2;
        println!("Sleeping {} seconds before unregister", wait_in_secs);
        thread::sleep(Duration::from_secs(wait_in_secs));

        let receiver = mdns.unregister(&service_fullname).unwrap();
        while let Ok(event) = receiver.recv() {
            println!("unregister result: {:?}", &event);
        }
    }
}

fn print_usage() {
    println!("Usage:");
    println!("cargo run --example register <service_type> <instance_name> [--unregister]");
    println!("Options:");
    println!("--unregister: automatically unregister after 2 seconds");
    println!("");
    println!("For example:");
    println!("cargo run --example register _my-hello._udp.local. test1");
}
