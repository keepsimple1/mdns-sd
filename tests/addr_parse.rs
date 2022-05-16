use std::collections::HashSet;
use std::iter::FromIterator;

use mdns_sd::AsIpv4Addrs;
use nix::sys::socket::Ipv4Addr;

#[test]
fn test_addr_str() {
    assert_eq!(
        "127.0.0.1".as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)));

            set
        })
    );

    let addr = "127.0.0.1".to_string();
    assert_eq!(
        addr.as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)));

            set
        })
    );

    assert_eq!(
        "127.0.0.1,127.0.0.2".as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)));
            set.insert(Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 2)));

            set
        })
    );
}

#[test]
fn test_addr_slice() {
    assert_eq!(
        (&["127.0.0.1"][..]).as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)));

            set
        })
    );

    assert_eq!(
        (&["127.0.0.1", "127.0.0.2"][..]).as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)));
            set.insert(Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 2)));

            set
        })
    );

    assert_eq!(
        (&vec!["127.0.0.1", "127.0.0.2"][..]).as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)));
            set.insert(Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 2)));

            set
        })
    );
}

#[test]
fn test_addr_ip() {
    let ip = std::net::Ipv4Addr::new(127, 0, 0, 1);

    assert_eq!(
        ip.as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)));

            set
        })
    );

    assert_eq!(
        Ipv4Addr::from_std(&ip).as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)));

            set
        })
    );
}
