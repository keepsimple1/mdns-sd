use mdns_sd::AsIpv4Addrs;
use std::collections::HashSet;
use std::net::Ipv4Addr;

#[test]
fn test_addr_str() {
    assert_eq!(
        "127.0.0.1".as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::new(127, 0, 0, 1));

            set
        })
    );

    let addr = "127.0.0.1".to_string();
    assert_eq!(
        addr.as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::new(127, 0, 0, 1));

            set
        })
    );

    // verify that `&String` also works.
    assert_eq!(
        (&addr).as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::new(127, 0, 0, 1));

            set
        })
    );

    assert_eq!(
        "127.0.0.1,127.0.0.2".as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::new(127, 0, 0, 1));
            set.insert(Ipv4Addr::new(127, 0, 0, 2));

            set
        })
    );

    // verify that an empty string parsed into an empty set.
    assert_eq!("".as_ipv4_addrs(), Ok(HashSet::new()));
}

#[test]
fn test_addr_slice() {
    assert_eq!(
        (&["127.0.0.1"][..]).as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::new(127, 0, 0, 1));

            set
        })
    );

    assert_eq!(
        (&["127.0.0.1", "127.0.0.2"][..]).as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::new(127, 0, 0, 1));
            set.insert(Ipv4Addr::new(127, 0, 0, 2));

            set
        })
    );

    assert_eq!(
        (&vec!["127.0.0.1", "127.0.0.2"][..]).as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::new(127, 0, 0, 1));
            set.insert(Ipv4Addr::new(127, 0, 0, 2));

            set
        })
    );
}

#[test]
fn test_addr_ip() {
    let ip = Ipv4Addr::new(127, 0, 0, 1);

    assert_eq!(
        ip.as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::new(127, 0, 0, 1));

            set
        })
    );

    assert_eq!(
        (&ip).as_ipv4_addrs(),
        Ok({
            let mut set = HashSet::new();
            set.insert(Ipv4Addr::new(127, 0, 0, 1));

            set
        })
    );
}
