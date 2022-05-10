use ipnet::Ipv4Net;
use mdns_sd::AsAddr;
use nix::sys::socket::Ipv4Addr;

#[test]
fn test_addr_str() {
    assert_eq!(
        "127.0.0.1".as_addr(),
        Ok([Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1))].into())
    );

    assert_eq!(
        "127.0.0.1,127.0.0.2".as_addr(),
        Ok([
            Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)),
            Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 2))
        ]
        .into())
    );
}
