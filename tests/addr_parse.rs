#[cfg(feature = "ipnet")]
use ipnet::{Ipv4AddrRange, Ipv4Net};
use mdns_sd::AsAddr;
use nix::sys::socket::Ipv4Addr;

#[test]
fn test_addr_str() {
    assert_eq!(
        "127.0.0.1".as_addr(),
        Ok([Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1))].into())
    );

    let addr = "127.0.0.1".to_string();
    assert_eq!(
        addr.as_addr(),
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

    #[cfg(feature = "ipnet")]
    {
        assert_eq!(
            "127.0.0.0/31".as_addr(),
            Ok([
                Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 0)),
                Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1))
            ]
            .into())
        );

        assert_eq!(
            "127.0.0.0/31,127.1.0.0".as_addr(),
            Ok([
                Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 0)),
                Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)),
                Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 1, 0, 0))
            ]
            .into())
        )
    }
}

#[test]
fn test_addr_slice() {
    assert_eq!(
        ["127.0.0.1"].as_slice().as_addr(),
        Ok([Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1))].into())
    );

    assert_eq!(
        ["127.0.0.1", "127.0.0.2"].as_slice().as_addr(),
        Ok([
            Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)),
            Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 2))
        ]
        .into())
    );

    assert_eq!(
        vec!["127.0.0.1", "127.0.0.2"].as_slice().as_addr(),
        Ok([
            Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)),
            Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 2))
        ]
        .into())
    );

    #[cfg(feature = "ipnet")]
    {
        assert_eq!(
            ["127.0.0.0/31", "127.0.0.2"].as_slice().as_addr(),
            Ok([
                Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 0)),
                Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)),
                Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 2))
            ]
            .into())
        );
    }
}

#[test]
fn test_addr_ip() {
    let ip = std::net::Ipv4Addr::new(127, 0, 0, 1);

    assert_eq!(
        ip.as_addr(),
        Ok([Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)),].into())
    );

    assert_eq!(
        Ipv4Addr::from_std(&ip).as_addr(),
        Ok([Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)),].into())
    );
}

#[cfg(feature = "ipnet")]
#[test]
fn test_addr_ipnet() {
    let range = Ipv4AddrRange::new(
        std::net::Ipv4Addr::new(127, 0, 0, 1),
        std::net::Ipv4Addr::new(127, 0, 0, 2),
    );

    assert_eq!(
        range.as_addr(),
        Ok([
            Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1)),
            Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 2))
        ]
        .into())
    );

    let net = Ipv4Net::new(std::net::Ipv4Addr::new(127, 0, 0, 0), 31).unwrap();
    assert_eq!(
        net.as_addr(),
        Ok([
            Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 0)),
            Ipv4Addr::from_std(&std::net::Ipv4Addr::new(127, 0, 0, 1))
        ]
        .into())
    );
}
