pub fn local_socket(dst_ip: &str, ttl: u32) -> std::io::Result<()> {
    {
        let ip = std::net::Ipv4Addr::UNSPECIFIED;
        let addr = (ip, 33254);
        let socket_rcx = std::net::UdpSocket::bind(addr).expect("could not bind to address");
        dbg!(&socket_rcx);
        let ip = std::net::Ipv4Addr::UNSPECIFIED;
        let addr = (ip, 33255);
        let socket_trx = std::net::UdpSocket::bind(addr).expect("could not bind to address");
        dbg!(&socket_trx);

        socket_trx
            .set_nonblocking(false)
            .expect("could not change the blocking mode");

        let five_seconds = std::time::Duration::new(5, 0);
        socket_rcx
            .set_read_timeout(Some(five_seconds))
            .expect("could not set read timeout");
        socket_trx
            .set_write_timeout(Some(five_seconds))
            .expect("could not set write timeout");

        for t in 1..ttl {
            let mut buf = [0; 10];

            socket_trx.set_ttl(t).expect("set_ttl call failed");
            print!(
                "socket TTL: {}\n",
                socket_trx
                    .ttl()
                    .expect("could not read TTL from the socket")
            );

            let dst: std::net::SocketAddr =
                std::net::ToSocketAddrs::to_socket_addrs(&(dst_ip, 33254))
                    .expect("could not convert URL to socket")
                    .next()
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
                    .expect("could not establish target connection");
            dbg!(dst);

            let _n = &socket_trx.send_to(&buf, dst).expect("could not send data");
            match socket_trx.take_error() {
                Ok(Some(error)) => println!("UdpSocket error: {:?}", error),
                Ok(None) => {}
                Err(error) => println!("UdpSocket.take_error failed: {:?}", error),
            };

            match socket_rcx.recv_from(&mut buf) {
                Ok((num_bytes_read, src)) => {
                    let _buf = &mut buf[..num_bytes_read];
                    print!("packet received on {:?} from {:?}\n", socket_rcx, src);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    print!("IO WouldBlock error: {}\n", e);
                }
                Err(e) => {
                    print!("encountered IO error: {}\n", e);
                    std::process::exit(1);
                }
            };

            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
    }
    Ok(())
}

pub fn traceroute(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let all_interfaces: Vec<pnet::datalink::NetworkInterface> = pnet::datalink::interfaces();

    let default_interface: Option<&pnet::datalink::NetworkInterface> = all_interfaces
        .iter()
        .filter(|e| e.is_up() && !e.is_loopback() && e.ips.len() > 0)
        .next();

    let interface: &pnet::datalink::NetworkInterface = match default_interface {
        Some(interface) => {
            print!("Found default interface with [{}]\n", interface.name);
            interface
        }
        None => {
            return Err(Box::<dyn std::error::Error>::from(
                "Error while finding the default interface",
            ));
        }
    };

    // OSI model layers
    // https://en.wikipedia.org/wiki/OSI_model
    //
    // Layer 2
    //
    let (_tx, _rx): (
        Box<dyn pnet::datalink::DataLinkSender>,
        Box<dyn pnet::datalink::DataLinkReceiver>,
    ) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(Box::<dyn std::error::Error>::from(
                "could not handle this channel type",
            ))
        }

        Err(e) => {
            return Err(Box::<dyn std::error::Error>::from(format!(
                "An error occurred when creating the datalink channel: {}",
                e,
            )))
        }
    };

    // OSI model layers
    // https://en.wikipedia.org/wiki/OSI_model
    //
    // Layer 3
    //
    // The channel type specifies what layer to send and receive
    // packets at, and the transport protocol you wish to implement.
    // For example, Layer4(Ipv4(IpNextHeaderProtocols::Udp)) would
    // allow sending and receiving UDP packets using IPv4; whereas
    // Layer3(IpNextHeaderProtocols::Udp) would include the IPv4
    // Header in received values, and require manual construction of
    // an IP header when sending.
    //
    let (mut tx, mut rx): (
        pnet::transport::TransportSender,
        pnet::transport::TransportReceiver,
    ) = match pnet::transport::transport_channel(
        65535,
        pnet::transport::TransportChannelType::Layer3(
            pnet::packet::ip::IpNextHeaderProtocols::Icmp,
        ),
    ) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            return Err(Box::<dyn std::error::Error>::from(format!(
                "An error occurred when creating the transport channel: {}",
                e,
            )))
        }
    };

    let addr: std::net::SocketAddr = std::net::ToSocketAddrs::to_socket_addrs(&(url, 80))
        .expect("could not convert URL to socket")
        .next()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        .expect("could not establish target connection");

    let dest: std::net::Ipv4Addr = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(Box::<dyn std::error::Error>::from(
                "unsupported IPv6 address\n",
            ))
        }
    };

    print!(
        "The URL {} resolves in {}. Sending ICMP Echo request\n",
        url, addr
    );

    // RFC 792 https://tools.ietf.org/html/rfc792
    //
    // Echo or Echo Reply Message
    //
    //     0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    //     6 7 8 9 0 1
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     | Type | Code | Checksum |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     | Identifier | Sequence Number |
    //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //     | Data ... +-+-+-+-+-

    const IP_HEADER_LENGTH: usize = 20;
    const ICMP_HEADER_LENGTH: usize = 8;
    const IP_TOTAL_LENGTH: usize = IP_HEADER_LENGTH + ICMP_HEADER_LENGTH;
    const ICMP_RECEIVE_TIMEOUT: u64 = 5;
    const MAX_TTL: u8 = 32;

    fn new_icmp_echo_request<'a>(
        dest: std::net::Ipv4Addr,
        ttl: u8,
    ) -> Option<pnet::packet::ipv4::MutableIpv4Packet<'a>> {
        let ipv4_raw_packet = vec![0u8; IP_TOTAL_LENGTH];
        let mut p: pnet::packet::ipv4::MutableIpv4Packet =
            pnet::packet::ipv4::MutableIpv4Packet::owned(ipv4_raw_packet)
                .expect("could not create a IPv4 packet");
        p.set_version(4);
        p.set_header_length((IP_HEADER_LENGTH * 8 / 32) as u8);
        p.set_total_length(IP_TOTAL_LENGTH as u16);
        p.set_ttl(ttl);
        p.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Icmp);
        p.set_destination(dest);

        let icmp_raw_packet = vec![0u8; ICMP_HEADER_LENGTH];

        let mut icmp_packet =
            pnet::packet::icmp::echo_request::MutableEchoRequestPacket::owned(icmp_raw_packet)
                .expect("could not create ICMP request packet");
        icmp_packet.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoRequest);
        icmp_packet.set_identifier(0);
        icmp_packet.set_sequence_number(ttl as u16);
        let checksum = pnet::packet::icmp::checksum(
            &pnet::packet::icmp::IcmpPacket::new(pnet::packet::Packet::packet(&icmp_packet))
                .expect("could not create ICMP packet"),
        );
        icmp_packet.set_checksum(checksum);

        p.set_payload(pnet::packet::Packet::packet(&icmp_packet));

        Some(p)
    }

    for ttl in 1..MAX_TTL {
        let echo_request = new_icmp_echo_request(dest, ttl)
            .ok_or("could not generate ICMP packet".to_string())
            .expect("could not generate PING");

        tx.send_to(echo_request, std::net::IpAddr::V4(dest))
            .map_err(|e| e.to_string())
            .expect("could not send PING");

        let mut iter: pnet::transport::IcmpTransportChannelIterator =
            pnet::transport::icmp_packet_iter(&mut rx);

        match iter.next_with_timeout(std::time::Duration::new(ICMP_RECEIVE_TIMEOUT, 0)) {
            Ok(opt) => match opt {
                Some((packet, addr)) => {
                    print!(
                        "- TTL: \t{: >2},\tpacket: {:?},\taddr: {}\n",
                        ttl, packet, addr
                    );
                    if addr == dest {
                        print!("found\n");
                        return Ok(());
                    }
                }
                None => print!("- TTL:\t{: >2}\t*.*.*\n", ttl),
            },
            Err(e) => return Err(Box::<dyn std::error::Error>::from(e)),
        };

        std::thread::sleep(std::time::Duration::from_millis(1000));
    }

    return Err(Box::<dyn std::error::Error>::from(
        format!("could not get the host with a MAX TTL of {}", MAX_TTL).to_string(),
    ));
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
