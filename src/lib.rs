//! # TRCRT
//!
//! `TRCRT` is a collection of useless things to run little experiments and
//! documentation.
//!
//! https://en.wikipedia.org/wiki/Traceroute

mod commons;
mod packets;
mod socket;

/// OSI model layers
/// https://en.wikipedia.org/wiki/OSI_model
///
/// Layer 2
///
/// OSI model layers
/// https://en.wikipedia.org/wiki/OSI_model
///
/// Layer 3
///
/// The channel type specifies what layer to send and receive
/// packets at, and the transport protocol you wish to implement.
/// For example, Layer4(Ipv4(IpNextHeaderProtocols::Udp)) would
/// allow sending and receiving UDP packets using IPv4; whereas
/// Layer3(IpNextHeaderProtocols::Udp) would include the IPv4
/// Header in received values, and require manual construction of
/// an IP header when sending.
pub fn layers() -> std::result::Result<(), Box<dyn std::error::Error>> {
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

    print!("\n--- Layer 2 ---\n");
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

    print!("\n--- Layer 3 ---\n");
    let (_tx, _rx): (
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

    Ok(())
}

pub fn local_socket(url: &str, ttl: u8) -> std::result::Result<(), Box<dyn std::error::Error>> {
    {
        let addr: std::net::SocketAddrV4 = crate::commons::to_ipv4(url).expect("could not resolve");
        let dest: &std::net::Ipv4Addr = addr.ip();

        let five_seconds = std::time::Duration::new(5, 0);

        let tx = std::net::UdpSocket::bind((std::net::Ipv4Addr::BROADCAST, 33254))
            .expect("could not bind the UDP socket to a local address");
        tx.set_write_timeout(Some(five_seconds))
            .expect("could not set write timeout");
        tx.set_read_timeout(Some(five_seconds))
            .expect("could not set read timeout");

        tx.set_nonblocking(false)
            .expect("could not change the blocking mode");

        let src: std::net::Ipv4Addr = match tx
            .local_addr()
            .expect("could not read TX local address")
            .ip()
        {
            std::net::IpAddr::V4(ip) => {
                log::debug!("socket local address: {}", ip);
                ip
            }
            std::net::IpAddr::V6(_) => {
                return Err(Box::<dyn std::error::Error>::from(
                    "could not support Ipv6 sockets",
                ))
            }
        };
        for t in 1..ttl {
            tx.set_ttl(t as u32)
                .expect("could not set the TTL to the TX socket");

            let packet: pnet::packet::ipv4::MutableIpv4Packet =
                crate::packets::udp::new_udp_packet(src, *dest, t)
                    .expect("could not generate UDP packet");

            let buf: &[u8] = pnet::packet::Packet::packet(&packet);

            let n = &tx.send_to(buf, addr).expect("could not send data");
            match tx.take_error() {
                Ok(Some(error)) => {
                    return Err(Box::<dyn std::error::Error>::from(format!(
                        "UDP socket error: {:?}",
                        error
                    )))
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(Box::<dyn std::error::Error>::from(format!(
                        "UDP socket error: {:?}",
                        error
                    )))
                }
            };

            log::debug!(
                "transmitted {} bytes from {:?} with TTL {}",
                n,
                &tx,
                tx.ttl().expect("could not read TTL from the socket")
            );

            let mut buf = [0u8; 10];
            match tx.recv_from(&mut buf) {
                Ok((num_bytes_read, src)) => {
                    let _buf = &mut buf[..num_bytes_read];
                    print!("packet received on {:?} from {:?}\n", tx, src);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    print!("  * (IO WouldBlock error: {})\n", e);
                }
                Err(e) => {
                    return Err(Box::<dyn std::error::Error>::from(format!(
                        "encountered IO error: {}",
                        e
                    )))
                }
            };

            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    Ok(())
}

/// UDP - User Datagram Protocol
///
/// In computer networking, the User Datagram Protocol (UDP) is one of
/// the core members of the Internet protocol suite. The protocol was
/// designed by David P. Reed in 1980 and formally defined in RFC 768.
/// With UDP, computer applications can send messages, in this case
/// referred to as datagrams, to other hosts on an Internet Protocol
/// (IP) network. Prior communications are not required in order to set
/// up communication channels or data paths.
///
/// UDP uses a simple connectionless communication model with a minimum
/// of protocol mechanisms. UDP provides checksums for data integrity,
/// and port numbers for addressing different functions at the source
/// and destination of the datagram. It has no handshaking dialogues,
/// and thus exposes the user's program to any unreliability of the
/// underlying network; there is no guarantee of delivery, ordering, or
/// duplicate protection. If error-correction facilities are needed at
/// the network interface level, an application may use Transmission
/// Control Protocol (TCP) or Stream Control Transmission Protocol
/// (SCTP) which are designed for this purpose.
///
/// UDP is suitable for purposes where error checking and correction
/// are either not necessary or are performed in the application; UDP
/// avoids the overhead of such processing in the protocol stack.
/// Time-sensitive applications often use UDP because dropping packets
/// is preferable to waiting for packets delayed due to retransmission,
/// which may not be an option in a real-time system.
///
/// UDP is a simple message-oriented transport layer protocol that is
/// documented in RFC 768. Although UDP provides integrity verification
/// (via checksum) of the header and payload,[2] it provides no
/// guarantees to the upper layer protocol for message delivery and the
/// UDP layer retains no state of UDP messages once sent. For this
/// reason, UDP sometimes is referred to as Unreliable Datagram
/// Protocol.[3] If transmission reliability is desired, it must be
/// implemented in the user's application.
///
/// A number of UDP's attributes make it especially suited for certain
/// applications.
///
/// - It is transaction-oriented, suitable for simple query-response
///   protocols such as the Domain Name System or the Network Time
///   Protocol.
///
/// - It provides datagrams, suitable for modeling other protocols such
///   as IP tunneling or remote procedure call and the Network File
///   System.
///
/// - It is simple, suitable for bootstrapping or other purposes
///   without a full protocol stack, such as the DHCP and Trivial File
///   Transfer Protocol.
///
/// - It is stateless, suitable for very large numbers of clients, such
///   as in streaming media applications such as IPTV.
///
/// - The lack of retransmission delays makes it suitable for real-time
///   applications such as Voice over IP, online games, and many
///   protocols using Real Time Streaming Protocol.
///
/// - Because it supports multicast, it is suitable for broadcast
///   information such as in many kinds of service discovery and shared
///   information such as Precision Time Protocol and Routing Information
///   Protocol.
///
/// https://en.wikipedia.org/wiki/User_Datagram_Protocol
pub fn traceroute_udp(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr: std::net::SocketAddrV4 = crate::commons::to_ipv4(url).expect("could not resolve");
    let dest: &std::net::Ipv4Addr = addr.ip();
    let src: std::net::Ipv4Addr = std::net::Ipv4Addr::BROADCAST;

    print!("The URL {} resolves in {}. Sending UDP packet\n", url, addr);

    let (mut tx, mut rx): (
        pnet::transport::TransportSender,
        pnet::transport::TransportReceiver,
    ) = match pnet::transport::transport_channel(
        65535,
        pnet::transport::TransportChannelType::Layer3(pnet::packet::ip::IpNextHeaderProtocols::Udp),
    ) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            return Err(Box::<dyn std::error::Error>::from(format!(
                "An error occurred when creating the transport channel: {}",
                e,
            )))
        }
    };

    for ttl in 1..crate::packets::MAX_TTL {
        let packet: pnet::packet::ipv4::MutableIpv4Packet =
            crate::packets::udp::new_udp_packet(src, *dest, ttl)
                .expect("could not generate UPD packet");

        tx.send_to(packet, std::net::IpAddr::V4(*dest))
            .map_err(|e| e.to_string())
            .expect("could not send packet");

        let mut iter: pnet::transport::UdpTransportChannelIterator =
            pnet::transport::udp_packet_iter(&mut rx);

        match iter.next_with_timeout(std::time::Duration::new(
            crate::packets::UDP_RECEIVE_TIMEOUT,
            0,
        )) {
            Ok(opt) => match opt {
                Some((packet, addr)) => {
                    print!(
                        "- TTL: \t{: >2},\tpacket: {:?},\taddr: {}\n",
                        ttl, packet, addr
                    );
                    if addr == *dest {
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
        format!(
            "could not get the host with a MAX TTL of {}",
            crate::packets::MAX_TTL
        )
        .to_string(),
    ));
}

/// ICMP Traceroute
///
/// The Internet Control Message Protocol (ICMP) is a supporting
/// protocol in the Internet protocol suite. It is used by network
/// devices, including routers, to send error messages and operational
/// information indicating success or failure when communicating with
/// another IP address, for example, an error is indicated when a
/// requested service is not available or that a host or router could
/// not be reached. ICMP differs from transport protocols such as
/// TCP and UDP in that it is not typically used to exchange data
/// between systems, nor is it regularly employed by end-user network
/// applications (with the exception of some diagnostic tools like ping
/// and traceroute).
///
/// ICMP is part of the Internet protocol suite as defined in RFC 792.
/// ICMP messages are typically used for diagnostic or control purposes
/// or generated in response to errors in IP operations (as specified
/// in RFC 1122). ICMP errors are directed to the source IP address of
/// the originating packet.
///
/// For example, every device (such as an intermediate router)
/// forwarding an IP datagram first decrements the time to live (TTL)
/// field in the IP header by one. If the resulting TTL is 0, the
/// packet is discarded and an ICMP time exceeded in transit message is
/// sent to the datagram's source address.
///
/// Many commonly used network utilities are based on ICMP messages.
/// The traceroute command can be implemented by transmitting IP
/// datagrams with specially set IP TTL header fields, and looking for
/// ICMP time exceeded in transit and Destination unreachable messages
/// generated in response. The related ping utility is implemented
/// using the ICMP echo request and echo reply messages.
///
/// ICMP uses the basic support of IP as if it were a higher-level
/// protocol, however, ICMP is actually an integral part of IP.
/// Although ICMP messages are contained within standard IP packets,
/// ICMP messages are usually processed as a special case,
/// distinguished from normal IP processing. In many cases, it is
/// necessary to inspect the contents of the ICMP message and deliver
/// the appropriate error message to the application responsible for
/// transmitting the IP packet that prompted the ICMP message to be
/// sent.
///
/// ICMP is a network-layer protocol. There is no TCP or UDP port
/// number associated with ICMP packets as these numbers are associated
/// with the transport layer above.
///
/// In the seven-layer OSI model of computer networking, the network
/// layer is layer 3. The network layer is responsible for packet
/// forwarding including routing through intermediate routers.
///
/// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
pub fn traceroute_icmp(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr: std::net::SocketAddrV4 = crate::commons::to_ipv4(url).expect("could not resolve");
    let dest: &std::net::Ipv4Addr = addr.ip();

    print!(
        "The URL {} resolves in {}. Sending ICMP Echo request\n",
        url, addr
    );

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

    for ttl in 1..crate::packets::MAX_TTL {
        let echo_request = crate::packets::icmp::new_icmp_echo_request(*dest, ttl)
            .ok_or("could not generate ICMP packet".to_string())
            .expect("could not generate PING");

        tx.send_to(echo_request, std::net::IpAddr::V4(*dest))
            .map_err(|e| e.to_string())
            .expect("could not send PING");

        let mut iter: pnet::transport::IcmpTransportChannelIterator =
            pnet::transport::icmp_packet_iter(&mut rx);

        match iter.next_with_timeout(std::time::Duration::new(
            crate::packets::ICMP_RECEIVE_TIMEOUT,
            0,
        )) {
            Ok(opt) => match opt {
                Some((packet, addr)) => {
                    print!(
                        "- TTL: \t{: >2},\tpacket: {:?},\taddr: {}\n",
                        ttl, packet, addr
                    );
                    if addr == *dest {
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
        format!(
            "could not get the host with a MAX TTL of {}",
            crate::packets::MAX_TTL
        )
        .to_string(),
    ));
}

#[cfg(test)]
mod test {
    use std::net;
    use std::thread;

    #[test]
    fn test_udp() {
        let listen_ip = net::Ipv4Addr::new(127, 0, 0, 1);
        let listen_addr = net::SocketAddrV4::new(listen_ip, 8888);
        let send_ip = net::Ipv4Addr::new(127, 0, 0, 1);
        let send_addr = net::SocketAddrV4::new(send_ip, 8889);
        let future = super::socket::listen(net::SocketAddr::V4(listen_addr));
        let message: Vec<u8> = vec![10];
        thread::sleep(std::time::Duration::new(3, 0));
        super::socket::send_message(
            net::SocketAddr::V4(send_addr),
            net::SocketAddr::V4(listen_addr),
            message,
        );
        println!("Waiting");
        let received = future.join().unwrap();
        println!("Got {} bytes", received.len());
        assert_eq!(1, received.len());
        assert_eq!(10, received[0]);
    }
}
