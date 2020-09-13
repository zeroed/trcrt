/// RFC 768
/// User Datagram Protocol
///
/// https://tools.ietf.org/html/rfc768
///
///                  0      7 8     15 16    23 24    31
///                 +--------+--------+--------+--------+
///                 |     Source      |   Destination   |
///                 |      Port       |      Port       |
///                 +--------+--------+--------+--------+
///                 |                 |                 |
///                 |     Length      |    Checksum     |
///                 +--------+--------+--------+--------+
///                 |
///                 |          data octets ...
///                 +---------------- ...
///
///                      User Datagram Header Format
pub fn new_udp_packet<'a>(
    src: std::net::Ipv4Addr,
    dest: std::net::Ipv4Addr,
    ttl: u8,
) -> Option<pnet::packet::ipv4::MutableIpv4Packet<'a>> {
    let ipv4_raw_packet = vec![0u8; crate::packets::IP_UDP_TOTAL_LENGTH];
    let mut p: pnet::packet::ipv4::MutableIpv4Packet =
        pnet::packet::ipv4::MutableIpv4Packet::owned(ipv4_raw_packet)
            .expect("could not create a IPv4 packet");
    p.set_version(4);
    p.set_header_length((crate::packets::IP_HEADER_LENGTH * 8 / 32) as u8);
    p.set_total_length(crate::packets::IP_UDP_TOTAL_LENGTH as u16);
    p.set_ttl(ttl);
    p.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
    p.set_destination(dest);

    let udp_raw_packet = vec![0u8; crate::packets::UDP_HEADER_LENGTH];

    let mut udp_packet = pnet::packet::udp::MutableUdpPacket::owned(udp_raw_packet)
        .expect("could not create UDP request packet");
    let u = std::convert::Into::<u32>::into(dest);
    udp_packet.set_destination(u as u16);
    let u = std::convert::Into::<u32>::into(src);
    udp_packet.set_source(u as u16);
    let checksum = pnet::packet::udp::ipv4_checksum(
        &pnet::packet::udp::UdpPacket::new(pnet::packet::Packet::packet(&udp_packet))
            .expect("could not create UDP packet"),
        &src,
        &dest,
    );
    udp_packet.set_checksum(checksum);

    // The size (in bytes) of a Udp instance when converted into a byte-arryay.
    log::debug!(
        "UDP Packet size: {} bytes, length: {}",
        pnet::packet::PacketSize::packet_size(&udp_packet),
        udp_packet.get_length(),
    );

    p.set_payload(pnet::packet::Packet::packet(&udp_packet));

    log::debug!(
        "IPv4 Packet header length: {}, total length: {}",
        pnet::packet::ipv4::MutableIpv4Packet::get_header_length(&p),
        pnet::packet::ipv4::MutableIpv4Packet::get_total_length(&p),
    );

    Some(p)
}
