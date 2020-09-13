/// RFC 792
///
///
/// Echo or Echo Reply Message
///
///     0                   1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |     Type      |     Code      |          Checksum             |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |           Identifier          |        Sequence Number        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |     Data ...
///    +-+-+-+-+-
pub fn new_icmp_echo_request<'a>(
    dest: std::net::Ipv4Addr,
    ttl: u8,
) -> Option<pnet::packet::ipv4::MutableIpv4Packet<'a>> {
    let ipv4_raw_packet = vec![0u8; crate::packets::IP_ICMP_TOTAL_LENGTH];
    let mut p: pnet::packet::ipv4::MutableIpv4Packet =
        pnet::packet::ipv4::MutableIpv4Packet::owned(ipv4_raw_packet)
            .expect("could not create a IPv4 packet");
    p.set_version(4);
    p.set_header_length((crate::packets::IP_HEADER_LENGTH * 8 / 32) as u8);
    p.set_total_length(crate::packets::IP_ICMP_TOTAL_LENGTH as u16);
    p.set_ttl(ttl);
    p.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Icmp);
    p.set_destination(dest);

    let icmp_raw_packet = vec![0u8; crate::packets::ICMP_HEADER_LENGTH];

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

    // The size (in bytes) of a EchoRequest instance when converted into a byte-array.
    log::debug!(
        "ICMP Packet size: {} bytes",
        pnet::packet::PacketSize::packet_size(&icmp_packet),
    );

    p.set_payload(pnet::packet::Packet::packet(&icmp_packet));

    log::debug!(
        "IPv4 Packet header length: {}, total length: {}",
        pnet::packet::ipv4::MutableIpv4Packet::get_header_length(&p),
        pnet::packet::ipv4::MutableIpv4Packet::get_total_length(&p),
    );

    Some(p)
}
