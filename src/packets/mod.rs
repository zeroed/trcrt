pub mod icmp;
pub mod udp;

const IP_HEADER_LENGTH: usize = 20;

// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
const ICMP_HEADER_LENGTH: usize = 8;

// https://en.wikipedia.org/wiki/User_Datagram_Protocol
const UDP_HEADER_LENGTH: usize = 8;

const IP_ICMP_TOTAL_LENGTH: usize = IP_HEADER_LENGTH + ICMP_HEADER_LENGTH;

const IP_UDP_TOTAL_LENGTH: usize = IP_HEADER_LENGTH + UDP_HEADER_LENGTH;

pub const ICMP_RECEIVE_TIMEOUT: u64 = 5;

pub const UDP_RECEIVE_TIMEOUT: u64 = 5;

pub const MAX_TTL: u8 = 60;
