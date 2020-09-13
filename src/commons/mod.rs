pub fn to_ipv4(dst_url: &str) -> Result<std::net::SocketAddrV4, Box<dyn std::error::Error>> {
    let dst: std::net::SocketAddrV4 =
        match std::net::ToSocketAddrs::to_socket_addrs(&(dst_url, 80 as u16))
            .expect("could not convert URL to socket")
            .next()
        {
            Some(std::net::SocketAddr::V4(addr)) => addr,
            Some(std::net::SocketAddr::V6(_)) => {
                return Err("Socket on IPv6 are not supported".into())
            }
            None => {
                let e: Box<dyn std::error::Error> =
                    Box::new(std::io::Error::from(std::io::ErrorKind::NotFound));
                return Err(e);
            }
        };
    print!("destination address: {:?}\n", dst);
    Ok(dst)
}
