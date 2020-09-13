pub fn socket(listen_on: std::net::SocketAddr) -> std::net::UdpSocket {
    let attempt = std::net::UdpSocket::bind(listen_on);
    let socket;
    match attempt {
        Ok(sock) => {
            println!("Bound socket to {}", listen_on);
            socket = sock;
        }
        Err(err) => panic!("Could not bind: {}", err),
    }
    socket
}

pub fn read_message(socket: std::net::UdpSocket) -> Vec<u8> {
    let mut buf: [u8; 1] = [0; 1];
    println!("Reading data");
    let result = socket.recv_from(&mut buf);
    drop(socket);
    let data;
    match result {
        Ok((amt, src)) => {
            println!("Received data from {}", src);
            data = Vec::from(&buf[0..amt]);
        }
        Err(err) => panic!("Read error: {}", err),
    }
    data
}

pub fn send_message(send_addr: std::net::SocketAddr, target: std::net::SocketAddr, data: Vec<u8>) {
    let socket = socket(send_addr);
    println!("Sending data");
    let result = socket.send_to(&data, target);
    drop(socket);
    match result {
        Ok(amt) => println!("Sent {} bytes", amt),
        Err(err) => panic!("Write error: {}", err),
    }
}

pub fn listen(listen_on: std::net::SocketAddr) -> std::thread::JoinHandle<Vec<u8>> {
    let socket = socket(listen_on);
    let handle = std::thread::spawn(move || read_message(socket));
    handle
}
