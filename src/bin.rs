fn main() -> Result<(), Box<dyn std::error::Error>> {
    trcrtlib::local_socket("0.0.0.0", 3)?;
    trcrtlib::traceroute("wikipedia.org")
}
