extern crate env_logger;
extern crate log;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    unsafe {
        print!(
            "running as {} ({})\n",
            libc::getuid(),
            std::env::var("LOGNAME").unwrap_or("user".to_string())
        );
    }

    let url: &str = "resolver2.opendns.com";

    print!("--- Traceroute UDP\n");
    trcrtlib::traceroute_udp(url)?;

    print!("--- Traceroute ICMP\n");
    trcrtlib::traceroute_icmp(url)?;

    print!("--- Traceroute Local Socket\n");
    trcrtlib::local_socket(url, 30)?;

    Ok(())
}
