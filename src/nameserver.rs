use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
    str::FromStr,
};

/// Parse /etc/resolv.conf to get the system default nameservers. Based on my research
/// this seems to be the preferred way on *nix (vs. calling a library API).
/// TODO someday: make a variant for Windows
pub fn get_system_default_nameservers() -> Result<Vec<IpAddr>, Box<dyn Error>> {
    let f = File::open("/etc/resolv.conf")?;
    let reader = BufReader::new(f);

    let mut result = vec![];

    for line in reader.lines() {
        let line = line?;
        if !line.starts_with("nameserver") {
            continue;
        }

        let (_, ns) = line.split_once(' ').ok_or("weird resolv.conf")?;
        let addr = IpAddr::from_str(ns)?;
        result.push(addr);
    }

    Ok(result)
}
