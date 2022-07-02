use clap::Parser;
use nameserver::get_system_default_nameservers;
use rdig::message::{Class, Message, QueryOrResponse, Type};
use std::{
    error::Error,
    io::Read,
    io::Write,
    net::{IpAddr, Ipv4Addr, TcpStream, UdpSocket},
    str::FromStr,
};

mod nameserver;

/// Simple toy program to query DNS like `dig`
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The hostname to look up
    hostname: String,

    /// The nameserver to use
    #[clap(short, long)]
    nameserver: Option<String>,

    /// The type of DNS record to retrieve
    #[clap(short, long, default_value_t = Type::A)]
    qtype: Type,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let nameserver = if let Some(ns) = args.nameserver {
        IpAddr::from_str(&ns).map_err(|e| format!("failed to parse nameserver address: {e}"))?
    } else {
        let nss = get_system_default_nameservers()
            .map_err(|e| format!("failed to get system default nameservers: {e}"))?;
        if nss.is_empty() {
            return Err("no system default nameservers defined".into());
        }
        nss[0] // TODO: iterate through these below w/timeouts
    };

    println!("Nameserver: {}", nameserver);

    let response = query(&args.hostname, args.qtype, nameserver)?;

    print_message(&response);

    Ok(())
}

fn query(hostname: &str, qtype: Type, nameserver: IpAddr) -> Result<Message, Box<dyn Error>> {
    let query = Message::new_query(hostname, qtype, Class::IN);
    let write_buf = query.serialize()?;

    let response = if write_buf.len() <= 512 {
        let mut r = query_udp(nameserver, &write_buf)?;
        if r.header.truncation {
            println!("Response truncated, falling back to TCP...");
            r = query_tcp(nameserver, &write_buf)?;
        }
        r
    } else {
        println!("Large query, falling back to TCP...");
        query_tcp(nameserver, &write_buf)?
    };
    Ok(response)
}

fn query_udp(nameserver: IpAddr, write_buf: &[u8]) -> Result<Message, Box<dyn Error>> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    s.connect((nameserver, 53))?;
    s.send(write_buf)?;

    let mut buf = [0; 512];
    let size = s.recv(&mut buf)?;

    let response = Message::deserialize(&buf[0..size])?;

    Ok(response)
}

fn query_tcp(nameserver: IpAddr, write_buf: &[u8]) -> Result<Message, Box<dyn Error>> {
    let mut s = TcpStream::connect((nameserver, 53))?;
    s.set_nodelay(true)?;

    let write_len = write_buf.len();
    let write_len_header = [(write_len >> 8) as u8, write_len as u8];
    s.write_all(&write_len_header[..])?;
    s.write_all(write_buf)?;
    s.flush()?;

    let mut read_len_header = [0_u8; 2];
    s.read_exact(&mut read_len_header)?;
    let len = (read_len_header[0] as usize) << 8 | read_len_header[1] as usize;

    let mut read_buf = vec![0_u8; len];
    s.read_exact(&mut read_buf)?;

    let response = Message::deserialize(&read_buf)?;

    Ok(response)
}

fn print_message(m: &Message) {
    println!("Header:");
    println!("    ID: {}", m.header.id);
    print!("    Flags:");
    if m.header.qr == QueryOrResponse::Response {
        print!(" QR");
    }
    if m.header.authoritative_answer {
        print!(" AA");
    }
    if m.header.truncation {
        print!(" TC");
    }
    if m.header.recursion_desired {
        print!(" RD");
    }
    if m.header.recursion_available {
        print!(" RA");
    }
    println!();
    println!("    Response code: {}", m.header.response_code);

    if !m.questions.is_empty() {
        println!("Questions:");
        for q in &m.questions {
            println!("    {} {} {}", q.qname, q.qclass, q.qtype);
        }
    }
    if !m.answers.is_empty() {
        println!("Answers:");
        for a in &m.answers {
            println!(
                "    {} {} {} {} {}",
                a.name, a.ttl, a.rclass, a.rtype, a.rdata
            );
        }
    }
    if !m.authorities.is_empty() {
        println!("Authorities:");
        for a in &m.authorities {
            println!(
                "    {} {} {} {} {}",
                a.name, a.ttl, a.rclass, a.rtype, a.rdata
            );
        }
    }
    if !m.additionals.is_empty() {
        println!("Additionals:");
        for a in &m.additionals {
            println!(
                "    {} {} {} {} {}",
                a.name, a.ttl, a.rclass, a.rtype, a.rdata
            );
        }
    }
}
