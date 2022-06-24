use clap::Parser;
use message::{Class, Message, QueryOrResponse, Type};
use nameserver::get_system_default_nameservers;
use std::{
    error::Error,
    io::Read,
    io::Write,
    net::{IpAddr, Ipv4Addr, TcpStream, UdpSocket},
    str::FromStr,
};

mod message;
mod nameserver;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    hostname: String,

    #[clap(short, long)]
    nameserver: Option<String>,

    #[clap(short, long)]
    qtype: Option<Type>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let nameserver = if let Some(ns) = args.nameserver {
        IpAddr::from_str(&ns)?
    } else {
        let nss = get_system_default_nameservers()?;
        if nss.is_empty() {
            return Err("failed to get default nameservers".into());
        }
        nss[0] // TODO: iterate through these below w/timeouts
    };

    println!("Nameserver: {}", nameserver);

    let qtype = args.qtype.unwrap_or(Type::A);

    let mut response = query_udp(nameserver, &args.hostname, qtype)?;
    if response.header.truncation {
        println!("Response truncated, falling back to TCP...");
        response = query_tcp(nameserver, &args.hostname, qtype)?;
    }

    print_message(&response);

    Ok(())
}

fn query_udp(nameserver: IpAddr, qname: &str, qtype: Type) -> Result<Message, Box<dyn Error>> {
    let query = Message::new_query(qname, qtype, Class::IN);
    let buf = query.serialize()?;

    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    s.connect((nameserver, 53))?;
    s.send(&buf)?;

    let mut buf = [0; 512];
    let size = s.recv(&mut buf)?;

    let response = Message::deserialize(&buf[0..size])?;

    Ok(response)
}

fn query_tcp(nameserver: IpAddr, qname: &str, qtype: Type) -> Result<Message, Box<dyn Error>> {
    let query = Message::new_query(qname, qtype, Class::IN);
    let buf = query.serialize()?;

    let mut s = TcpStream::connect((nameserver, 53))?;
    s.set_nodelay(true)?;

    let write_len = buf.len();
    let write_len_header = [(write_len >> 8) as u8, write_len as u8];
    s.write_all(&write_len_header[..])?;
    s.write_all(&buf)?;
    s.flush()?;

    let mut len_header = [0_u8; 2];
    s.read_exact(&mut len_header)?;
    let len = (len_header[0] as usize) << 8 | len_header[1] as usize;

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
