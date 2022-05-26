use clap::Parser;
use message::{Class, Message, QueryOrResponse, Type};
use nameserver::get_system_default_nameservers;
use std::{
    error::Error,
    net::{IpAddr, UdpSocket},
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
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let nameserver = if let Some(ns) = args.nameserver {
        let addr = IpAddr::from_str(&ns)?;
        (addr, 53)
    } else {
        let nss = get_system_default_nameservers()?;
        if nss.is_empty() {
            return Err("failed to get default nameservers".into());
        }
        (nss[0], 53) // TODO: iterate through these below w/timeouts instead of picking first
    };

    println!("Nameserver: {}", nameserver.0);

    let s = UdpSocket::bind(("0.0.0.0", 0))?;
    s.connect(nameserver)?;

    let query = Message::new_query(args.hostname, Type::A, Class::IN);
    let buf = query.serialize()?;
    s.send(&buf)?;

    let mut buf = [0; 512];
    let size = s.recv(&mut buf)?;

    let response = Message::deserialize(&buf[0..size])?;

    print_message(&response);

    Ok(())
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
                "    {} {} {} {} {:?}",
                a.name, a.ttl, a.rclass, a.rtype, a.rdata
            );
        }
    }
    if !m.authorities.is_empty() {
        println!("Authorities:");
        for a in &m.authorities {
            println!(
                "    {} {} {} {} {:?}",
                a.name, a.ttl, a.rclass, a.rtype, a.rdata
            );
        }
    }
    if !m.additionals.is_empty() {
        println!("Additionals:");
        for a in &m.additionals {
            println!(
                "    {} {} {} {} {:?}",
                a.name, a.ttl, a.rclass, a.rtype, a.rdata
            );
        }
    }
}
