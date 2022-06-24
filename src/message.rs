use bitvec::prelude::*;
use std::{error::Error, fmt::Display, net::Ipv4Addr, str::FromStr};

#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    pub fn new_query(qname: &str, qtype: Type, qclass: Class) -> Message {
        let mut msg = Message {
            header: Header::new_query(),
            questions: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };

        let qname = qname.to_owned();

        msg.questions.push(Question {
            qname,
            qtype,
            qclass,
        });
        msg.header.qd_count += 1;

        msg
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut v = self.header.serialize();

        assert_eq!(self.questions.len(), self.header.qd_count as usize);
        assert_eq!(self.answers.len(), self.header.an_count as usize);

        for q in self.questions.iter() {
            let mut buf = q.serialize()?;
            v.append(&mut buf);
        }

        for a in self.answers.iter() {
            let mut buf = a.serialize()?;
            v.append(&mut buf);
        }

        if v.len() > 512 {
            // should we futz with the truncation bit instead of erroring?
            return Err("serialized query too long".into());
        }

        Ok(v)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Message, Box<dyn Error>> {
        let mut i = 0usize;
        let header = Header::deserialize(buf, &mut i)?;

        let mut questions = vec![];
        for _ in 0..header.qd_count {
            questions.push(Question::deserialize(buf, &mut i)?);
        }

        let mut answers = vec![];
        for _ in 0..header.an_count {
            answers.push(ResourceRecord::deserialize(buf, &mut i)?);
        }

        let mut authorities = vec![];
        for _ in 0..header.ns_count {
            authorities.push(ResourceRecord::deserialize(buf, &mut i)?);
        }

        let mut additionals = vec![];
        for _ in 0..header.ar_count {
            additionals.push(ResourceRecord::deserialize(buf, &mut i)?);
        }

        Ok(Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

///////////////
/// Header

#[derive(PartialEq, Eq, Debug)]
pub enum QueryOrResponse {
    Query,
    Response,
}

impl From<bool> for QueryOrResponse {
    fn from(value: bool) -> Self {
        if value {
            QueryOrResponse::Response
        } else {
            QueryOrResponse::Query
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum OpCode {
    Query = 0,
    Iquery = 1,
    Status = 2,
}

impl TryFrom<u8> for OpCode {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(OpCode::Query),
            1 => Ok(OpCode::Iquery),
            2 => Ok(OpCode::Status),
            _ => Err(format!("unknown opcode {value}")),
        }
    }
}

#[derive(Debug)]
pub enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

impl TryFrom<u8> for ResponseCode {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ResponseCode::NoError),
            1 => Ok(ResponseCode::FormatError),
            2 => Ok(ResponseCode::ServerFailure),
            3 => Ok(ResponseCode::NameError),
            4 => Ok(ResponseCode::NotImplemented),
            5 => Ok(ResponseCode::Refused),
            _ => Err(format!("unknown response code {value}")),
        }
    }
}

impl Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ResponseCode::NoError => "NOERROR",
            ResponseCode::FormatError => "FORMATERROR",
            ResponseCode::ServerFailure => "SERVERFAILURE",
            ResponseCode::NameError => "NAMEERROR",
            ResponseCode::NotImplemented => "NOTIMPLEMENTED",
            ResponseCode::Refused => "REFUSED",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub qr: QueryOrResponse,
    pub opcode: OpCode,
    pub authoritative_answer: bool,
    pub truncation: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: ResponseCode,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl Header {
    fn new_query() -> Header {
        Header {
            id: rand::random(),
            qr: QueryOrResponse::Query,
            opcode: OpCode::Query,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: true,
            recursion_available: false,
            response_code: ResponseCode::NoError,
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut pkt: BitArray<[u8; 12], Msb0> = BitArray::ZERO;

        pkt[..=15].store_be(self.id);

        *pkt.get_mut(16).unwrap() = self.qr == QueryOrResponse::Response;

        pkt[17..=20].store(self.opcode as u8);

        *pkt.get_mut(23).unwrap() = self.recursion_desired;

        pkt[32..=47].store_be(self.qd_count);
        pkt[48..=63].store_be(self.an_count);

        pkt.as_raw_slice().to_vec()
    }

    fn deserialize(buf: &[u8], i: &mut usize) -> Result<Header, Box<dyn Error>> {
        let hdr: &BitSlice<u8, Msb0> = BitSlice::from_slice(buf);

        check_space(buf, *i, 12)?; // this covers the entire header

        let id = hdr[0..=15].load_be();

        let raw_qr = *hdr.get(16).unwrap();
        let qr = QueryOrResponse::from(raw_qr);

        let raw_opcode: u8 = hdr[17..=20].load();
        let opcode = OpCode::try_from(raw_opcode)?;

        let authoritative_answer = *hdr.get(21).unwrap();
        let truncation = *hdr.get(22).unwrap();
        let recursion_desired = *hdr.get(23).unwrap();
        let recursion_available = *hdr.get(24).unwrap();

        let raw_rcode: u8 = hdr[28..=31].load();
        let response_code = ResponseCode::try_from(raw_rcode)?;

        let qd_count = hdr[32..=47].load_be();
        let an_count = hdr[48..=63].load_be();
        let ns_count = hdr[64..=79].load_be();
        let ar_count = hdr[80..=95].load_be();

        *i += 12;

        Ok(Header {
            id,
            qr,
            opcode,
            authoritative_answer,
            truncation,
            recursion_desired,
            recursion_available,
            response_code,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        })
    }
}

///////////////
/// Question
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug)]
pub enum Type {
    A = 1,
    NS = 2,
    // MD,
    // MF,
    CNAME = 5,
    SOA = 6,
    // MB,
    // MG,
    // MR,
    // NULL,
    // WKS,
    PTR = 12,
    // HINFO,
    // MINFO,
    MX = 15,
    TXT = 16,
}

impl TryFrom<u16> for Type {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Type::A),
            2 => Ok(Type::NS),
            5 => Ok(Type::CNAME),
            6 => Ok(Type::SOA),
            12 => Ok(Type::PTR),
            15 => Ok(Type::MX),
            16 => Ok(Type::TXT),
            _ => Err(format!("unknown type {value}")),
        }
    }
}

// needed for Clap
impl FromStr for Type {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "a" | "A" => Ok(Type::A),
            "ns" | "NS" => Ok(Type::NS),
            "cname" | "CNAME" => Ok(Type::CNAME),
            "soa" | "SOA" => Ok(Type::SOA),
            "ptr" | "PTR" => Ok(Type::PTR),
            "mx" | "MX" => Ok(Type::MX),
            "txt" | "TXT" => Ok(Type::TXT),
            _ => Err(format!("unsupported query type {s}")),
        }
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Type::A => "A",
            Type::NS => "NS",
            Type::CNAME => "CNAME",
            Type::SOA => "SOA",
            Type::PTR => "PTR",
            Type::MX => "MX",
            Type::TXT => "TXT",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Class {
    IN = 1,
    // CS,
    // CH,
    // HS
}

impl TryFrom<u16> for Class {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Class::IN),
            _ => Err(format!("unknown class {value}")),
        }
    }
}

impl Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Class::IN => "IN",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug)]
pub struct Question {
    pub qname: String,
    pub qtype: Type,
    pub qclass: Class,
}

impl Question {
    fn serialize(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut result: Vec<u8> = Vec::new();

        result.append(&mut serialize_name(&self.qname)?);

        result.push(0); // msb
        result.push(self.qtype as u8); // lsb

        result.push(0); // msb
        result.push(self.qclass as u8); // lsb

        Ok(result)
    }

    fn deserialize(buf: &[u8], i: &mut usize) -> Result<Question, Box<dyn Error>> {
        // read name
        let qname = deserialize_name(buf, i)?;

        check_space(buf, *i, 2)?;
        let raw_q_type = (buf[*i] as u16) << 8 | buf[*i + 1] as u16;
        let qtype = Type::try_from(raw_q_type)?;
        *i += 2;

        check_space(buf, *i, 2)?;
        let raw_q_class = (buf[*i] as u16) << 8 | buf[*i + 1] as u16;
        let qclass = Class::try_from(raw_q_class)?;
        *i += 2;

        Ok(Question {
            qname,
            qtype,
            qclass,
        })
    }
}

///////////////
/// Resource Record

#[derive(Debug)]
pub enum RrData {
    Ipv4Addr(Ipv4Addr),
    Name(String),
    PrefString((u16, String)),
    TxtStrings(Vec<String>),
    Soa(Soa),
}

impl RrData {
    fn serialize(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        match self {
            RrData::Ipv4Addr(addr) => {
                let bytes = addr.octets();
                Ok(Vec::from(bytes))
            }
            RrData::Name(s) => {
                let bytes = serialize_name(s)?;
                Ok(bytes)
            }
            RrData::PrefString(pref_string) => {
                let mut bytes = vec![(pref_string.0 >> 8) as u8, (pref_string.0 & 0xFF) as u8];
                bytes.append(&mut serialize_name(&pref_string.1)?);

                Ok(bytes)
            }
            RrData::TxtStrings(ref txt_strings) => {
                let mut bytes = vec![];
                for s in txt_strings {
                    bytes.push((s.len() >> 8) as u8);
                    bytes.push((s.len() & 0xFF) as u8);
                    for b in s.as_bytes() {
                        if !b.is_ascii() {
                            return Err("non-ascii character in txtstring".into());
                        }
                        bytes.push(*b);
                    }
                }
                Ok(bytes)
            }
            RrData::Soa(soa) => {
                let bytes = soa.serialize()?;
                Ok(bytes)
            }
        }
    }

    fn deserialize(rtype: Type, buf: &[u8], i: &mut usize) -> Result<RrData, Box<dyn Error>> {
        check_space(buf, *i, 2)?;
        let rd_length = (buf[*i] as u16) << 8 | buf[*i + 1] as u16;
        *i += 2;

        check_space(buf, *i, rd_length as usize)?;

        match rtype {
            Type::A => {
                if rd_length != 4 {
                    return Err("rdata for IpV4 address is incorrect length".into());
                }
                let arr: [u8; 4] = buf[*i..*i + rd_length as usize].try_into().unwrap();
                let addr = Ipv4Addr::try_from(arr)?;
                *i += 4;
                Ok(RrData::Ipv4Addr(addr))
            }
            Type::NS => {
                let ns = deserialize_name(buf, i)?;
                Ok(RrData::Name(ns))
            }
            Type::CNAME => {
                let cname = deserialize_name(buf, i)?;
                Ok(RrData::Name(cname))
            }
            Type::SOA => {
                let soa = Soa::deserialize(buf, i)?;
                Ok(RrData::Soa(soa))
            }
            Type::PTR => {
                let ptr = deserialize_name(buf, i)?;
                Ok(RrData::Name(ptr))
            }
            Type::MX => {
                check_space(buf, *i, 2)?;
                let pref: u16 = (buf[0] as u16) << 8 | buf[1] as u16;
                *i += 2;
                let exch = deserialize_name(buf, i)?;
                Ok(RrData::PrefString((pref, exch)))
            }
            Type::TXT => {
                let mut strings = vec![];
                let mut remaining = rd_length;
                while remaining != 0 {
                    check_space(buf, *i, 1)?;
                    let len = buf[*i] as usize;
                    *i += 1;
                    remaining -= 1;

                    check_space(buf, *i, len)?;
                    let s = std::str::from_utf8(&buf[*i..*i + len]);
                    if let Ok(s) = s {
                        strings.push(String::from(s));
                    }
                    *i += len;
                    if remaining < len as u16 {
                        // underflow
                        return Err("corrupt TXT rdata character-string".into());
                    }
                    remaining -= len as u16;
                }

                Ok(RrData::TxtStrings(strings))
            }
        }
    }
}

impl Display for RrData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RrData::Ipv4Addr(addr) => {
                write!(f, "{}", addr)
            }
            RrData::Name(s) => {
                write!(f, "{}", s)
            }
            RrData::PrefString(pref_string) => {
                write!(f, "{} {}", pref_string.0, pref_string.1)
            }
            RrData::TxtStrings(strings) => {
                let strings: Vec<String> = strings.iter().map(|s| format!("\"{}\"", s)).collect();
                write!(f, "{}", strings.join(" "))
            }
            RrData::Soa(soa) => {
                write!(
                    f,
                    "{} {} {} {} {} {} {}",
                    soa.mname,
                    soa.rname,
                    soa.serial,
                    soa.refresh,
                    soa.retry,
                    soa.expire,
                    soa.minimum
                )
            }
        }
    }
}

#[derive(Debug)]
pub struct Soa {
    mname: String,
    rname: String,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

impl Soa {
    fn serialize(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut result = Vec::new();

        result.append(&mut serialize_name(&self.mname)?);
        result.append(&mut serialize_name(&self.rname)?);

        macro_rules! write_be_u32 {
            ($vec:ident, $var:expr) => {
                $vec.push((($var & 0xFF000000) >> 24) as u8);
                $vec.push((($var & 0x00FF0000) >> 16) as u8);
                $vec.push((($var & 0x0000FF00) >> 8) as u8);
                $vec.push(($var & 0x000000FF) as u8);
            };
        }

        write_be_u32!(result, self.serial);
        write_be_u32!(result, self.refresh);
        write_be_u32!(result, self.retry);
        write_be_u32!(result, self.expire);
        write_be_u32!(result, self.minimum);

        Ok(result)
    }

    fn deserialize(buf: &[u8], i: &mut usize) -> Result<Soa, Box<dyn Error>> {
        let mname = deserialize_name(buf, i)?;
        let rname = deserialize_name(buf, i)?;

        macro_rules! read_be_u32 {
            ($buf:expr, $off:expr) => {
                ($buf[$off] as u32) << 24
                | ($buf[$off + 1] as u32) << 16
                | ($buf[$off + 2] as u32) << 8
                | ($buf[$off + 3] as u32)
            };
        }

        check_space(buf, *i, 4)?;
        let serial = read_be_u32!(buf, *i);
        *i += 4;

        check_space(buf, *i, 4)?;
        let refresh = read_be_u32!(buf, *i);
        *i += 4;

        check_space(buf, *i, 4)?;
        let retry = read_be_u32!(buf, *i);
        *i += 4;

        check_space(buf, *i, 4)?;
        let expire = read_be_u32!(buf, *i);
        *i += 4;

        check_space(buf, *i, 4)?;
        let minimum = read_be_u32!(buf, *i);
        *i += 4;

        Ok(Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }
}

#[derive(Debug)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: Type,
    pub rclass: Class,
    pub ttl: u32,
    pub rdata: RrData,
}

impl ResourceRecord {
    fn serialize(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut result = Vec::new();

        result.append(&mut serialize_name(&self.name)?);

        result.push(0); // msb
        result.push(self.rtype as u8); // lsb
        result.push(0); // msb
        result.push(self.rclass as u8); // lsb

        result.push(((self.ttl & 0xFF000000) >> 24) as u8);
        result.push(((self.ttl & 0x00FF0000) >> 16) as u8);
        result.push(((self.ttl & 0x0000FF00) >> 8) as u8);
        result.push((self.ttl & 0x000000FF) as u8);

        let mut rdata = self.rdata.serialize()?;
        let rd_length = u16::try_from(rdata.len())?;
        result.push((rd_length >> 8) as u8);
        result.push((rd_length & 0xFF) as u8);

        result.append(&mut rdata);

        Ok(result)
    }

    fn deserialize(buf: &[u8], i: &mut usize) -> Result<ResourceRecord, Box<dyn Error>> {
        let name = deserialize_name(buf, i)?;

        check_space(buf, *i, 2)?;
        let raw_r_type = (buf[*i] as u16) << 8 | buf[*i + 1] as u16;
        let rtype = Type::try_from(raw_r_type)?;
        *i += 2;

        check_space(buf, *i, 2)?;
        let raw_r_class = (buf[*i] as u16) << 8 | buf[*i + 1] as u16;
        let rclass = Class::try_from(raw_r_class)?;
        *i += 2;

        check_space(buf, *i, 4)?;
        let ttl = (buf[*i] as u32) << 24
            | (buf[*i + 1] as u32) << 16
            | (buf[*i + 2] as u32) << 8
            | buf[*i + 3] as u32;
        *i += 4;

        let rdata = RrData::deserialize(rtype, buf, i)?;

        Ok(ResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        })
    }
}

fn serialize_name(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut result = Vec::new();

    let labels = s.split('.').collect::<Vec<_>>();
    for label in labels {
        let chars: Vec<char> = label.chars().collect();

        if chars.len() > 63 {
            return Err("invalid label length".into());
        }

        result.push(chars.len() as u8);
        for ch in chars {
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                return Err("illegal character in label".into());
            }

            result.push(ch as u8);
        }
    }
    result.push(0); // labels terminator

    Ok(result)
}

fn deserialize_name(buf: &[u8], i: &mut usize) -> Result<String, Box<dyn Error>> {
    let mut name = String::new();

    while buf[*i] != 0 {
        if buf[*i] & 0b11000000 == 0b11000000 {
            // this is a 14-bit pointer to elsewhere in the message
            check_space(buf, *i, 2)?;
            let mut offset = ((buf[*i] & 0b00111111) as usize) << 8 | buf[*i + 1] as usize;
            *i += 2;

            if offset >= buf.len() {
                return Err("invalid offset for name ptr".into());
            }

            let pointed_name = deserialize_name(buf, &mut offset)?;
            name.push_str(&pointed_name);
            return Ok(name);
        }

        check_space(buf, *i, 1)?;
        let label_len = buf[*i] as usize;
        *i += 1;

        if label_len > 63 {
            // catch the 10 and 01 cases for the two leading bits
            return Err("invalid label length".into());
        }

        check_space(buf, *i, label_len)?;
        for j in 0..label_len {
            let c = buf[*i + j];
            if !c.is_ascii_alphanumeric() && c != b'-' {
                return Err("invalid character in name - corrupt packet?".into());
            }
            name.push(c as char);
        }
        *i += label_len;

        if buf[*i] != 0 {
            name.push('.');
        }
    }
    check_space(buf, *i, 1)?;
    *i += 1; // skip terminator

    Ok(name)
}

fn check_space(buf: &[u8], i: usize, amount: usize) -> Result<(), Box<dyn Error>> {
    if i + amount > buf.len() {
        return Err("corrupt or truncated packet - invalid offset".into());
    }
    Ok(())
}
