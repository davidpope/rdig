use bitvec::prelude::*;
use std::{fmt::Display, io::Write, net::Ipv4Addr, str::FromStr};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("validation error")]
    ValidationError(String),

    #[error("serialization failed")]
    SerializationFailed(String),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error("deserialization failed")]
    DeserializationFailed(String),
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
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

    pub fn serialize(&self, buf: &mut Vec<u8>) -> Result<(), MessageError> {
        self.header.serialize(buf)?;

        assert_eq!(self.questions.len(), self.header.qd_count as usize);
        assert_eq!(self.answers.len(), self.header.an_count as usize);
        assert_eq!(self.authorities.len(), self.header.ns_count as usize);
        assert_eq!(self.additionals.len(), self.header.ar_count as usize);

        for q in self.questions.iter() {
            q.serialize(buf)?;
        }

        for a in self.answers.iter() {
            a.serialize(buf)?;
        }

        for a in self.authorities.iter() {
            a.serialize(buf)?;
        }

        for a in self.additionals.iter() {
            a.serialize(buf)?;
        }

        Ok(())
    }

    pub fn deserialize(buf: &[u8]) -> Result<Message, MessageError> {
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
#[cfg_attr(test, derive(PartialEq))]
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

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq))]
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
        write!(f, "{s}")
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
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

    fn serialize(&self, buf: &mut Vec<u8>) -> Result<(), MessageError> {
        let mut pkt: BitArray<[u8; 12], Msb0> = BitArray::ZERO;

        pkt[..=15].store_be(self.id);

        *pkt.get_mut(16).unwrap() = self.qr == QueryOrResponse::Response;

        pkt[17..=20].store(self.opcode as u8);

        *pkt.get_mut(21).unwrap() = self.authoritative_answer;
        *pkt.get_mut(22).unwrap() = self.truncation;
        *pkt.get_mut(23).unwrap() = self.recursion_desired;
        *pkt.get_mut(24).unwrap() = self.recursion_available;

        pkt[28..=31].store(self.response_code as u8);

        pkt[32..=47].store_be(self.qd_count);
        pkt[48..=63].store_be(self.an_count);
        pkt[64..=79].store_be(self.ns_count);
        pkt[80..=95].store_be(self.ar_count);

        buf.write_all(pkt.as_raw_slice())?;

        Ok(())
    }

    fn deserialize(buf: &[u8], i: &mut usize) -> Result<Header, MessageError> {
        let hdr: &BitSlice<u8, Msb0> = BitSlice::from_slice(buf);

        check_space(buf, *i, 12)?; // this covers the entire header

        let id = hdr[0..=15].load_be();

        let raw_qr = *hdr.get(16).unwrap();
        let qr = QueryOrResponse::from(raw_qr);

        let raw_opcode: u8 = hdr[17..=20].load();
        let opcode = OpCode::try_from(raw_opcode).map_err(|e| {
            MessageError::DeserializationFailed(format!("received invalid opcode: {e}"))
        })?;

        let authoritative_answer = *hdr.get(21).unwrap();
        let truncation = *hdr.get(22).unwrap();
        let recursion_desired = *hdr.get(23).unwrap();
        let recursion_available = *hdr.get(24).unwrap();

        let raw_rcode: u8 = hdr[28..=31].load();
        let response_code = ResponseCode::try_from(raw_rcode).map_err(|e| {
            MessageError::DeserializationFailed(format!("received invalid response code: {e}"))
        })?;

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
#[cfg_attr(test, derive(PartialEq))]
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
        write!(f, "{s}")
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq))]
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
        write!(f, "{s}")
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Question {
    pub qname: String,
    pub qtype: Type,
    pub qclass: Class,
}

impl Question {
    fn serialize(&self, buf: &mut Vec<u8>) -> Result<(), MessageError> {
        serialize_name(&self.qname, buf)?;

        buf.write_all(&[0_u8, self.qtype as u8])?;
        buf.write_all(&[0_u8, self.qclass as u8])?;

        Ok(())
    }

    fn deserialize(buf: &[u8], i: &mut usize) -> Result<Question, MessageError> {
        // read name
        let qname = deserialize_name(buf, i)?;

        check_space(buf, *i, 2)?;
        let raw_q_type = (buf[*i] as u16) << 8 | buf[*i + 1] as u16;
        let qtype = Type::try_from(raw_q_type)
            .map_err(|e| MessageError::DeserializationFailed(format!("invalid query type: {e}")))?;
        *i += 2;

        check_space(buf, *i, 2)?;
        let raw_q_class = (buf[*i] as u16) << 8 | buf[*i + 1] as u16;
        let qclass = Class::try_from(raw_q_class).map_err(|e| {
            MessageError::DeserializationFailed(format!("invalid query class: {e}"))
        })?;
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
#[cfg_attr(test, derive(PartialEq))]
pub enum RrData {
    Ipv4Addr(Ipv4Addr),
    Name(String),
    PrefString((u16, String)),
    TxtStrings(Vec<String>),
    Soa(Soa),
}

impl RrData {
    // The reason this returns a Vec of data instead of writing directly to a buffer (like
    // the rest of the serialize methods) is that the DNS protocol requires us to write
    // the size of the rdata before writing the rdata itself.
    fn serialize(&self) -> Result<Vec<u8>, MessageError> {
        match self {
            RrData::Ipv4Addr(addr) => {
                let bytes = addr.octets();
                Ok(Vec::from(bytes))
            }
            RrData::Name(s) => {
                let mut bytes = Vec::new();
                serialize_name(s, &mut bytes)?;
                Ok(bytes)
            }
            RrData::PrefString(pref_string) => {
                let mut bytes = Vec::new();
                bytes.write_all(&[(pref_string.0 >> 8) as u8, pref_string.0 as u8])?;
                serialize_name(&pref_string.1, &mut bytes)?;
                Ok(bytes)
            }
            RrData::TxtStrings(txt_strings) => {
                let mut bytes = vec![];
                for s in txt_strings {
                    if s.len() > 255 {
                        return Err(MessageError::ValidationError(format!(
                            "TXT string too long: {}",
                            s.len()
                        )));
                    }
                    bytes.push(s.len() as u8);
                    for b in s.as_bytes() {
                        if !b.is_ascii() {
                            return Err(MessageError::ValidationError(format!(
                                "non-ascii character '{b}' in txtstring"
                            )));
                        }
                        bytes.push(*b);
                    }
                }
                Ok(bytes)
            }
            RrData::Soa(soa) => {
                let mut bytes = Vec::new();
                soa.serialize(&mut bytes)?;
                Ok(bytes)
            }
        }
    }

    fn deserialize(rtype: Type, buf: &[u8], i: &mut usize) -> Result<RrData, MessageError> {
        check_space(buf, *i, 2)?;
        let rd_length = (buf[*i] as u16) << 8 | buf[*i + 1] as u16;
        *i += 2;

        check_space(buf, *i, rd_length as usize)?;

        match rtype {
            Type::A => {
                if rd_length != 4 {
                    return Err(MessageError::DeserializationFailed(
                        "rdata for IpV4 address is incorrect length".to_owned(),
                    ));
                }
                let arr: [u8; 4] = buf[*i..*i + rd_length as usize].try_into().unwrap();
                let addr = Ipv4Addr::from(arr);
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
                let pref: u16 = (buf[*i] as u16) << 8 | buf[*i + 1] as u16;
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
                        return Err(MessageError::DeserializationFailed(
                            "corrupt TXT rdata character-string".to_owned(),
                        ));
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
                write!(f, "{addr}")
            }
            RrData::Name(s) => {
                write!(f, "{s}")
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
#[cfg_attr(test, derive(PartialEq))]
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
    fn serialize(&self, buf: &mut Vec<u8>) -> Result<(), MessageError> {
        serialize_name(&self.mname, buf)?;
        serialize_name(&self.rname, buf)?;

        macro_rules! write_be_u32 {
            ($buf:ident, $var:expr) => {
                $buf.write_all(&[
                    ($var >> 24) as u8,
                    ($var >> 16) as u8,
                    ($var >> 8) as u8,
                    $var as u8,
                ])?;
            };
        }

        write_be_u32!(buf, self.serial);
        write_be_u32!(buf, self.refresh);
        write_be_u32!(buf, self.retry);
        write_be_u32!(buf, self.expire);
        write_be_u32!(buf, self.minimum);

        Ok(())
    }

    fn deserialize(buf: &[u8], i: &mut usize) -> Result<Soa, MessageError> {
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
#[cfg_attr(test, derive(PartialEq))]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: Type,
    pub rclass: Class,
    pub ttl: u32,
    pub rdata: RrData,
}

impl ResourceRecord {
    fn serialize(&self, buf: &mut Vec<u8>) -> Result<(), MessageError> {
        serialize_name(&self.name, buf)?;

        buf.write_all(&[0_u8, self.rtype as u8])?;
        buf.write_all(&[0_u8, self.rclass as u8])?;

        buf.write_all(&[
            (self.ttl >> 24) as u8,
            (self.ttl >> 16) as u8,
            (self.ttl >> 8) as u8,
            (self.ttl) as u8,
        ])?;

        // N.B. here we must retrieve the data to be written so that we can write its length
        // before writing the data itself.
        let rdata = self.rdata.serialize()?;
        let rd_length = u16::try_from(rdata.len()).map_err(|e| {
            MessageError::SerializationFailed(format!("resource data too long: {e}"))
        })?;

        buf.write_all(&[(rd_length >> 8) as u8, rd_length as u8])?;
        buf.write_all(&rdata)?;

        Ok(())
    }

    fn deserialize(buf: &[u8], i: &mut usize) -> Result<ResourceRecord, MessageError> {
        let name = deserialize_name(buf, i)?;

        check_space(buf, *i, 2)?;
        let raw_r_type = (buf[*i] as u16) << 8 | buf[*i + 1] as u16;
        let rtype = Type::try_from(raw_r_type).map_err(|e| {
            MessageError::DeserializationFailed(format!("invalid response type: {e}"))
        })?;
        *i += 2;

        check_space(buf, *i, 2)?;
        let raw_r_class = (buf[*i] as u16) << 8 | buf[*i + 1] as u16;
        let rclass = Class::try_from(raw_r_class).map_err(|e| {
            MessageError::DeserializationFailed(format!("invalid response class: {e}"))
        })?;
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

fn serialize_name(s: &str, buf: &mut Vec<u8>) -> Result<(), MessageError> {
    let labels = s.split('.').collect::<Vec<_>>();
    for label in labels {
        let chars: Vec<char> = label.chars().collect();

        if chars.is_empty() {
            return Err(MessageError::ValidationError(
                "zero-length label".to_owned(),
            ));
        }

        if chars.len() > 63 {
            return Err(MessageError::ValidationError(format!(
                "label length greater than 63: {label}"
            )));
        }

        buf.write_all(&[chars.len() as u8])?;
        for ch in chars {
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                return Err(MessageError::ValidationError(format!(
                    "illegal character in label: {ch}"
                )));
            }

            buf.write_all(&[ch as u8])?;
        }
    }
    buf.write_all(&[0])?; // labels terminator

    Ok(())
}

fn deserialize_name(buf: &[u8], i: &mut usize) -> Result<String, MessageError> {
    deserialize_name_internal(buf, i, true)
}

fn deserialize_name_internal(
    buf: &[u8],
    i: &mut usize,
    allow_compressed: bool,
) -> Result<String, MessageError> {
    let mut name = String::new();

    while *i < buf.len() && buf[*i] != 0 {
        if buf[*i] & 0b11000000 == 0b11000000 {
            if !allow_compressed {
                return Err(MessageError::DeserializationFailed(
                    "detected multiply-compressed name".to_owned(),
                ));
            }

            // this is a 14-bit pointer to elsewhere in the message
            check_space(buf, *i, 2)?;
            let mut offset = ((buf[*i] & 0b00111111) as usize) << 8 | buf[*i + 1] as usize;
            *i += 2;

            if offset >= buf.len() {
                return Err(MessageError::DeserializationFailed(
                    "invalid offset for name ptr".to_owned(),
                ));
            }

            let pointed_name = deserialize_name_internal(buf, &mut offset, false)?;
            name.push_str(&pointed_name);
            return Ok(name);
        }

        check_space(buf, *i, 1)?;
        let label_len = buf[*i] as usize;
        *i += 1;

        if label_len > 63 {
            // catch the 10 and 01 cases for the two leading bits
            return Err(MessageError::DeserializationFailed(format!(
                "invalid label length: {label_len}"
            )));
        }

        check_space(buf, *i, label_len)?;
        for j in 0..label_len {
            let c = buf[*i + j];
            if !c.is_ascii_alphanumeric() && c != b'-' {
                return Err(MessageError::DeserializationFailed(format!(
                    "invalid character in name: {c}"
                )));
            }
            name.push(c as char);
        }
        *i += label_len;

        if *i < buf.len() && buf[*i] != 0 {
            name.push('.');
        }
    }

    if *i < buf.len() {
        check_space(buf, *i, 1)?;
        *i += 1; // skip terminator
    }

    Ok(name)
}

fn check_space(buf: &[u8], i: usize, amount: usize) -> Result<(), MessageError> {
    if i + amount > buf.len() {
        return Err(MessageError::DeserializationFailed(
            "corrupt or truncated packet - invalid offset".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_deserialize_round_trip() {
        let mut m1 = Message::new_query("ietf.org", Type::A, Class::IN);
        m1.answers.push(ResourceRecord {
            name: "example.com".to_owned(),
            rtype: Type::A,
            rclass: Class::IN,
            ttl: 86400,
            rdata: RrData::Ipv4Addr([1, 2, 3, 4].into()),
        });
        m1.header.an_count += 1;
        m1.answers.push(ResourceRecord {
            name: "example.com".to_owned(),
            rtype: Type::CNAME,
            rclass: Class::IN,
            ttl: 86400,
            rdata: RrData::Name("some-cname.example.com".to_owned()),
        });
        m1.header.an_count += 1;
        m1.answers.push(ResourceRecord {
            name: "example.com".to_owned(),
            rtype: Type::MX,
            rclass: Class::IN,
            ttl: 86400,
            rdata: RrData::PrefString((100, "some-mx.example.com".to_owned())),
        });
        m1.header.an_count += 1;
        m1.answers.push(ResourceRecord {
            name: "example.com".to_owned(),
            rtype: Type::TXT,
            rclass: Class::IN,
            ttl: 86400,
            rdata: RrData::TxtStrings(vec!["some text data".into(), "some more text data".into()]),
        });
        m1.header.an_count += 1;
        m1.answers.push(ResourceRecord {
            name: "example.com".to_owned(),
            rtype: Type::SOA,
            rclass: Class::IN,
            ttl: 86400,
            rdata: RrData::Soa(Soa {
                mname: "example.com".to_owned(),
                rname: "mbox.example.com".to_owned(),
                serial: 1,
                refresh: 86400,
                retry: 86400,
                expire: 86400,
                minimum: 86400,
            }),
        });
        m1.header.an_count += 1;

        let mut buf = Vec::new();
        m1.serialize(&mut buf).unwrap();
        let m2 = Message::deserialize(&buf).unwrap();

        assert_eq!(m1, m2);
    }

    #[test]
    fn long_rdata_fails_serialization() {
        let mut m = Message::new_query("example.com", Type::A, Class::IN);
        let mut strings = vec![];
        // build strings over 64k total length
        for _ in 0..(1 << 16) / 255 {
            strings.push(String::from_utf8([b'a'; 255].to_vec()).unwrap());
        }
        m.answers.push(ResourceRecord {
            name: "example.com".to_owned(),
            rtype: Type::TXT,
            rclass: Class::IN,
            ttl: 86400,
            rdata: RrData::TxtStrings(strings),
        });
        m.header.an_count += 1;

        let mut buf = vec![];
        let r = m.serialize(&mut buf);

        assert!(matches!(r, Err(MessageError::SerializationFailed(_))));
    }

    #[test]
    fn long_name_label_fails_serialization() {
        // labels can only be 63 bytes long
        let long_label_name =
            "1234567890123456789012345678901234567890123456789012345678901234.example.com";
        let m = Message::new_query(long_label_name, Type::A, Class::IN);

        let mut buf = vec![];
        let r = m.serialize(&mut buf);

        assert!(matches!(r, Err(MessageError::ValidationError(_))));
    }

    #[test]
    fn non_ascii_name_fails_serialization() {
        let name = "🙂.example.com";
        let m = Message::new_query(name, Type::A, Class::IN);

        let mut buf = vec![];
        let r = m.serialize(&mut buf);

        assert!(matches!(r, Err(MessageError::ValidationError(_))));
    }

    #[test]
    fn zero_length_label_fails_serialization() {
        let name = "...";
        let m = Message::new_query(name, Type::A, Class::IN);

        let mut buf = vec![];
        let r = m.serialize(&mut buf);

        assert!(matches!(r, Err(MessageError::ValidationError(_))));
    }

    #[test]
    fn deserialize_fuzzed_data_1() {
        // index out of range
        let buf = [3, 0, 0, 0, 0, 9, 110, 110, 130, 130, 130, 10];
        let _ = Message::deserialize(&buf);
    }

    #[test]
    fn deserialize_fuzzed_data_2() {
        // index out of range
        let buf = [1, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 253, 1, 104, 1, 104];
        let _ = Message::deserialize(&buf);
    }

    #[test]
    fn deserialize_fuzzed_data_3() {
        // stack overflow
        let buf = [
            0, 3, 0, 0, 3, 3, 0, 0, 192, 192, 192, 192, 192, 192, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 192, 192, 192, 192,
            192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192,
            192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192,
            192, 192, 3, 3, 0, 10, 110, 48, 110, 110, 110, 110, 110, 110, 110, 110,
        ];
        let _ = Message::deserialize(&buf);
    }
}
