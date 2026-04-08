// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use crate::error::{DnsError, ErrorKind};

/// DNS message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMessageType {
    Query,
    Response,
}

impl DnsMessageType {
    pub fn parse_flags(flags: u16) -> Self {
        match (flags >> 15) & 0x1 {
            0 => DnsMessageType::Query,
            1 => DnsMessageType::Response,
            _ => unreachable!(),
        }
    }

    pub fn to_opcode(&self) -> u16 {
        match self {
            DnsMessageType::Query => 0,
            DnsMessageType::Response => 0,
        }
    }
}

/// DNS query types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsQueryType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    SOA,
    TXT,
    PTR,
    SRV,
    OTHER(u16),
}

impl From<DnsQueryType> for u16 {
    fn from(qtype: DnsQueryType) -> Self {
        match qtype {
            DnsQueryType::A => 1,
            DnsQueryType::AAAA => 28,
            DnsQueryType::CNAME => 5,
            DnsQueryType::MX => 15,
            DnsQueryType::NS => 2,
            DnsQueryType::SOA => 6,
            DnsQueryType::TXT => 16,
            DnsQueryType::PTR => 12,
            DnsQueryType::SRV => 33,
            DnsQueryType::OTHER(t) => t,
        }
    }
}

impl TryFrom<u16> for DnsQueryType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DnsQueryType::A),
            28 => Ok(DnsQueryType::AAAA),
            5 => Ok(DnsQueryType::CNAME),
            15 => Ok(DnsQueryType::MX),
            2 => Ok(DnsQueryType::NS),
            6 => Ok(DnsQueryType::SOA),
            16 => Ok(DnsQueryType::TXT),
            12 => Ok(DnsQueryType::PTR),
            33 => Ok(DnsQueryType::SRV),
            _ => Ok(DnsQueryType::OTHER(value)),
        }
    }
}

/// DNS record classes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordClass {
    IN,
    CS,
    CH,
    HS,
    OTHER(u16),
}

impl From<DnsRecordClass> for u16 {
    fn from(rclass: DnsRecordClass) -> Self {
        match rclass {
            DnsRecordClass::IN => 1,
            DnsRecordClass::CS => 2,
            DnsRecordClass::CH => 3,
            DnsRecordClass::HS => 4,
            DnsRecordClass::OTHER(c) => c,
        }
    }
}

impl TryFrom<u16> for DnsRecordClass {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DnsRecordClass::IN),
            2 => Ok(DnsRecordClass::CS),
            3 => Ok(DnsRecordClass::CH),
            4 => Ok(DnsRecordClass::HS),
            _ => Ok(DnsRecordClass::OTHER(value)),
        }
    }
}

/// DNS response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResponseCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    OTHER(u16),
}

impl From<DnsResponseCode> for u16 {
    fn from(rcode: DnsResponseCode) -> Self {
        match rcode {
            DnsResponseCode::NoError => 0,
            DnsResponseCode::FormErr => 1,
            DnsResponseCode::ServFail => 2,
            DnsResponseCode::NXDomain => 3,
            DnsResponseCode::NotImp => 4,
            DnsResponseCode::Refused => 5,
            DnsResponseCode::OTHER(c) => c,
        }
    }
}

impl TryFrom<u16> for DnsResponseCode {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DnsResponseCode::NoError),
            1 => Ok(DnsResponseCode::FormErr),
            2 => Ok(DnsResponseCode::ServFail),
            3 => Ok(DnsResponseCode::NXDomain),
            4 => Ok(DnsResponseCode::NotImp),
            5 => Ok(DnsResponseCode::Refused),
            _ => Ok(DnsResponseCode::OTHER(value)),
        }
    }
}

/// A fully domain name
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsDomainName {
    pub labels: Vec<Vec<u8>>,
    pub raw_offset: usize,
    /// If the domain was originally encoded as a compression pointer,
    /// this stores the pointer target for faithful re-emission
    pub compression_pointer: Option<usize>,
}

impl fmt::Display for DnsDomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.labels
                .iter()
                .map(|label| String::from_utf8_lossy(label))
                .collect::<Vec<_>>()
                .join(".")
        )
    }
}

impl DnsDomainName {
    /// Parse a domain name from the buffer, handling compression pointers
    pub fn parse_from(
        buf: &[u8],
        offset: &mut usize,
    ) -> Result<Self, DnsError> {
        let start_offset = *offset;
        let mut labels = Vec::new();
        let mut return_offset: Option<usize> = None;
        let mut compression_pointer: Option<usize> = None;
        let mut total_length: usize = 0;
        let mut pointer_count: usize = 0;
        const MAX_POINTER_CHAIN: usize = 10; // Prevent excessive chaining

        while *offset < buf.len() {
            let len_byte = buf[*offset];

            // Check for end of domain name
            if len_byte == 0 {
                *offset += 1;
                break;
            }

            // Check for compression pointer (top 2 bits set to 11)
            if (len_byte & 0xC0) == 0xC0 {
                // Validate: only one compression pointer allowed at the end
                if *offset + 1 >= buf.len() {
                    return Err(DnsError::new(
                        ErrorKind::InvalidCompressionPointer,
                        "Pointer offset out of bounds",
                    ));
                }

                // Detect cycles
                pointer_count += 1;
                if pointer_count > MAX_POINTER_CHAIN {
                    return Err(DnsError::new(
                        ErrorKind::CompressionPointerCycle,
                        "Too many compression pointers (possible cycle)",
                    ));
                }

                let pointer_offset = (((len_byte & 0x3F) as u16) << 8)
                    | (buf[*offset + 1] as u16);
                if pointer_offset as usize >= buf.len() {
                    return Err(DnsError::new(
                        ErrorKind::InvalidCompressionPointer,
                        "Pointer offset beyond buffer",
                    ));
                }

                // Store the compression pointer target (only the first one)
                if compression_pointer.is_none() {
                    compression_pointer = Some(pointer_offset as usize);
                }

                // Save where we need to return to after following the pointer
                if return_offset.is_none() {
                    return_offset = Some(*offset + 2);
                }

                *offset = pointer_offset as usize;
                continue;
            }

            // Check for reserved pointer values (01xxxxxx or 10xxxxxx)
            if (len_byte & 0xC0) != 0 {
                return Err(DnsError::new(
                    ErrorKind::InvalidCompressionPointer,
                    "Reserved compression pointer prefix",
                ));
            }

            // Regular label: validate length (must be <= 63)
            // At this point, we know high-order 2 bits are 00, so max value is
            // 63 This check is a safety guard; with proper prefix
            // validation above, it should never trigger under
            // normal circumstances.
            let len = len_byte as usize;
            debug_assert!(
                len <= 63,
                "Label length {} exceeds 63, but high bits were 00",
                len
            );

            // Check total domain name length (must be <= 255)
            // +1 for the length byte itself
            total_length += 1 + len;
            if total_length > 255 {
                return Err(DnsError::new(
                    ErrorKind::DomainNameTooLong,
                    "Domain name exceeds 255 byte limit",
                ));
            }

            *offset += 1;
            if *offset + len > buf.len() {
                return Err(DnsError::new(
                    ErrorKind::BufferTooShort,
                    "Insufficient buffer for label",
                ));
            }
            labels.push(buf[*offset..*offset + len].to_vec());
            *offset += len;
        }

        // After parsing the name (possibly following compression pointers),
        // return to the position after the compression pointer
        if let Some(return_pos) = return_offset {
            *offset = return_pos;
        }

        Ok(DnsDomainName {
            labels,
            raw_offset: start_offset,
            compression_pointer,
        })
    }

    /// Serialize domain name to buffer, using compression pointer if available
    pub fn emit_to(&self, buf: &mut Vec<u8>) {
        // If we have a compression pointer, use it
        if let Some(offset) = self.compression_pointer {
            buf.push(0xC0 | ((offset >> 8) as u8));
            buf.push((offset & 0xFF) as u8);
            return;
        }

        // Otherwise, emit the full domain name
        for label in &self.labels {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label);
        }
        buf.push(0);
    }
}

/// DNS Header structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub message_type: DnsMessageType,
    pub qr: bool,
    pub opcode: u16,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u16,
    pub rcode: DnsResponseCode,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn from_bytes(buf: &[u8]) -> Result<Self, DnsError> {
        if buf.len() < 12 {
            return Err(DnsError::new(
                ErrorKind::BufferTooShort,
                "DNS header must be at least 12 bytes",
            ));
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        let nscount = u16::from_be_bytes([buf[8], buf[9]]);
        let arcount = u16::from_be_bytes([buf[10], buf[11]]);

        let qr = flags >> 15 == 1;
        let opcode = (flags >> 11) & 0xF;
        let aa = (flags >> 10) & 1 == 1;
        let tc = (flags >> 9) & 1 == 1;
        let rd = (flags >> 8) & 1 == 1;
        let ra = (flags >> 7) & 1 == 1;
        let z = (flags >> 4) & 0x7;
        let rcode = DnsResponseCode::try_from(flags & 0xF)
            .unwrap_or(DnsResponseCode::OTHER(flags & 0xF));

        // RFC 1035 §4.1.1: Z field must be zero in all queries and responses
        // Some upstream servers set non-zero Z bits, so we parse but log at
        // debug level
        if z != 0 {
            log::debug!("DNS header has non-zero Z field: {}", z);
        }

        Ok(DnsHeader {
            id,
            message_type: DnsMessageType::parse_flags(flags),
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);

        // ID
        buf.extend_from_slice(&self.id.to_be_bytes());

        // Flags
        let mut flags = 0u16;
        if self.qr {
            flags |= 1u16 << 15;
        }
        flags |= self.opcode << 11;
        if self.aa {
            flags |= 1u16 << 10;
        }
        if self.tc {
            flags |= 1u16 << 9;
        }
        if self.rd {
            flags |= 1u16 << 8;
        }
        if self.ra {
            flags |= 1u16 << 7;
        }
        flags |= self.z << 4;
        flags |= u16::from(self.rcode);

        buf.extend_from_slice(&flags.to_be_bytes());

        // Counts
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());

        buf
    }
}

/// DNS Question record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub domain: DnsDomainName,
    pub query_type: DnsQueryType,
    pub query_class: DnsRecordClass,
}

impl DnsQuestion {
    pub fn parse_from(
        buf: &[u8],
        offset: &mut usize,
    ) -> Result<Self, DnsError> {
        let domain = DnsDomainName::parse_from(buf, offset)?;

        if *offset + 4 > buf.len() {
            return Err(DnsError::new(
                ErrorKind::BufferTooShort,
                "Insufficient buffer for question fields",
            ));
        }

        let qtype = u16::from_be_bytes([buf[*offset], buf[*offset + 1]]);
        let qclass = u16::from_be_bytes([buf[*offset + 2], buf[*offset + 3]]);
        *offset += 4;

        Ok(DnsQuestion {
            domain,
            query_type: DnsQueryType::try_from(qtype)
                .unwrap_or(DnsQueryType::OTHER(qtype)),
            query_class: DnsRecordClass::try_from(qclass)
                .unwrap_or(DnsRecordClass::OTHER(qclass)),
        })
    }

    pub fn emit_to(&self, buf: &mut Vec<u8>) {
        self.domain.emit_to(buf);
        buf.extend_from_slice(&u16::from(self.query_type).to_be_bytes());
        buf.extend_from_slice(&u16::from(self.query_class).to_be_bytes());
    }
}

/// DNS Resource Record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    pub domain: DnsDomainName,
    pub record_type: DnsQueryType,
    pub record_class: DnsRecordClass,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
}

impl DnsResourceRecord {
    pub fn parse_from(
        buf: &[u8],
        offset: &mut usize,
    ) -> Result<Self, DnsError> {
        let domain = DnsDomainName::parse_from(buf, offset)?;

        if *offset + 10 > buf.len() {
            return Err(DnsError::new(
                ErrorKind::BufferTooShort,
                "Insufficient buffer for resource record header",
            ));
        }

        let record_type = u16::from_be_bytes([buf[*offset], buf[*offset + 1]]);
        let record_class =
            u16::from_be_bytes([buf[*offset + 2], buf[*offset + 3]]);
        let ttl = u32::from_be_bytes([
            buf[*offset + 4],
            buf[*offset + 5],
            buf[*offset + 6],
            buf[*offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[*offset + 8], buf[*offset + 9]]);
        *offset += 10;

        if *offset + rdlength as usize > buf.len() {
            return Err(DnsError::new(
                ErrorKind::BufferTooShort,
                "Insufficient buffer for RDATA",
            ));
        }

        let rdata = buf[*offset..*offset + rdlength as usize].to_vec();
        *offset += rdlength as usize;

        Ok(DnsResourceRecord {
            domain,
            record_type: DnsQueryType::try_from(record_type)
                .unwrap_or(DnsQueryType::OTHER(record_type)),
            record_class: DnsRecordClass::try_from(record_class)
                .unwrap_or(DnsRecordClass::OTHER(record_class)),
            ttl,
            rdlength,
            rdata,
        })
    }

    pub fn emit_to(&self, buf: &mut Vec<u8>) {
        self.domain.emit_to(buf);
        buf.extend_from_slice(&u16::from(self.record_type).to_be_bytes());
        buf.extend_from_slice(&u16::from(self.record_class).to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        let rdlength = self.rdata.len() as u16;
        buf.extend_from_slice(&rdlength.to_be_bytes());
        buf.extend_from_slice(&self.rdata);
    }
}

/// DNS message - the complete packet without UDP/TCP header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additionals: Vec<DnsResourceRecord>,
}

impl DnsMessage {
    /// Create a simple DNS query message for the given domain name.
    ///
    /// # Arguments
    /// * `id` - Transaction ID for matching queries with responses
    /// * `domain_name` - The domain name to query (e.g., "example.com")
    /// * `query_type` - The type of query (A, AAAA, MX, etc.)
    ///
    /// # Returns
    /// A `DnsMessage` configured as a query, or an error if the domain name is
    /// invalid
    pub fn new_query(
        id: u16,
        domain_name: &str,
        query_type: DnsQueryType,
    ) -> Result<Self, DnsError> {
        let domain = Self::parse_domain_name(domain_name)?;

        let header = DnsHeader {
            id,
            message_type: DnsMessageType::Query,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true, // Recursion desired by default
            ra: false,
            z: 0,
            rcode: DnsResponseCode::NoError,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        let question = DnsQuestion {
            domain,
            query_type,
            query_class: DnsRecordClass::IN, // Internet class by default
        };

        Ok(DnsMessage {
            header,
            questions: vec![question],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        })
    }

    /// Parse a dot-separated domain name string into a DnsDomainName
    fn parse_domain_name(name: &str) -> Result<DnsDomainName, DnsError> {
        if name.is_empty() {
            return Err(DnsError::new(
                ErrorKind::InvalidDomainName,
                "Domain name cannot be empty",
            ));
        }

        let mut labels = Vec::new();
        for label in name.split('.') {
            // Skip empty labels (e.g., from trailing dot)
            if label.is_empty() {
                continue;
            }
            if label.len() > 63 {
                return Err(DnsError::new(
                    ErrorKind::LabelTooLong,
                    format!("Label '{}' exceeds 63 characters", label),
                ));
            }
            labels.push(label.as_bytes().to_vec());
        }

        if labels.is_empty() {
            return Err(DnsError::new(
                ErrorKind::InvalidDomainName,
                "Domain name must contain at least one label",
            ));
        }

        Ok(DnsDomainName {
            labels,
            raw_offset: 0,
            compression_pointer: None,
        })
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, DnsError> {
        let header = DnsHeader::from_bytes(buf)?;
        let mut offset = 12;

        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            let question = DnsQuestion::parse_from(buf, &mut offset)?;
            questions.push(question);
        }

        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            let record = DnsResourceRecord::parse_from(buf, &mut offset)?;
            answers.push(record);
        }

        let mut authorities = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            let record = DnsResourceRecord::parse_from(buf, &mut offset)?;
            authorities.push(record);
        }

        let mut additionals = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            let record = DnsResourceRecord::parse_from(buf, &mut offset)?;
            additionals.push(record);
        }

        Ok(DnsMessage {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DnsError> {
        let mut buf = Vec::new();

        // Validate counts match actual vectors
        let mut computed_counts = DnsHeader {
            ..self.header.clone()
        };
        computed_counts.qdcount = self.questions.len() as u16;
        computed_counts.ancount = self.answers.len() as u16;
        computed_counts.nscount = self.authorities.len() as u16;
        computed_counts.arcount = self.additionals.len() as u16;

        buf.extend_from_slice(&computed_counts.to_bytes());

        for question in &self.questions {
            question.emit_to(&mut buf);
        }

        for answer in &self.answers {
            answer.emit_to(&mut buf);
        }

        for authority in &self.authorities {
            authority.emit_to(&mut buf);
        }

        for additional in &self.additionals {
            additional.emit_to(&mut buf);
        }

        Ok(buf)
    }
}

impl Default for DnsMessage {
    fn default() -> Self {
        Self {
            header: DnsHeader {
                id: 0,
                message_type: DnsMessageType::Query,
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: 0,
                rcode: DnsResponseCode::NoError,
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}
