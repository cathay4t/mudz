// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use crate::{
    DnsClass, DnsDomainName, DnsHeader, DnsQuestion, DnsResourceRecord,
    DnsResponseCode, MudzError,
};

/// DNS query types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsType {
    /// RFC 1035: The IPv4 address record
    A,
    /// RFC 3596: The IPv6 address record
    AAAA,
    /// RFC 1035: The canonical name record
    CNAME,
    /// RFC 1035: The mail exchange record
    MX,
    /// RFC 1035: The name server record
    NS,
    /// RFC 1035: The start of authority record
    SOA,
    /// RFC 1035: The text record
    TXT,
    /// RFC 1035: The domain name pointer record
    PTR,
    /// RFC 2782: The service locator record
    SRV,
    /// RFC 9460: HTTPS resource record
    HTTPS,
    /// RFC 8482: Host information record
    HINFO,
    Other(u16),
}

impl From<DnsType> for u16 {
    fn from(qtype: DnsType) -> Self {
        match qtype {
            DnsType::A => 1,
            DnsType::AAAA => 28,
            DnsType::CNAME => 5,
            DnsType::MX => 15,
            DnsType::NS => 2,
            DnsType::SOA => 6,
            DnsType::TXT => 16,
            DnsType::PTR => 12,
            DnsType::SRV => 33,
            DnsType::HTTPS => 65,
            DnsType::HINFO => 13,
            DnsType::Other(t) => t,
        }
    }
}

impl From<u16> for DnsType {
    fn from(value: u16) -> Self {
        match value {
            1 => DnsType::A,
            28 => DnsType::AAAA,
            5 => DnsType::CNAME,
            15 => DnsType::MX,
            2 => DnsType::NS,
            6 => DnsType::SOA,
            16 => DnsType::TXT,
            12 => DnsType::PTR,
            33 => DnsType::SRV,
            65 => DnsType::HTTPS,
            13 => DnsType::HINFO,
            _ => DnsType::Other(value),
        }
    }
}

impl std::fmt::Display for DnsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsType::A => write!(f, "A"),
            DnsType::AAAA => write!(f, "AAAA"),
            DnsType::CNAME => write!(f, "CNAME"),
            DnsType::MX => write!(f, "MX"),
            DnsType::NS => write!(f, "NS"),
            DnsType::SOA => write!(f, "SOA"),
            DnsType::TXT => write!(f, "TXT"),
            DnsType::PTR => write!(f, "PTR"),
            DnsType::SRV => write!(f, "SRV"),
            DnsType::HTTPS => write!(f, "HTTPS"),
            DnsType::HINFO => write!(f, "HINFO"),
            DnsType::Other(t) => write!(f, "TYPE{}", t),
        }
    }
}

impl Default for DnsType {
    fn default() -> Self {
        Self::Other(u16::MAX)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsPacket {
    pub header: DnsHeader,
    // RFC 9619 said: In the DNS, QDCOUNT Is (Usually) One
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additionals: Vec<DnsResourceRecord>,
}

impl DnsPacket {
    /// RFC6891: A good compromise may be the use of an EDNS maximum payload
    /// size of 4096 octets as a starting point.
    pub const MAX_UDP_EDNS_PACKET_SIZE: usize = 4096;
    /// RFC 8484: This media type restricts the maximum size of the DNS message
    /// to 65535 bytes
    pub const MAX_DOH_PACKET_SIZE: usize = 65535;

    pub fn parse(data: &[u8]) -> Result<Self, MudzError> {
        let header = DnsHeader::parse(data)?;

        let mut offset = DnsHeader::LEN;

        let remaining = data.len().saturating_sub(offset);
        let mut questions = Vec::with_capacity(std::cmp::min(
            header.qdcount as usize,
            remaining / DnsQuestion::HDR_LEN,
        ));

        // RFC 9619 said: In the DNS, QDCOUNT Is (Usually) One
        // But we still parse multiple here, so follow up data can be parsed.
        for _ in 0..header.qdcount {
            let question = DnsQuestion::parse_from(data, &mut offset)?;
            questions.push(question);
        }

        let remaining = data.len().saturating_sub(offset);
        let mut answers = Vec::with_capacity(std::cmp::min(
            header.ancount as usize,
            remaining / DnsResourceRecord::HDR_LEN,
        ));
        for _ in 0..header.ancount {
            let record = DnsResourceRecord::parse_from(data, &mut offset)?;
            answers.push(record);
        }

        let remaining = data.len().saturating_sub(offset);
        let mut authorities = Vec::with_capacity(std::cmp::min(
            header.nscount as usize,
            remaining / DnsResourceRecord::HDR_LEN,
        ));
        for _ in 0..header.nscount {
            let record = DnsResourceRecord::parse_from(data, &mut offset)?;
            authorities.push(record);
        }

        let remaining = data.len().saturating_sub(offset);
        let mut additionals = Vec::with_capacity(std::cmp::min(
            header.arcount as usize,
            remaining,
        ));
        for _ in 0..header.arcount {
            let record = DnsResourceRecord::parse_from(data, &mut offset)?;
            additionals.push(record);
        }

        Ok(DnsPacket {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_with_ttls(None)
    }

    pub fn to_bytes_with_ttls(
        &self,
        mut ttl_positions: Option<&mut Vec<(usize, u32)>>,
    ) -> Vec<u8> {
        let mut buf = self.header.to_bytes();

        for question in &self.questions {
            question.emit_to(&mut buf);
        }

        for answer in &self.answers {
            answer.emit_to_with_ttl(&mut buf, &mut ttl_positions);
        }

        for authority in &self.authorities {
            authority.emit_to_with_ttl(&mut buf, &mut ttl_positions);
        }

        for additional in &self.additionals {
            additional.emit_to_with_ttl(&mut buf, &mut ttl_positions);
        }

        buf
    }

    /// Serialize this packet omitting any EDNS(0) OPT pseudo-records, with
    /// the header ARCOUNT adjusted accordingly. RFC 6891 §6.2.1 mandates
    /// that OPT records MUST NOT be cached, so this is the form stored in
    /// the cache. TTL byte offsets are recorded in `ttl_positions` for later
    /// in-place decrement (OPT records, having no real TTL, are excluded).
    pub fn to_bytes_without_opt(
        &self,
        mut ttl_positions: Option<&mut Vec<(usize, u32)>>,
    ) -> Vec<u8> {
        let opt_count = self
            .additionals
            .iter()
            .filter(|r| u16::from(r.kind) == 41)
            .count() as u16;
        let mut header = self.header.clone();
        header.arcount = header.arcount.saturating_sub(opt_count);
        let mut buf = header.to_bytes();

        for question in &self.questions {
            question.emit_to(&mut buf);
        }
        for answer in &self.answers {
            answer.emit_to_with_ttl(&mut buf, &mut ttl_positions);
        }
        for authority in &self.authorities {
            authority.emit_to_with_ttl(&mut buf, &mut ttl_positions);
        }
        for additional in &self.additionals {
            if u16::from(additional.kind) == 41 {
                continue;
            }
            additional.emit_to_with_ttl(&mut buf, &mut ttl_positions);
        }

        buf
    }

    pub fn is_query(&self) -> bool {
        self.header.is_query()
    }

    /// First record in answers or authorities or additionals, in this order.
    pub fn first_record(&self) -> Option<&DnsResourceRecord> {
        self.answers
            .first()
            .or_else(|| self.authorities.first())
            .or_else(|| self.additionals.first())
    }

    pub fn first_question(&self) -> Option<&DnsQuestion> {
        self.questions.first()
    }

    /// The EDNS(0) OPT pseudo-record (RFC 6891, type 41) from the additional
    /// section, if present.
    pub fn opt_record(&self) -> Option<&DnsResourceRecord> {
        self.additionals.iter().find(|r| u16::from(r.kind) == 41)
    }

    /// Whether the packet contains an EDNS OPT record (type 41) in the
    /// additional section.
    pub fn has_edns(&self) -> bool {
        self.opt_record().is_some()
    }

    /// The DNSSEC OK (DO) bit from the OPT record's flags (RFC 6891 §6.1.4,
    /// RFC 3225). False when no OPT record is present.
    pub fn dnssec_ok(&self) -> bool {
        self.opt_record().is_some_and(|r| r.ttl & 0x0000_8000 != 0)
    }

    /// The UDP payload size advertised in the OPT record's CLASS field
    /// (RFC 6891 §6.1.2), or None when no OPT record is present.
    pub fn edns_udp_payload_size(&self) -> Option<u16> {
        self.opt_record().map(|r| u16::from(r.class))
    }

    /// Append an EDNS(0) OPT pseudo-record (RFC 6891) to a serialized DNS
    /// message and bump the header ARCOUNT. Used to acknowledge an EDNS
    /// client when replaying a cached response that was stored without its
    /// OPT record (RFC 6891 §6.1.1: a response to an EDNS query MUST carry
    /// an OPT record). The OPT TTL field carries EXTENDED-RCODE=0, VERSION=0,
    /// the supplied DO bit, and Z=0; no EDNS options are emitted.
    pub fn append_opt_ack(
        buf: &mut Vec<u8>,
        udp_payload_size: u16,
        dnssec_ok: bool,
    ) {
        buf.push(0x00); // NAME: root
        buf.extend_from_slice(&u16::from(DnsType::Other(41)).to_be_bytes());
        buf.extend_from_slice(&udp_payload_size.to_be_bytes()); // CLASS
        let flags: u32 = if dnssec_ok { 0x0000_8000 } else { 0 };
        buf.extend_from_slice(&flags.to_be_bytes()); // TTL: ext-RCODE|VER|DO|Z
        buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH: no options
        if buf.len() >= DnsHeader::LEN {
            let arcount =
                u16::from_be_bytes([buf[10], buf[11]]).saturating_add(1);
            buf[10..12].copy_from_slice(&arcount.to_be_bytes());
        }
    }

    /// Append an EDNS(0) OPT pseudo-record (RFC 6891) to this packet's
    /// additional section and bump ARCOUNT. Used to turn a plain query into
    /// an EDNS query. `udp_payload_size` is advertised in the OPT CLASS field
    /// and `dnssec_ok` sets the DO flag (RFC 3225).
    pub fn add_opt_record(&mut self, udp_payload_size: u16, dnssec_ok: bool) {
        let ttl: u32 = if dnssec_ok { 0x0000_8000 } else { 0 };
        self.additionals.push(DnsResourceRecord {
            domain: DnsDomainName::default(),
            kind: DnsType::Other(41),
            class: DnsClass::Other(udp_payload_size),
            ttl,
            rdlength: 0,
            rdata: Vec::new(),
        });
        self.header.arcount = self.header.arcount.saturating_add(1);
    }

    pub fn domain_name(&self) -> Option<String> {
        if let Some(record) = self.first_question() {
            Some(record.domain.to_string())
        } else {
            self.first_record().map(|record| record.domain.to_string())
        }
    }

    pub fn display_brief(&self) -> String {
        format!(
            "{} {} {}",
            if self.is_query() { "query" } else { "response" },
            self.first_question().map(|r| r.kind).unwrap_or_default(),
            self.first_question()
                .map(|r| r.domain.to_string())
                .unwrap_or("invalid domain".to_string())
        )
    }

    pub fn new_query(domain: &str, kind: DnsType) -> Result<Self, MudzError> {
        let transaction_id = rand::random::<u16>();
        let domain_obj = DnsDomainName::from_str(domain)?;

        let ret = DnsPacket {
            header: DnsHeader::new_query(transaction_id),
            questions: vec![DnsQuestion {
                domain: domain_obj,
                kind,
                class: DnsClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        Ok(ret)
    }

    pub fn new_reply(
        id: u16,
        code: DnsResponseCode,
        domain: DnsDomainName,
        kind: DnsType,
        class: DnsClass,
        rd: bool,
    ) -> Self {
        DnsPacket {
            header: DnsHeader::new_response(id, code, rd),
            questions: vec![DnsQuestion {
                domain,
                kind,
                class,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}
