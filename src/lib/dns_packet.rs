// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additional: Vec<DnsResourceRecord>,
}

/// RFC 1035: 4.1.1. Header section format
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DnsResourceRecord {
    pub name: String,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl DnsPacket {
    pub fn parse(data: &[u8]) -> Result<DnsPacket, Box<dyn std::error::Error>> {
        if data.len() < 12 {
            return Err("Packet too short".into());
        }

        let id = BigEndian::read_u16(&data[0..2]);
        let flags = BigEndian::read_u16(&data[2..4]);
        let question_count = BigEndian::read_u16(&data[4..6]);
        let answer_count = BigEndian::read_u16(&data[6..8]);
        let authority_count = BigEndian::read_u16(&data[8..10]);
        let additional_count = BigEndian::read_u16(&data[10..12]);

        let mut offset = 12;
        let mut questions = Vec::new();
        let mut answers = Vec::new();
        let mut authorities = Vec::new();
        let mut additional = Vec::new();

        // Parse questions
        for _ in 0..question_count {
            let (name, new_offset) = parse_domain_name(data, offset)?;
            offset = new_offset;

            if offset + 4 > data.len() {
                return Err("Insufficient data for question".into());
            }

            let qtype = BigEndian::read_u16(&data[offset..offset + 2]);
            let qclass = BigEndian::read_u16(&data[offset + 2..offset + 4]);
            offset += 4;

            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }

        // Parse answers
        for _ in 0..answer_count {
            let (name, new_offset) = parse_domain_name(data, offset)?;
            offset = new_offset;

            if offset + 10 > data.len() {
                return Err("Insufficient data for answer".into());
            }

            let record_type = BigEndian::read_u16(&data[offset..offset + 2]);
            let class = BigEndian::read_u16(&data[offset + 2..offset + 4]);
            let ttl = BigEndian::read_u32(&data[offset + 4..offset + 8]);
            let data_len =
                BigEndian::read_u16(&data[offset + 8..offset + 10]) as usize;
            offset += 10;

            if offset + data_len > data.len() {
                return Err("Insufficient data for answer data".into());
            }

            let data = data[offset..offset + data_len].to_vec();
            offset += data_len;

            answers.push(DnsResourceRecord {
                name,
                record_type,
                class,
                ttl,
                data,
            });
        }

        // Parse authorities and additional (same format as answers)
        for _ in 0..authority_count {
            let (name, new_offset) = parse_domain_name(data, offset)?;
            offset = new_offset;

            if offset + 10 > data.len() {
                return Err("Insufficient data for authority".into());
            }

            let record_type = BigEndian::read_u16(&data[offset..offset + 2]);
            let class = BigEndian::read_u16(&data[offset + 2..offset + 4]);
            let ttl = BigEndian::read_u32(&data[offset + 4..offset + 8]);
            let data_len =
                BigEndian::read_u16(&data[offset + 8..offset + 10]) as usize;
            offset += 10;

            if offset + data_len > data.len() {
                return Err("Insufficient data for authority data".into());
            }

            let data = data[offset..offset + data_len].to_vec();
            offset += data_len;

            authorities.push(DnsResourceRecord {
                name,
                record_type,
                class,
                ttl,
                data,
            });
        }

        for _ in 0..additional_count {
            let (name, new_offset) = parse_domain_name(data, offset)?;
            offset = new_offset;

            if offset + 10 > data.len() {
                return Err("Insufficient data for additional".into());
            }

            let record_type = BigEndian::read_u16(&data[offset..offset + 2]);
            let class = BigEndian::read_u16(&data[offset + 2..offset + 4]);
            let ttl = BigEndian::read_u32(&data[offset + 4..offset + 8]);
            let data_len =
                BigEndian::read_u16(&data[offset + 8..offset + 10]) as usize;
            offset += 10;

            if offset + data_len > data.len() {
                return Err("Insufficient data for additional data".into());
            }

            let data = data[offset..offset + data_len].to_vec();
            offset += data_len;

            additional.push(DnsResourceRecord {
                name,
                record_type,
                class,
                ttl,
                data,
            });
        }

        Ok(DnsPacket {
            id,
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
            questions,
            answers,
            authorities,
            additional,
        })
    }
}

fn parse_domain_name(
    data: &[u8],
    mut offset: usize,
) -> Result<(String, usize), Box<dyn std::error::Error>> {
    let mut name = String::new();
    let mut labels = Vec::new();
    let mut pointer_offset = None;

    loop {
        if offset >= data.len() {
            return Err("Unexpected end of packet".into());
        }

        let label_len = data[offset] as usize;

        // Check for pointer (first two bits are 11)
        if (label_len & 0xC0) == 0xC0 {
            if pointer_offset.is_some() {
                return Err("Nested pointers not supported".into());
            }

            if offset + 1 >= data.len() {
                return Err("Incomplete pointer".into());
            }

            let pointer = ((label_len & 0x3F) << 8) | data[offset + 1] as usize;
            pointer_offset = Some(offset + 2);
            offset = pointer;
            continue;
        }

        // End of name (zero length label)
        if label_len == 0 {
            break;
        }

        if offset + 1 + label_len > data.len() {
            return Err("Label exceeds packet bounds".into());
        }

        let label =
            std::str::from_utf8(&data[offset + 1..offset + 1 + label_len])
                .map_err(|_| "Invalid UTF-8 in label")?;
        labels.push(label.to_string());
        offset += 1 + label_len;
    }

    name = labels.join(".");

    if let Some(pos) = pointer_offset {
        Ok((name, pos))
    } else {
        Ok((name, offset))
    }
}
