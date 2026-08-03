// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, str::FromStr};

use crate::{DnsType, ErrorKind, MudzError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsClass {
    IN,
    CS,
    CH,
    HS,
    Other(u16),
}

impl From<DnsClass> for u16 {
    fn from(class: DnsClass) -> Self {
        match class {
            DnsClass::IN => 1,
            DnsClass::CS => 2,
            DnsClass::CH => 3,
            DnsClass::HS => 4,
            DnsClass::Other(c) => c,
        }
    }
}

impl From<u16> for DnsClass {
    fn from(value: u16) -> Self {
        match value {
            1 => DnsClass::IN,
            2 => DnsClass::CS,
            3 => DnsClass::CH,
            4 => DnsClass::HS,
            _ => DnsClass::Other(value),
        }
    }
}

impl Default for DnsClass {
    fn default() -> Self {
        DnsClass::Other(u16::MAX)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub domain: DnsDomainName,
    pub kind: DnsType,
    pub class: DnsClass,
}

impl DnsQuestion {
    // 1 byte for QNAME, 2 byts for QTYPE, 2 bytes for QCLASS
    pub const HDR_LEN: usize = 5;

    pub fn parse_from(
        buf: &[u8],
        offset: &mut usize,
    ) -> Result<Self, MudzError> {
        let domain = DnsDomainName::parse_from(buf, offset)?;

        if *offset + 4 > buf.len() {
            return Err(MudzError::new(
                ErrorKind::InvalidPacket,
                format!(
                    "Insufficient buffer for question fields, expecting 4 \
                     bytes but only {} available",
                    buf.len() - *offset
                ),
            ));
        }

        let qtype = u16::from_be_bytes([buf[*offset], buf[*offset + 1]]);
        let qclass = u16::from_be_bytes([buf[*offset + 2], buf[*offset + 3]]);
        *offset += 4;

        Ok(DnsQuestion {
            domain,
            kind: DnsType::from(qtype),
            class: DnsClass::from(qclass),
        })
    }

    pub fn emit_to(&self, buf: &mut Vec<u8>) {
        self.domain.emit_to(buf);
        buf.extend_from_slice(&u16::from(self.kind).to_be_bytes());
        buf.extend_from_slice(&u16::from(self.class).to_be_bytes());
    }

    pub fn emit_to_compressed(
        &self,
        buf: &mut Vec<u8>,
        map: &mut DnsNameCompressionMap,
    ) {
        self.domain.emit_to_compressed(buf, map);
        buf.extend_from_slice(&u16::from(self.kind).to_be_bytes());
        buf.extend_from_slice(&u16::from(self.class).to_be_bytes());
    }
}

/// DNS Resource Record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    pub domain: DnsDomainName,
    pub kind: DnsType,
    pub class: DnsClass,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
}

fn kind_has_domain_names(kind: DnsType) -> bool {
    matches!(
        kind,
        DnsType::CNAME
            | DnsType::NS
            | DnsType::PTR
            | DnsType::MX
            | DnsType::SOA
            | DnsType::SRV
    )
}

impl DnsResourceRecord {
    pub const HDR_LEN: usize = 10;

    pub fn parse_from(
        buf: &[u8],
        offset: &mut usize,
    ) -> Result<Self, MudzError> {
        let domain = DnsDomainName::parse_from(buf, offset)?;

        if *offset + Self::HDR_LEN > buf.len() {
            return Err(MudzError::new(
                ErrorKind::InvalidPacket,
                "Insufficient buffer for resource record header",
            ));
        }

        let kind = u16::from_be_bytes([buf[*offset], buf[*offset + 1]]);
        let class = u16::from_be_bytes([buf[*offset + 2], buf[*offset + 3]]);
        let ttl = u32::from_be_bytes([
            buf[*offset + 4],
            buf[*offset + 5],
            buf[*offset + 6],
            buf[*offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[*offset + 8], buf[*offset + 9]]);
        *offset += Self::HDR_LEN;

        if *offset + rdlength as usize > buf.len() {
            return Err(MudzError::new(
                ErrorKind::InvalidPacket,
                "Insufficient buffer for RDATA",
            ));
        }

        let rdata_offset = *offset;
        let raw_rdata = buf[*offset..*offset + rdlength as usize].to_vec();
        *offset += rdlength as usize;

        let kind_enum = DnsType::from(kind);
        let rdata =
            Self::expand_rdata(buf, kind_enum, raw_rdata, rdata_offset)?;

        Ok(DnsResourceRecord {
            domain,
            kind: kind_enum,
            class: DnsClass::from(class),
            ttl,
            rdlength: rdata.len() as u16,
            rdata,
        })
    }

    /// For record types that embed domain names in rdata (CNAME, NS, PTR,
    /// MX, SOA, SRV), expand any compression pointers so the record can be
    /// re-emitted into a new packet without stale offset references.
    fn expand_rdata(
        buf: &[u8],
        kind: DnsType,
        rdata: Vec<u8>,
        rdata_offset: usize,
    ) -> Result<Vec<u8>, MudzError> {
        if !kind_has_domain_names(kind) {
            return Ok(rdata);
        }

        // For types where rdata is entirely a domain name, we can safely
        // check for compression pointers to skip unnecessary expansion.
        // For SOA/MX/SRV, the rdata also contains numeric fields, so a
        // byte-level scan would produce false positives — always expand.
        if matches!(kind, DnsType::CNAME | DnsType::NS | DnsType::PTR) {
            let has_compression = rdata.windows(2).any(|w| w[0] & 0xC0 == 0xC0);
            if !has_compression {
                return Ok(rdata);
            }
        }

        match kind {
            DnsType::CNAME | DnsType::NS | DnsType::PTR => {
                let mut off = rdata_offset;
                let name = DnsDomainName::parse_from(buf, &mut off)?;
                let mut out = Vec::new();
                name.emit_to(&mut out);
                Ok(out)
            }
            DnsType::MX => {
                if rdata.len() < 2 {
                    return Err(MudzError::new(
                        ErrorKind::InvalidPacket,
                        "MX rdata too short",
                    ));
                }
                let mut out = Vec::new();
                out.extend_from_slice(&rdata[..2]);
                let mut off = rdata_offset + 2;
                let name = DnsDomainName::parse_from(buf, &mut off)?;
                name.emit_to(&mut out);
                Ok(out)
            }
            DnsType::SOA => {
                let mut out = Vec::new();
                let mut off = rdata_offset;
                let mname = DnsDomainName::parse_from(buf, &mut off)?;
                mname.emit_to(&mut out);
                let rname = DnsDomainName::parse_from(buf, &mut off)?;
                rname.emit_to(&mut out);
                let consumed = off - rdata_offset;
                if consumed > rdata.len() {
                    return Err(MudzError::new(
                        ErrorKind::InvalidPacket,
                        "SOA rdata overflow",
                    ));
                }
                out.extend_from_slice(&rdata[consumed..]);
                Ok(out)
            }
            DnsType::SRV => {
                if rdata.len() < 6 {
                    return Err(MudzError::new(
                        ErrorKind::InvalidPacket,
                        "SRV rdata too short",
                    ));
                }
                let mut out = Vec::new();
                out.extend_from_slice(&rdata[..6]);
                let mut off = rdata_offset + 6;
                let name = DnsDomainName::parse_from(buf, &mut off)?;
                name.emit_to(&mut out);
                Ok(out)
            }
            _ => Ok(rdata),
        }
    }

    pub fn emit_to(&self, buf: &mut Vec<u8>) {
        self.emit_to_with_ttl(buf, &mut None);
    }

    pub fn emit_to_with_ttl(
        &self,
        buf: &mut Vec<u8>,
        ttl_positions: &mut Option<&mut Vec<(usize, u32)>>,
    ) {
        self.domain.emit_to(buf);
        buf.extend_from_slice(&u16::from(self.kind).to_be_bytes());
        buf.extend_from_slice(&u16::from(self.class).to_be_bytes());
        // The OPT pseudo-record (RFC 6891, type 41) reuses the TTL field to
        // carry the extended RCODE, version, and flags (including the DNSSEC
        // DO bit), so it is not a real TTL and must never be decremented.
        if let Some(positions) = ttl_positions
            && u16::from(self.kind) != 41
        {
            positions.push((buf.len(), self.ttl));
        }
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        let rdlength = self.rdata.len() as u16;
        buf.extend_from_slice(&rdlength.to_be_bytes());
        buf.extend_from_slice(&self.rdata);
    }

    /// Serialize with RFC 1035 §4.1.4 compression applied to the owner
    /// name. The rdata is emitted verbatim.
    pub fn emit_to_with_ttl_compressed(
        &self,
        buf: &mut Vec<u8>,
        ttl_positions: &mut Option<&mut Vec<(usize, u32)>>,
        map: &mut DnsNameCompressionMap,
    ) {
        self.domain.emit_to_compressed(buf, map);
        buf.extend_from_slice(&u16::from(self.kind).to_be_bytes());
        buf.extend_from_slice(&u16::from(self.class).to_be_bytes());
        if let Some(positions) = ttl_positions
            && u16::from(self.kind) != 41
        {
            positions.push((buf.len(), self.ttl));
        }
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        let rdlength = self.rdata.len() as u16;
        buf.extend_from_slice(&rdlength.to_be_bytes());
        buf.extend_from_slice(&self.rdata);
    }
}

/// A fully domain name
#[derive(Debug, Clone, Default)]
pub struct DnsDomainName {
    pub labels: Vec<Vec<u8>>,
    pub raw_offset: usize,
    /// If the domain was originally encoded as a compression pointer,
    /// this stores the pointer target for faithful re-emission
    pub compression_pointer: Option<usize>,
}

impl PartialEq for DnsDomainName {
    /// DNS names are case-insensitive (RFC 4343): two names that differ only
    /// in label casing compare equal, consistent with [`Self::to_string`] /
    /// [`std::fmt::Display`], which lowercases. A name parsed from the wire
    /// preserves its original casing, while `FromStr` lowercases, so without
    /// this the same domain could compare unequal.
    fn eq(&self, other: &Self) -> bool {
        self.labels.len() == other.labels.len()
            && self.labels.iter().zip(&other.labels).all(|(a, b)| {
                a.len() == b.len()
                    && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
            })
    }
}

impl Eq for DnsDomainName {}

impl std::hash::Hash for DnsDomainName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Must match `PartialEq`: hash the case-folded labels so names that
        // compare equal always hash equal.
        for label in &self.labels {
            state.write_usize(label.len());
            for byte in label {
                state.write_u8(byte.to_ascii_lowercase());
            }
        }
    }
}

impl std::fmt::Display for DnsDomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.labels.is_empty() {
            return write!(f, ".");
        }
        write!(
            f,
            "{}",
            self.labels
                .iter()
                .map(|label| String::from_utf8_lossy(label).to_lowercase())
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
    ) -> Result<Self, MudzError> {
        let start_offset = *offset;
        let mut labels = Vec::new();
        let mut return_offset: Option<usize> = None;
        let mut compression_pointer: Option<usize> = None;
        let mut total_length: usize = 0;
        let mut pointer_count: usize = 0;
        let mut terminated = false;
        const MAX_POINTER_CHAIN: usize = 10; // Prevent excessive chaining

        while *offset < buf.len() {
            let len_byte = buf[*offset];

            // Check for end of domain name
            if len_byte == 0 {
                *offset += 1;
                terminated = true;
                break;
            }

            // Check for compression pointer (top 2 bits set to 11)
            if (len_byte & 0xC0) == 0xC0 {
                // Validate: only one compression pointer allowed at the end
                if *offset + 1 >= buf.len() {
                    return Err(MudzError::new(
                        ErrorKind::InvalidPacket,
                        "Pointer offset out of bounds",
                    ));
                }

                // Detect cycles
                pointer_count += 1;
                if pointer_count > MAX_POINTER_CHAIN {
                    return Err(MudzError::new(
                        ErrorKind::InvalidPacket,
                        "Too many compression pointers (possible cycle)",
                    ));
                }

                let pointer_offset = (((len_byte & 0x3F) as u16) << 8)
                    | (buf[*offset + 1] as u16);
                if pointer_offset as usize >= buf.len() {
                    return Err(MudzError::new(
                        ErrorKind::InvalidPacket,
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
                return Err(MudzError::new(
                    ErrorKind::InvalidPacket,
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
                return Err(MudzError::new(
                    ErrorKind::InvalidPacket,
                    "Domain name exceeds 255 byte limit",
                ));
            }

            *offset += 1;
            if *offset + len > buf.len() {
                return Err(MudzError::new(
                    ErrorKind::InvalidPacket,
                    "Insufficient buffer for label",
                ));
            }
            labels.push(buf[*offset..*offset + len].to_vec());
            *offset += len;
        }

        // RFC 1035 §3.1: every wire-format domain name must end with a
        // zero-length label (the root). If the buffer ran out before the
        // terminator, the name is malformed.
        if !terminated {
            return Err(MudzError::new(
                ErrorKind::InvalidPacket,
                "Domain name not terminated by a zero-length label",
            ));
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

    /// Serialize domain name to buffer
    pub fn emit_to(&self, buf: &mut Vec<u8>) {
        for label in &self.labels {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label);
        }
        buf.push(0);
    }

    /// Serialize this domain name into `buf` using DNS message compression
    /// (RFC 1035 §4.1.4). Repeated labels are replaced with 2-byte pointers
    /// to a prior occurrence. `map` tracks name-suffix → byte-offset across
    /// the whole message.
    pub fn emit_to_compressed(
        &self,
        buf: &mut Vec<u8>,
        map: &mut DnsNameCompressionMap,
    ) {
        let labels = &self.labels;
        for i in 0..labels.len() {
            let suffix = DnsNameCompressionMap::suffix_key(&labels[i..]);
            if let Some(&offset) = map.names.get(&suffix) {
                map.emit_pointer(buf, offset);
                return;
            }
            map.names.insert(suffix, buf.len());
            buf.push(labels[i].len() as u8);
            buf.extend_from_slice(&labels[i]);
        }
        buf.push(0);
    }
}

/// Tracks domain-name byte offsets during packet serialization so repeated
/// names can be emitted as RFC 1035 §4.1.4 compression pointers. One map is
/// created per serialized message and shared across all sections.
#[derive(Debug, Default)]
pub struct DnsNameCompressionMap {
    names: HashMap<String, usize>,
}

impl DnsNameCompressionMap {
    pub fn new() -> Self {
        Self::default()
    }

    fn suffix_key(labels: &[Vec<u8>]) -> String {
        labels
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(".")
    }

    /// RFC 1035 §4.1.4: a compression pointer is two octets; the two most
    /// significant bits are 1, and the remaining 14 bits hold the offset
    /// from the start of the message. The 14-bit field caps the usable
    /// offset at 16383.
    fn emit_pointer(&self, buf: &mut Vec<u8>, offset: usize) {
        let offset = offset & 0x3FFF;
        buf.push(0xC0 | ((offset >> 8) & 0x3F) as u8);
        buf.push((offset & 0xFF) as u8);
    }
}

impl FromStr for DnsDomainName {
    type Err = MudzError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if name.is_empty() {
            return Err(MudzError::new(
                ErrorKind::InvalidArgument,
                "Domain name cannot be empty",
            ));
        }

        // Root domain: "." is a single zero-length label
        if name == "." {
            return Ok(DnsDomainName {
                labels: Vec::new(),
                raw_offset: 0,
                compression_pointer: None,
            });
        }

        let mut labels = Vec::new();
        for label in name.split('.') {
            // Skip empty labels (e.g., from trailing dot)
            if label.is_empty() {
                continue;
            }
            if label.len() > 63 {
                return Err(MudzError::new(
                    ErrorKind::InvalidPacket,
                    format!("Label '{}' exceeds 63 characters", label),
                ));
            }
            // Normalize to lowercase per RFC 1035
            labels.push(label.to_ascii_lowercase().into_bytes());
        }

        if labels.is_empty() {
            return Err(MudzError::new(
                ErrorKind::InvalidPacket,
                "Domain name must contain at least one label",
            ));
        }

        Ok(DnsDomainName {
            labels,
            raw_offset: 0,
            compression_pointer: None,
        })
    }
}
