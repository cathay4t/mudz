// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use mudz::{
    DnsClass, DnsDomainName, DnsHeader, DnsPacket, DnsQuestion,
    DnsResourceRecord, DnsResponseCode, DnsType,
};

use super::{build_client_reply, validate_upstream_response};

/// A NOERROR response to `example.com A` carrying an OPT record whose
/// TTL encodes the given extended RCODE in its high byte.
fn response_with_ext_rcode(ext_rcode: u8) -> DnsPacket {
    let domain = DnsDomainName::from_str("example.com").unwrap();
    let opt_ttl: u32 = (ext_rcode as u32) << 24;
    DnsPacket {
        header: DnsHeader {
            id: 0x1234,
            qr: true,
            rcode: DnsResponseCode::NoError,
            qdcount: 1,
            arcount: 1,
            ..Default::default()
        },
        questions: vec![DnsQuestion {
            domain: domain.clone(),
            kind: DnsType::A,
            class: DnsClass::IN,
        }],
        answers: vec![DnsResourceRecord {
            domain: domain.clone(),
            kind: DnsType::A,
            class: DnsClass::IN,
            ttl: 300,
            rdlength: 4,
            rdata: vec![1, 2, 3, 4],
        }],
        authorities: Vec::new(),
        additionals: vec![DnsResourceRecord {
            domain: DnsDomainName::default(),
            kind: DnsType::Other(41),
            class: DnsClass::Other(1232),
            ttl: opt_ttl,
            rdlength: 0,
            rdata: Vec::new(),
        }],
    }
}

#[test]
fn test_validate_accepts_matching_response() {
    let packet = response_with_ext_rcode(0);
    assert!(validate_upstream_response(
        &packet,
        "example.com",
        DnsType::A,
        DnsClass::IN,
    ));
}

#[test]
fn test_validate_rejects_extended_rcode() {
    // BADVERS = 16 (ext-rcode 1): the header says NoError, but the
    // response is an error and must not be treated as a valid answer.
    let packet = response_with_ext_rcode(1);
    assert_eq!(packet.extended_rcode(), 1);
    assert!(!validate_upstream_response(
        &packet,
        "example.com",
        DnsType::A,
        DnsClass::IN,
    ));
}

#[test]
fn test_validate_rejects_question_mismatch() {
    let packet = response_with_ext_rcode(0);
    assert!(!validate_upstream_response(
        &packet,
        "other.com",
        DnsType::A,
        DnsClass::IN,
    ));
    assert!(!validate_upstream_response(
        &packet,
        "example.com",
        DnsType::AAAA,
        DnsClass::IN,
    ));
}

/// A NOERROR response to `example.com A` with 100 answers, serialized to
/// well over 512 bytes.
fn large_response() -> Vec<u8> {
    let domain = DnsDomainName::from_str("example.com").unwrap();
    let packet = DnsPacket {
        header: DnsHeader {
            id: 0x1234,
            qr: true,
            rcode: DnsResponseCode::NoError,
            qdcount: 1,
            ancount: 100,
            ..Default::default()
        },
        questions: vec![DnsQuestion {
            domain: domain.clone(),
            kind: DnsType::A,
            class: DnsClass::IN,
        }],
        answers: (0..100u8)
            .map(|i| DnsResourceRecord {
                domain: domain.clone(),
                kind: DnsType::A,
                class: DnsClass::IN,
                ttl: 300,
                rdlength: 4,
                rdata: vec![10, 0, 0, i],
            })
            .collect(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let bytes = packet.to_bytes();
    assert!(bytes.len() > 512, "test response must exceed 512 bytes");
    bytes
}

#[test]
fn test_build_client_reply_truncates_large_response_for_non_edns() {
    let reply =
        build_client_reply(&large_response(), 0x1111, true, None, false, false);
    assert!(
        reply.len() <= 512,
        "non-EDNS reply must fit in 512 bytes, got {}",
        reply.len()
    );
    let parsed = DnsPacket::parse(&reply).unwrap();
    assert!(parsed.header.tc, "TC bit must be set on truncation");
    assert_eq!(parsed.header.id, 0x1111);
    assert_eq!(parsed.questions[0].domain.to_string(), "example.com");
    // RFC 1035 §4.2.1: as many RRs as possible must be kept.
    assert!(
        !parsed.answers.is_empty(),
        "truncated reply must keep as many answers as fit"
    );
    assert!(
        parsed.answers.len() < 100,
        "not all 100 answers can fit in 512 bytes"
    );
    assert!(!parsed.has_edns());
}

#[test]
fn test_build_client_reply_truncates_to_edns_payload() {
    let reply = build_client_reply(
        &large_response(),
        0x2222,
        false,
        Some(512),
        false,
        false,
    );
    assert!(
        reply.len() <= 512,
        "reply must fit within the advertised payload, got {}",
        reply.len()
    );
    let parsed = DnsPacket::parse(&reply).unwrap();
    assert!(parsed.header.tc, "TC bit must be set on truncation");
    assert_eq!(parsed.header.id, 0x2222);
    assert_eq!(parsed.questions[0].domain.to_string(), "example.com");
    assert!(
        !parsed.answers.is_empty(),
        "truncated reply must keep as many answers as fit"
    );
    assert!(parsed.answers.len() < 100);
    // An EDNS client still gets its OPT ack.
    assert!(parsed.has_edns());
}

#[test]
fn test_build_client_reply_tiny_advertised_payload() {
    // A client advertising an absurdly small payload (below the 512
    // octet EDNS minimum) must still receive a reply that fits, even if
    // that means dropping the question section entirely.
    let reply = build_client_reply(
        &large_response(),
        0x4444,
        false,
        Some(40),
        false,
        false,
    );
    assert!(
        reply.len() <= 40,
        "reply must fit within the tiny advertised payload, got {}",
        reply.len()
    );
    let parsed = DnsPacket::parse(&reply).unwrap();
    assert!(parsed.header.tc, "TC bit must be set on truncation");
    assert_eq!(parsed.header.id, 0x4444);
}

#[test]
fn test_build_client_reply_malformed_neutral() {
    // Garbage neutral bytes: must not panic and must yield a parseable
    // header-only reply with TC set instead of a corrupt message.
    let garbage = vec![0xAA; 600];
    let reply = build_client_reply(&garbage, 0x5555, true, None, false, false);
    assert!(reply.len() <= 512);
    let parsed = DnsPacket::parse(&reply).unwrap();
    assert!(parsed.header.tc);
    assert_eq!(parsed.header.id, 0x5555);
    assert!(parsed.questions.is_empty());
}

#[test]
fn test_build_client_reply_tcp_never_truncates() {
    // RFC 7766 §7: over TCP there is no message size limit. A reply that
    // would be truncated to 512 bytes over UDP is delivered whole with
    // TC clear, even for a non-EDNS client.
    let reply =
        build_client_reply(&large_response(), 0x8888, true, None, false, true);
    let parsed = DnsPacket::parse(&reply).unwrap();
    assert_eq!(parsed.answers.len(), 100);
    assert!(!parsed.header.tc, "TCP reply must not be truncated");
    assert!(
        !parsed.has_edns(),
        "non-EDNS client must not get an OPT record over TCP"
    );

    // EDNS client over TCP: full answer plus OPT ack, still no
    // truncation even with a tiny advertised payload (RFC 7766 §7).
    let reply = build_client_reply(
        &large_response(),
        0x9999,
        true,
        Some(40),
        true,
        true,
    );
    assert!(reply.len() > 512, "TCP reply carries the full answer");
    let parsed = DnsPacket::parse(&reply).unwrap();
    assert_eq!(parsed.answers.len(), 100);
    assert!(!parsed.header.tc);
    assert!(parsed.has_edns());
    assert!(parsed.dnssec_ok());
}

#[test]
fn test_build_client_reply_keeps_small_response() {
    let domain = DnsDomainName::from_str("example.com").unwrap();
    let packet = DnsPacket {
        header: DnsHeader {
            id: 0x3333,
            qr: true,
            rcode: DnsResponseCode::NoError,
            qdcount: 1,
            ancount: 1,
            ..Default::default()
        },
        questions: vec![DnsQuestion {
            domain: domain.clone(),
            kind: DnsType::A,
            class: DnsClass::IN,
        }],
        answers: vec![DnsResourceRecord {
            domain: domain.clone(),
            kind: DnsType::A,
            class: DnsClass::IN,
            ttl: 300,
            rdlength: 4,
            rdata: vec![1, 2, 3, 4],
        }],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let neutral = packet.to_bytes();

    // Small response for a non-EDNS client: no truncation, no OPT ack.
    let reply = build_client_reply(&neutral, 0x3333, true, None, false, false);
    let parsed = DnsPacket::parse(&reply).unwrap();
    assert!(!parsed.header.tc);
    assert_eq!(parsed.answers.len(), 1);
    assert!(!parsed.has_edns());

    // Small response for an EDNS client with DO=1: intact, with OPT ack
    // echoing the DO bit.
    let reply =
        build_client_reply(&neutral, 0x3333, true, Some(4096), true, false);
    let parsed = DnsPacket::parse(&reply).unwrap();
    assert!(!parsed.header.tc);
    assert_eq!(parsed.answers.len(), 1);
    assert!(parsed.has_edns());
    assert!(parsed.dnssec_ok());
}

#[test]
fn test_truncation_keeps_maximum_answers() {
    // With RFC 1035 §4.1.4 compression, each A record for "example.com"
    // serializes to 16 bytes (2-byte pointer to the question name +
    // 2 type + 2 class + 4 TTL + 2 rdlength + 4 rdata).
    // Header(12) + question(17) = 29 bytes overhead.
    // Non-EDNS limit 512: (512 - 29) / 16 = 30 answers fit.
    let reply =
        build_client_reply(&large_response(), 0x6666, true, None, false, false);
    let parsed = DnsPacket::parse(&reply).unwrap();
    assert!(parsed.header.tc);
    assert_eq!(parsed.answers.len(), 30);
    assert!(reply.len() <= 512);
    // Adding one more answer would exceed 512: 29 + 31 * 16 = 525.
}

/// A CNAME chain response similar to `finance.sina.com.cn`: 3 CNAMEs
/// plus enough A records that even the compressed serialization exceeds
/// 512 bytes.
fn cname_chain_response() -> Vec<u8> {
    let domain = DnsDomainName::from_str("finance.sina.com.cn").unwrap();
    let cname1 =
        DnsDomainName::from_str("financesina.gslb.sinaedge.com").unwrap();
    let cname2 = DnsDomainName::from_str("acksmall.grid.sinaedge.com").unwrap();
    let cname3 =
        DnsDomainName::from_str("ww1.sinaimg.cn.w.alikunlun.com").unwrap();
    let mut answers = vec![
        DnsResourceRecord {
            domain: domain.clone(),
            kind: DnsType::CNAME,
            class: DnsClass::IN,
            ttl: 300,
            rdlength: 0,
            rdata: {
                let mut b = Vec::new();
                cname1.emit_to(&mut b);
                b
            },
        },
        DnsResourceRecord {
            domain: cname1.clone(),
            kind: DnsType::CNAME,
            class: DnsClass::IN,
            ttl: 300,
            rdlength: 0,
            rdata: {
                let mut b = Vec::new();
                cname2.emit_to(&mut b);
                b
            },
        },
        DnsResourceRecord {
            domain: cname2.clone(),
            kind: DnsType::CNAME,
            class: DnsClass::IN,
            ttl: 300,
            rdlength: 0,
            rdata: {
                let mut b = Vec::new();
                cname3.emit_to(&mut b);
                b
            },
        },
    ];
    for i in 0..40u8 {
        answers.push(DnsResourceRecord {
            domain: cname3.clone(),
            kind: DnsType::A,
            class: DnsClass::IN,
            ttl: 37,
            rdlength: 4,
            rdata: vec![121, 17, 122, 56 + i],
        });
    }
    let packet = DnsPacket {
        header: DnsHeader {
            id: 0x7777,
            qr: true,
            rcode: DnsResponseCode::NoError,
            qdcount: 1,
            ancount: answers.len() as u16,
            ..Default::default()
        },
        questions: vec![DnsQuestion {
            domain,
            kind: DnsType::A,
            class: DnsClass::IN,
        }],
        answers,
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let bytes = packet.to_bytes();
    assert!(bytes.len() > 512, "CNAME chain must exceed 512 bytes");
    bytes
}

#[test]
fn test_truncation_keeps_cname_chain_and_some_answers() {
    // A non-EDNS client querying a CNAME chain with many A records
    // (like `host finance.sina.com.cn`) must receive as many records
    // as fit within 512 bytes, not an empty truncated reply.
    let reply = build_client_reply(
        &cname_chain_response(),
        0x7777,
        true,
        None,
        false,
        false,
    );
    assert!(reply.len() <= 512);
    let parsed = DnsPacket::parse(&reply).unwrap();
    assert!(parsed.header.tc);
    assert_eq!(parsed.header.id, 0x7777);
    // The 3 CNAME records plus a few A records must fit; at minimum the
    // CNAME chain is preserved.
    assert!(
        parsed.answers.len() >= 3,
        "CNAME chain must survive truncation, got {} answers",
        parsed.answers.len()
    );
    assert!(
        parsed.answers.len() < 43,
        "not all 43 records can fit in 512 bytes"
    );
    // First three answers must be the CNAME chain in order.
    assert_eq!(parsed.answers[0].kind, DnsType::CNAME);
    assert_eq!(parsed.answers[1].kind, DnsType::CNAME);
    assert_eq!(parsed.answers[2].kind, DnsType::CNAME);
}
