// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use mudz::{
    DnsClass, DnsDomainName, DnsHeader, DnsPacket, DnsQuestion,
    DnsResourceRecord, DnsResponseCode, DnsType, ErrorKind,
};

#[test]
fn test_dns_packet_new_query() {
    let packet = DnsPacket::new_query("example.com", DnsType::A)
        .expect("Failed to create query");

    assert!(packet.header.id != 0);
    assert!(packet.header.is_query());
    assert!(!packet.header.qr);
    assert!(packet.header.rd);
    assert_eq!(packet.header.qdcount, 1);
    assert_eq!(packet.header.ancount, 0);
    assert_eq!(packet.header.nscount, 0);
    assert_eq!(packet.header.arcount, 0);

    assert_eq!(packet.questions.len(), 1);
    let question = &packet.questions[0];
    assert_eq!(question.domain.to_string(), "example.com");
    assert_eq!(question.domain.labels.len(), 2);
    assert_eq!(question.domain.labels[0], b"example");
    assert_eq!(question.domain.labels[1], b"com");
    assert_eq!(question.kind, DnsType::A);
    assert_eq!(question.class, DnsClass::IN);

    assert_eq!(packet.answers.len(), 0);
    assert_eq!(packet.authorities.len(), 0);
    assert_eq!(packet.additionals.len(), 0);
}

#[test]
fn test_dns_packet_new_query_round_trip() {
    let packet = DnsPacket::new_query("google.com", DnsType::AAAA)
        .expect("Failed to create query");

    let bytes = packet.to_bytes();

    let reparsed = DnsPacket::parse(&bytes).expect("Failed to parse");

    assert_eq!(reparsed.header.id, packet.header.id);
    assert_eq!(reparsed.questions.len(), packet.questions.len());
    assert_eq!(
        reparsed.questions[0].domain.to_string(),
        packet.questions[0].domain.to_string()
    );
    assert_eq!(reparsed.questions[0].kind, packet.questions[0].kind);
}

#[test]
fn test_dns_packet_new_query_invalid_domain() {
    let result = DnsPacket::new_query("", DnsType::A);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind, ErrorKind::InvalidArgument);

    let long_label = "a".repeat(64);
    let result = DnsPacket::new_query(&long_label, DnsType::A);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind, ErrorKind::InvalidPacket);
}

#[test]
fn test_dns_query_packet_parse_emit_round_trip() {
    let raw_packet: Vec<u8> = vec![
        0xef, 0x8e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];

    let packet =
        DnsPacket::parse(&raw_packet).expect("Failed to parse DNS packet");

    assert_eq!(packet.header.id, 0xef8e);
    assert!(packet.header.is_query());
    assert!(!packet.header.qr);
    assert_eq!(packet.header.opcode, 0);
    assert!(!packet.header.aa);
    assert!(!packet.header.tc);
    assert!(packet.header.rd);
    assert!(!packet.header.ra);
    assert_eq!(packet.header.rcode, DnsResponseCode::NoError);
    assert_eq!(packet.header.qdcount, 1);
    assert_eq!(packet.header.ancount, 0);
    assert_eq!(packet.header.nscount, 0);
    assert_eq!(packet.header.arcount, 1);

    assert_eq!(packet.questions.len(), 1);
    let question = &packet.questions[0];
    assert_eq!(question.domain.to_string(), "google.com");
    assert_eq!(question.domain.labels.len(), 2);
    assert_eq!(question.domain.labels[0], b"google");
    assert_eq!(question.domain.labels[1], b"com");
    assert_eq!(question.kind, DnsType::A);
    assert_eq!(question.class, DnsClass::IN);

    assert_eq!(packet.answers.len(), 0);
    assert_eq!(packet.authorities.len(), 0);

    assert_eq!(packet.additionals.len(), 1);
    let opt_record = &packet.additionals[0];
    assert_eq!(opt_record.domain.labels.len(), 0);
    assert_eq!(opt_record.kind, DnsType::Other(41));
    assert_eq!(opt_record.class, DnsClass::Other(1232));
    assert_eq!(opt_record.ttl, 0);
    assert_eq!(opt_record.rdata.len(), 0);

    let emitted = packet.to_bytes();
    assert_eq!(emitted, raw_packet);
}

#[test]
fn test_dns_response_a_record_parse_emit() {
    let raw_packet: Vec<u8> = vec![
        0x2d, 0xc3, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x35, 0x00, 0x04, 0x8e, 0xfb, 0x23, 0x4e,
    ];

    let packet =
        DnsPacket::parse(&raw_packet).expect("Failed to parse DNS packet");

    assert_eq!(packet.header.id, 0x2dc3);
    assert!(packet.header.qr);
    assert_eq!(packet.header.opcode, 0);
    assert!(!packet.header.aa);
    assert!(!packet.header.tc);
    assert!(packet.header.rd);
    assert!(packet.header.ra);
    assert_eq!(packet.header.rcode, DnsResponseCode::NoError);
    assert_eq!(packet.header.qdcount, 1);
    assert_eq!(packet.header.ancount, 1);
    assert_eq!(packet.header.nscount, 0);
    assert_eq!(packet.header.arcount, 0);

    assert_eq!(packet.questions.len(), 1);
    let question = &packet.questions[0];
    assert_eq!(question.domain.to_string(), "google.com");
    assert_eq!(question.domain.labels.len(), 2);
    assert_eq!(question.domain.labels[0], b"google");
    assert_eq!(question.domain.labels[1], b"com");
    assert_eq!(question.kind, DnsType::A);
    assert_eq!(question.class, DnsClass::IN);

    assert_eq!(packet.answers.len(), 1);
    let answer = &packet.answers[0];
    assert_eq!(answer.domain.to_string(), "google.com");
    assert_eq!(answer.kind, DnsType::A);
    assert_eq!(answer.class, DnsClass::IN);
    assert_eq!(answer.ttl, 53);
    assert_eq!(answer.rdata.len(), 4);
    assert_eq!(answer.rdata, vec![0x8e, 0xfb, 0x23, 0x4e]);

    assert_eq!(packet.authorities.len(), 0);
    assert_eq!(packet.additionals.len(), 0);

    let emitted = packet.to_bytes();
    let reparsed =
        DnsPacket::parse(&emitted).expect("Failed to re-parse emitted packet");
    assert_eq!(reparsed.header.id, packet.header.id);
    assert_eq!(reparsed.questions.len(), packet.questions.len());
    assert_eq!(reparsed.answers.len(), packet.answers.len());
    assert_eq!(
        reparsed.answers[0].domain.to_string(),
        packet.answers[0].domain.to_string()
    );
    assert_eq!(reparsed.answers[0].rdata, packet.answers[0].rdata);
}

#[test]
fn test_dns_response_aaaa_with_compression() {
    let raw_packet: Vec<u8> = vec![
        0xd3, 0x04, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x05, 0x00, 0x10, 0x26, 0x07, 0xf8, 0xb0, 0x40, 0x07, 0x08, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e,
    ];

    let packet =
        DnsPacket::parse(&raw_packet).expect("Failed to parse DNS packet");

    assert_eq!(packet.header.id, 0xd304);
    assert!(packet.header.qr);
    assert_eq!(packet.header.opcode, 0);
    assert!(!packet.header.aa);
    assert!(!packet.header.tc);
    assert!(packet.header.rd);
    assert!(packet.header.ra);
    assert_eq!(packet.header.rcode, DnsResponseCode::NoError);
    assert_eq!(packet.header.qdcount, 1);
    assert_eq!(packet.header.ancount, 1);
    assert_eq!(packet.header.nscount, 0);
    assert_eq!(packet.header.arcount, 0);

    assert_eq!(packet.questions.len(), 1);
    let question = &packet.questions[0];
    assert_eq!(question.domain.to_string(), "google.com");
    assert_eq!(question.domain.labels.len(), 2);
    assert_eq!(question.domain.labels[0], b"google");
    assert_eq!(question.domain.labels[1], b"com");
    assert_eq!(question.kind, DnsType::AAAA);
    assert_eq!(question.class, DnsClass::IN);

    assert_eq!(packet.answers.len(), 1);
    let answer = &packet.answers[0];
    assert_eq!(answer.domain.to_string(), "google.com");
    assert_eq!(answer.kind, DnsType::AAAA);
    assert_eq!(answer.class, DnsClass::IN);
    assert_eq!(answer.ttl, 0x0105);
    assert_eq!(answer.rdata.len(), 16);
    assert_eq!(
        answer.rdata,
        vec![
            0x26, 0x07, 0xf8, 0xb0, 0x40, 0x07, 0x08, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x20, 0x0e,
        ]
    );

    assert_eq!(packet.authorities.len(), 0);
    assert_eq!(packet.additionals.len(), 0);

    let emitted = packet.to_bytes();
    let reparsed =
        DnsPacket::parse(&emitted).expect("Failed to re-parse emitted packet");
    assert_eq!(reparsed.header.id, packet.header.id);
    assert_eq!(reparsed.questions.len(), packet.questions.len());
    assert_eq!(reparsed.answers.len(), packet.answers.len());
    assert_eq!(
        reparsed.answers[0].domain.to_string(),
        packet.answers[0].domain.to_string()
    );
    assert_eq!(reparsed.answers[0].rdata, packet.answers[0].rdata);
}

#[test]
fn test_dns_cname_response_round_trip() {
    let raw_packet: Vec<u8> = vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00,
        0x00, 0x01, 0x2c, 0x00, 0x09, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
        0xc0, 0x0c,
    ];

    let packet =
        DnsPacket::parse(&raw_packet).expect("Failed to parse CNAME response");

    assert_eq!(packet.questions[0].domain.to_string(), "example.com");
    assert_eq!(packet.questions[0].kind, DnsType::A);

    assert_eq!(packet.answers.len(), 1);
    let answer = &packet.answers[0];
    assert_eq!(answer.domain.to_string(), "example.com");
    assert_eq!(answer.kind, DnsType::CNAME);
    assert_eq!(answer.ttl, 300);

    let emitted = packet.to_bytes();
    let reparsed =
        DnsPacket::parse(&emitted).expect("Failed to re-parse CNAME response");

    assert_eq!(reparsed.answers.len(), 1);
    let reparsed_answer = &reparsed.answers[0];
    assert_eq!(reparsed_answer.domain.to_string(), "example.com");
    assert_eq!(reparsed_answer.kind, DnsType::CNAME);
    assert_eq!(reparsed_answer.ttl, 300);
}

#[test]
fn test_dns_cname_rdata_expanded() {
    let raw_packet: Vec<u8> = vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00,
        0x00, 0x01, 0x2c, 0x00, 0x09, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
        0xc0, 0x0c,
    ];

    let packet =
        DnsPacket::parse(&raw_packet).expect("Failed to parse CNAME response");

    let answer = &packet.answers[0];
    assert!(answer.rdata.len() > 9, "rdata should be expanded");
    assert_eq!(answer.rdata[0], 6);
    assert_eq!(&answer.rdata[1..7], b"target");
    assert_eq!(answer.rdata[7], 7);
    assert_eq!(&answer.rdata[8..15], b"example");
    assert_eq!(answer.rdata[15], 3);
    assert_eq!(&answer.rdata[16..19], b"com");
    assert_eq!(answer.rdata[19], 0);

    let emitted = packet.to_bytes();
    let reparsed =
        DnsPacket::parse(&emitted).expect("Failed to re-parse expanded CNAME");
    let reparsed_answer = &reparsed.answers[0];
    assert_eq!(reparsed_answer.rdata, answer.rdata);
}

#[test]
fn test_parse_dns_header_flags() {
    let raw_packet: Vec<u8> = vec![
        0xef, 0x8e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];

    let packet = DnsPacket::parse(&raw_packet).expect("Failed to parse");

    assert!(packet.header.is_query());
    assert!(!packet.header.qr);
    assert!(packet.header.rd);
    assert!(!packet.header.ra);
    assert!(!packet.header.aa);
    assert!(!packet.header.tc);
}

#[test]
fn test_parse_domain_name() {
    let raw_packet: Vec<u8> = vec![
        0xef, 0x8e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];

    let packet = DnsPacket::parse(&raw_packet).expect("Failed to parse");

    let question = &packet.questions[0];
    assert_eq!(question.domain.labels.len(), 2);
    assert_eq!(question.domain.labels[0], b"google");
    assert_eq!(question.domain.labels[1], b"com");
    assert_eq!(question.domain.to_string(), "google.com");
}

#[test]
fn test_emit_domain_name() {
    let domain = DnsDomainName {
        labels: vec![b"google".to_vec(), b"com".to_vec()],
        raw_offset: 0,
        compression_pointer: None,
    };

    let mut buf = Vec::new();
    domain.emit_to(&mut buf);

    let expected = vec![
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    ];

    assert_eq!(buf, expected);
}

#[test]
fn test_dns_type_conversion() {
    assert_eq!(u16::from(DnsType::A), 1);
    assert_eq!(u16::from(DnsType::AAAA), 28);
    assert_eq!(u16::from(DnsType::CNAME), 5);
    assert_eq!(u16::from(DnsType::MX), 15);
    assert_eq!(u16::from(DnsType::NS), 2);
    assert_eq!(u16::from(DnsType::SOA), 6);
    assert_eq!(u16::from(DnsType::TXT), 16);
    assert_eq!(u16::from(DnsType::PTR), 12);
    assert_eq!(u16::from(DnsType::SRV), 33);
    assert_eq!(u16::from(DnsType::Other(99)), 99);

    assert_eq!(DnsType::from(1), DnsType::A);
    assert_eq!(DnsType::from(28), DnsType::AAAA);
    assert_eq!(DnsType::from(99), DnsType::Other(99));
}

#[test]
fn test_dns_class_conversion() {
    assert_eq!(u16::from(DnsClass::IN), 1);
    assert_eq!(u16::from(DnsClass::CS), 2);
    assert_eq!(u16::from(DnsClass::CH), 3);
    assert_eq!(u16::from(DnsClass::HS), 4);
    assert_eq!(u16::from(DnsClass::Other(99)), 99);

    assert_eq!(DnsClass::from(1), DnsClass::IN);
    assert_eq!(DnsClass::from(99), DnsClass::Other(99));
}

#[test]
fn test_dns_response_code_conversion() {
    assert_eq!(u8::from(DnsResponseCode::NoError), 0);
    assert_eq!(u8::from(DnsResponseCode::FormErr), 1);
    assert_eq!(u8::from(DnsResponseCode::ServFail), 2);
    assert_eq!(u8::from(DnsResponseCode::NxDomain), 3);
    assert_eq!(u8::from(DnsResponseCode::NotImp), 4);
    assert_eq!(u8::from(DnsResponseCode::Refused), 5);
    assert_eq!(u8::from(DnsResponseCode::Other(99)), 99);

    assert_eq!(DnsResponseCode::from(0), DnsResponseCode::NoError);
    assert_eq!(DnsResponseCode::from(99), DnsResponseCode::Other(99));
}

#[test]
fn test_parse_empty_packet() {
    let raw_packet: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let packet = DnsPacket::parse(&raw_packet).expect("Failed to parse");

    assert_eq!(packet.header.id, 1);
    assert_eq!(packet.questions.len(), 0);
    assert_eq!(packet.answers.len(), 0);
    assert_eq!(packet.authorities.len(), 0);
    assert_eq!(packet.additionals.len(), 0);
}

#[test]
fn test_packet_too_short() {
    let raw_packet: Vec<u8> = vec![0x00, 0x01, 0x00, 0x00];
    let result = DnsPacket::parse(&raw_packet);
    assert!(result.is_err());
}

#[test]
fn test_header_serialization() {
    let header = DnsHeader {
        id: 0x1234,
        qr: false,
        opcode: 0,
        aa: false,
        tc: false,
        rd: true,
        ra: false,
        z: 0,
        rcode: DnsResponseCode::NoError,
        qdcount: 1,
        ancount: 2,
        nscount: 3,
        arcount: 4,
    };

    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), 12);
    assert_eq!(bytes[0], 0x12);
    assert_eq!(bytes[1], 0x34);
    assert_eq!(bytes[2], 0x01);
    assert_eq!(bytes[4], 0x00);
    assert_eq!(bytes[5], 0x01);
    assert_eq!(bytes[6], 0x00);
    assert_eq!(bytes[7], 0x02);
    assert_eq!(bytes[8], 0x00);
    assert_eq!(bytes[9], 0x03);
    assert_eq!(bytes[10], 0x00);
    assert_eq!(bytes[11], 0x04);
}

#[test]
fn test_dns_query_aaaa_for_google_com() {
    let raw_dns_packet: Vec<u8> = vec![
        0xd3, 0x04, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x1c, 0x00, 0x01,
    ];

    let packet =
        DnsPacket::parse(&raw_dns_packet).expect("Failed to parse DNS packet");

    assert_eq!(packet.header.id, 0xd304);
    assert!(packet.header.is_query());
    assert!(!packet.header.qr);
    assert_eq!(packet.header.opcode, 0);
    assert!(!packet.header.aa);
    assert!(!packet.header.tc);
    assert!(packet.header.rd);
    assert!(!packet.header.ra);
    assert_eq!(packet.header.rcode, DnsResponseCode::NoError);
    assert_eq!(packet.header.qdcount, 1);
    assert_eq!(packet.header.ancount, 0);
    assert_eq!(packet.header.nscount, 0);
    assert_eq!(packet.header.arcount, 0);

    assert_eq!(packet.questions.len(), 1);
    let question = &packet.questions[0];
    assert_eq!(question.domain.to_string(), "google.com");
    assert_eq!(question.domain.labels.len(), 2);
    assert_eq!(question.domain.labels[0], b"google");
    assert_eq!(question.domain.labels[1], b"com");
    assert_eq!(question.kind, DnsType::AAAA);
    assert_eq!(question.class, DnsClass::IN);

    assert_eq!(packet.answers.len(), 0);
    assert_eq!(packet.authorities.len(), 0);
    assert_eq!(packet.additionals.len(), 0);

    let emitted = packet.to_bytes();
    assert_eq!(emitted, raw_dns_packet);
}

#[test]
fn test_z_field_parsing() {
    let raw_packet: Vec<u8> = vec![
        0xef, 0x8e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];

    let packet = DnsPacket::parse(&raw_packet).expect("Failed to parse");
    assert_eq!(packet.header.z, 0);
}

#[test]
fn test_z_field_serialization() {
    let header = DnsHeader {
        id: 0x1234,
        qr: false,
        opcode: 0,
        aa: false,
        tc: false,
        rd: true,
        ra: false,
        z: 0,
        rcode: DnsResponseCode::NoError,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), 12);
    assert_eq!(bytes[2], 0x01);
    assert_eq!(bytes[3], 0x00);
}

#[test]
fn test_empty_domain_name() {
    let raw_packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let packet = DnsPacket::parse(&raw_packet).expect("Failed to parse");
    assert_eq!(packet.questions.len(), 1);
    assert_eq!(packet.questions[0].domain.labels.len(), 0);
}

#[test]
fn test_multiple_labels_domain_name() {
    let raw_packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x61, 0x01, 0x62, 0x01, 0x63, 0x01, 0x64, 0x01, 0x65, 0x01, 0x66,
        0x01, 0x67, 0x01, 0x68, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let packet = DnsPacket::parse(&raw_packet).expect("Failed to parse");
    assert_eq!(packet.questions.len(), 1);
    let domain = &packet.questions[0].domain;
    assert_eq!(domain.labels.len(), 10);
    assert_eq!(domain.labels[0], b"a");
    assert_eq!(domain.labels[8], b"example");
    assert_eq!(domain.labels[9], b"com");
    assert_eq!(domain.to_string(), "a.b.c.d.e.f.g.h.example.com");
}

#[test]
fn test_label_too_long_error() {
    let mut raw_packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    raw_packet.push(0x42);
    raw_packet.extend_from_slice(&[0x41; 66]);
    raw_packet.push(0x00);
    raw_packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    let result = DnsPacket::parse(&raw_packet);
    assert!(result.is_err());
}

#[test]
fn test_domain_name_too_long_error() {
    let mut raw_packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    for i in 0..24 {
        raw_packet.push(10);
        raw_packet.extend_from_slice(&[0x41 + (i as u8); 10]);
    }
    raw_packet.push(0x00);
    raw_packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    let result = DnsPacket::parse(&raw_packet);
    assert!(result.is_err());
}

#[test]
fn test_reserved_compression_pointer_prefix_error() {
    let raw_packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x0C, 0x00, 0x01, 0x00, 0x01,
    ];

    let result = DnsPacket::parse(&raw_packet);
    assert!(result.is_err());
}

#[test]
fn test_compression_pointer_cycle_error() {
    let raw_packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
    ];

    let result = DnsPacket::parse(&raw_packet);
    assert!(result.is_err());
}

#[test]
fn test_compression_pointer_out_of_bounds_error() {
    let raw_packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0xFF, 0x00, 0x01, 0x00, 0x01,
    ];

    let result = DnsPacket::parse(&raw_packet);
    assert!(result.is_err());
}

#[test]
fn test_has_edns() {
    // Query with EDNS OPT record (type 41) in additionals
    let edns_packet: Vec<u8> = vec![
        0xef, 0x8e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];
    let packet =
        DnsPacket::parse(&edns_packet).expect("Failed to parse EDNS packet");
    assert!(packet.has_edns());

    // Query without EDNS OPT record
    let plain_packet: Vec<u8> = vec![
        0xd3, 0x04, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x1c, 0x00, 0x01,
    ];
    let packet =
        DnsPacket::parse(&plain_packet).expect("Failed to parse plain packet");
    assert!(!packet.has_edns());
}

/// Build an A response for example.com carrying a single OPT pseudo-record
/// whose DO bit is controlled by `do_bit`.
fn edns_response(do_bit: bool) -> DnsPacket {
    let domain = DnsDomainName::from_str("example.com").unwrap();
    let opt_ttl: u32 = if do_bit { 0x0000_8000 } else { 0 };
    DnsPacket {
        header: DnsHeader {
            id: 0x1234,
            qr: true,
            rcode: DnsResponseCode::NoError,
            qdcount: 1,
            ancount: 1,
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
fn test_to_bytes_without_opt_strips_opt() {
    let packet = edns_response(true);
    assert!(packet.has_edns());

    let mut positions = Vec::new();
    let bytes = packet.to_bytes_without_opt(Some(&mut positions));

    // The OPT record is gone: ARCOUNT drops from 1 to 0.
    let reparsed = DnsPacket::parse(&bytes).expect("reparse neutral bytes");
    assert_eq!(reparsed.header.arcount, 0);
    assert!(reparsed.additionals.is_empty());
    assert!(!reparsed.has_edns());
    // The A answer survives intact.
    assert_eq!(reparsed.answers.len(), 1);
    assert_eq!(reparsed.answers[0].ttl, 300);
    assert_eq!(reparsed.answers[0].rdata, vec![1, 2, 3, 4]);
    // Only the A record's TTL is tracked for decrement, not the OPT's.
    assert_eq!(positions.len(), 1);
    assert_eq!(positions[0].1, 300);
}

#[test]
fn test_append_opt_ack() {
    let mut bytes = edns_response(false).to_bytes_without_opt(None);
    // Sanity: the neutral response carries no OPT record.
    assert_eq!(DnsPacket::parse(&bytes).unwrap().header.arcount, 0);

    DnsPacket::append_opt_ack(&mut bytes, 4096, true);

    let reparsed = DnsPacket::parse(&bytes).expect("reparse with OPT ack");
    assert_eq!(reparsed.header.arcount, 1);
    assert!(reparsed.has_edns());
    assert!(reparsed.dnssec_ok());
    assert_eq!(reparsed.edns_udp_payload_size(), Some(4096));
    let opt = reparsed.opt_record().unwrap();
    assert_eq!(opt.kind, DnsType::Other(41));
    assert_eq!(opt.domain.labels.len(), 0); // root NAME
    assert!(opt.rdata.is_empty());
    // The A answer is untouched by the append.
    assert_eq!(reparsed.answers.len(), 1);
    assert_eq!(reparsed.answers[0].rdata, vec![1, 2, 3, 4]);
}

#[test]
fn test_dnssec_ok_and_udp_size_accessors() {
    let with_do = edns_response(true);
    assert!(with_do.dnssec_ok());
    assert_eq!(with_do.edns_udp_payload_size(), Some(1232));

    let without_do = edns_response(false);
    assert!(!without_do.dnssec_ok());
    assert_eq!(without_do.edns_udp_payload_size(), Some(1232));

    // No OPT record at all -> DO false and no payload size.
    let mut no_opt = edns_response(false);
    no_opt.additionals.clear();
    assert!(!no_opt.has_edns());
    assert!(!no_opt.dnssec_ok());
    assert_eq!(no_opt.edns_udp_payload_size(), None);
}

#[test]
fn test_add_opt_record() {
    let mut query =
        DnsPacket::new_query("example.com", DnsType::A).expect("build query");
    assert!(!query.has_edns());
    let arcount_before = query.header.arcount;

    query.add_opt_record(1232, true);

    assert!(query.has_edns());
    assert!(query.dnssec_ok());
    assert_eq!(query.edns_udp_payload_size(), Some(1232));
    assert_eq!(query.header.arcount, arcount_before + 1);

    // The OPT record survives a serialization round-trip.
    let reparsed =
        DnsPacket::parse(&query.to_bytes()).expect("reparse EDNS query");
    assert!(reparsed.has_edns());
    assert!(reparsed.dnssec_ok());
    assert_eq!(reparsed.edns_udp_payload_size(), Some(1232));
}
