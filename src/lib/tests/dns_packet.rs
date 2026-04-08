// SPDX-License-Identifier: Apache-2.0

use mudz::{
    DnsDomainName, DnsHeader, DnsMessage, DnsMessageType, DnsQueryType,
    DnsRecordClass, DnsResponseCode, ErrorKind,
};

#[test]
fn test_dns_message_new_query() {
    // Test creating a simple A record query
    let message = DnsMessage::new_query(0x1234, "example.com", DnsQueryType::A)
        .expect("Failed to create query");

    // Verify header
    assert_eq!(message.header.id, 0x1234);
    assert_eq!(message.header.message_type, DnsMessageType::Query);
    assert!(!message.header.qr);
    assert!(message.header.rd);
    assert_eq!(message.header.qdcount, 1);
    assert_eq!(message.header.ancount, 0);
    assert_eq!(message.header.nscount, 0);
    assert_eq!(message.header.arcount, 0);

    // Verify question
    assert_eq!(message.questions.len(), 1);
    let question = &message.questions[0];
    assert_eq!(question.domain.to_string(), "example.com");
    assert_eq!(question.domain.labels.len(), 2);
    assert_eq!(question.domain.labels[0], b"example");
    assert_eq!(question.domain.labels[1], b"com");
    assert_eq!(question.query_type, DnsQueryType::A);
    assert_eq!(question.query_class, DnsRecordClass::IN);

    // Verify empty sections
    assert_eq!(message.answers.len(), 0);
    assert_eq!(message.authorities.len(), 0);
    assert_eq!(message.additionals.len(), 0);
}

#[test]
fn test_dns_message_new_query_round_trip() {
    // Create a query and serialize it
    let message =
        DnsMessage::new_query(0xabcd, "google.com", DnsQueryType::AAAA)
            .expect("Failed to create query");

    let bytes = message.to_bytes().expect("Failed to serialize");

    // Parse it back
    let reparsed = DnsMessage::from_bytes(&bytes).expect("Failed to parse");

    assert_eq!(reparsed.header.id, message.header.id);
    assert_eq!(reparsed.questions.len(), message.questions.len());
    assert_eq!(
        reparsed.questions[0].domain.to_string(),
        message.questions[0].domain.to_string()
    );
    assert_eq!(
        reparsed.questions[0].query_type,
        message.questions[0].query_type
    );
}

#[test]
fn test_dns_message_new_query_invalid_domain() {
    // Test empty domain
    let result = DnsMessage::new_query(0x1234, "", DnsQueryType::A);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind, ErrorKind::InvalidDomainName);

    // Test single label too long (>63 chars)
    let long_label = "a".repeat(64);
    let result = DnsMessage::new_query(0x1234, &long_label, DnsQueryType::A);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind, ErrorKind::LabelTooLong);
}

#[test]
fn test_dns_query_packet_parse_emit_round_trip() {
    // Raw DNS query packet for google.com with OPT record
    let raw_packet: Vec<u8> = vec![
        0xef, 0x8e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];

    // Test 1: Parse the raw packet
    let message = DnsMessage::from_bytes(&raw_packet)
        .expect("Failed to parse DNS packet");

    // Verify header
    assert_eq!(message.header.id, 0xef8e);
    assert_eq!(message.header.message_type, DnsMessageType::Query);
    assert!(!message.header.qr);
    assert_eq!(message.header.opcode, 0);
    assert!(!message.header.aa);
    assert!(!message.header.tc);
    assert!(message.header.rd);
    assert!(!message.header.ra);
    assert_eq!(message.header.rcode, DnsResponseCode::NoError);
    assert_eq!(message.header.qdcount, 1);
    assert_eq!(message.header.ancount, 0);
    assert_eq!(message.header.nscount, 0);
    assert_eq!(message.header.arcount, 1);

    // Verify questions
    assert_eq!(message.questions.len(), 1);
    let question = &message.questions[0];
    assert_eq!(question.domain.to_string(), "google.com");
    assert_eq!(question.domain.labels.len(), 2);
    assert_eq!(question.domain.labels[0], b"google");
    assert_eq!(question.domain.labels[1], b"com");
    assert_eq!(question.query_type, DnsQueryType::A);
    assert_eq!(question.query_class, DnsRecordClass::IN);

    // Verify no answers
    assert_eq!(message.answers.len(), 0);
    assert_eq!(message.authorities.len(), 0);

    // Verify additional records (OPT record)
    assert_eq!(message.additionals.len(), 1);
    let opt_record = &message.additionals[0];
    assert_eq!(opt_record.domain.labels.len(), 0); // Root domain for OPT
    assert_eq!(opt_record.record_type, DnsQueryType::OTHER(41)); // OPT type
    assert_eq!(opt_record.record_class, DnsRecordClass::OTHER(1232)); // UDP payload size
    assert_eq!(opt_record.rdlength, 0);
    assert_eq!(opt_record.rdata.len(), 0);

    // Test 2: Emit the DNS message to bytes
    let emitted = message.to_bytes().expect("Failed to emit DNS packet");

    // Test 3: Verify round-trip produces identical bytes
    assert_eq!(emitted, raw_packet);
}

#[test]
fn test_dns_response_packet_parse_emit_round_trip() {
    // Raw DNS response packet for google.com with A record answer
    let raw_packet: Vec<u8> = vec![
        0x2d, 0xc3, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x35, 0x00, 0x04, 0x8e, 0xfb, 0x23, 0x4e,
    ];

    // Test 1: Parse the raw packet
    let message = DnsMessage::from_bytes(&raw_packet)
        .expect("Failed to parse DNS packet");

    // Verify header
    assert_eq!(message.header.id, 0x2dc3);
    assert_eq!(message.header.message_type, DnsMessageType::Response);
    assert!(message.header.qr);
    assert_eq!(message.header.opcode, 0);
    assert!(!message.header.aa);
    assert!(!message.header.tc);
    assert!(message.header.rd);
    assert!(message.header.ra);
    assert_eq!(message.header.rcode, DnsResponseCode::NoError);
    assert_eq!(message.header.qdcount, 1);
    assert_eq!(message.header.ancount, 1);
    assert_eq!(message.header.nscount, 0);
    assert_eq!(message.header.arcount, 0);

    // Verify questions
    assert_eq!(message.questions.len(), 1);
    let question = &message.questions[0];
    assert_eq!(question.domain.to_string(), "google.com");
    assert_eq!(question.domain.labels.len(), 2);
    assert_eq!(question.domain.labels[0], b"google");
    assert_eq!(question.domain.labels[1], b"com");
    assert_eq!(question.query_type, DnsQueryType::A);
    assert_eq!(question.query_class, DnsRecordClass::IN);

    // Verify answer records
    assert_eq!(message.answers.len(), 1);
    let answer = &message.answers[0];
    // Domain uses compression pointer (0xc0 0x0c points to offset 12)
    // The parser follows the pointer and gets "google.com"
    assert_eq!(answer.domain.to_string(), "google.com");
    assert_eq!(answer.record_type, DnsQueryType::A);
    assert_eq!(answer.record_class, DnsRecordClass::IN);
    assert_eq!(answer.rdlength, 4);
    assert_eq!(answer.rdata.len(), 4);
    // Verify the A record IP address (142.251.35.78)
    assert_eq!(answer.rdata, vec![0x8e, 0xfb, 0x23, 0x4e]);

    // Verify no authority or additional records
    assert_eq!(message.authorities.len(), 0);
    assert_eq!(message.additionals.len(), 0);

    // Test 2: Emit the DNS message to bytes
    let emitted = message.to_bytes().expect("Failed to emit DNS packet");

    // Verify the emitted packet is valid (may differ due to compression pointer
    // expansion)
    let reparsed = DnsMessage::from_bytes(&emitted)
        .expect("Failed to re-parse emitted packet");
    assert_eq!(reparsed.header.id, message.header.id);
    assert_eq!(reparsed.questions.len(), message.questions.len());
    assert_eq!(reparsed.answers.len(), message.answers.len());
}

#[test]
fn test_parse_dns_header_flags() {
    // Test parsing query flags (0x0100)
    let raw_packet: Vec<u8> = vec![
        0xef, 0x8e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];

    let message = DnsMessage::from_bytes(&raw_packet).expect("Failed to parse");

    assert_eq!(message.header.message_type, DnsMessageType::Query);
    assert!(!message.header.qr);
    assert!(message.header.rd);
    assert!(!message.header.ra);
    assert!(!message.header.aa);
    assert!(!message.header.tc);
}

#[test]
fn test_parse_domain_name() {
    let raw_packet: Vec<u8> = vec![
        0xef, 0x8e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];

    let message = DnsMessage::from_bytes(&raw_packet).expect("Failed to parse");

    let question = &message.questions[0];
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
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
        0x03, 0x63, 0x6f, 0x6d, // "com"
        0x00, // null terminator
    ];

    assert_eq!(buf, expected);
}

#[test]
fn test_dns_query_type_conversion() {
    assert_eq!(u16::from(DnsQueryType::A), 1);
    assert_eq!(u16::from(DnsQueryType::AAAA), 28);
    assert_eq!(u16::from(DnsQueryType::CNAME), 5);
    assert_eq!(u16::from(DnsQueryType::MX), 15);
    assert_eq!(u16::from(DnsQueryType::NS), 2);
    assert_eq!(u16::from(DnsQueryType::SOA), 6);
    assert_eq!(u16::from(DnsQueryType::TXT), 16);
    assert_eq!(u16::from(DnsQueryType::PTR), 12);
    assert_eq!(u16::from(DnsQueryType::SRV), 33);
    assert_eq!(u16::from(DnsQueryType::OTHER(99)), 99);

    assert_eq!(DnsQueryType::try_from(1).unwrap(), DnsQueryType::A);
    assert_eq!(DnsQueryType::try_from(28).unwrap(), DnsQueryType::AAAA);
    assert_eq!(DnsQueryType::try_from(99).unwrap(), DnsQueryType::OTHER(99));
}

#[test]
fn test_dns_record_class_conversion() {
    assert_eq!(u16::from(DnsRecordClass::IN), 1);
    assert_eq!(u16::from(DnsRecordClass::CS), 2);
    assert_eq!(u16::from(DnsRecordClass::CH), 3);
    assert_eq!(u16::from(DnsRecordClass::HS), 4);
    assert_eq!(u16::from(DnsRecordClass::OTHER(99)), 99);

    assert_eq!(DnsRecordClass::try_from(1).unwrap(), DnsRecordClass::IN);
    assert_eq!(
        DnsRecordClass::try_from(99).unwrap(),
        DnsRecordClass::OTHER(99)
    );
}

#[test]
fn test_dns_response_code_conversion() {
    assert_eq!(u16::from(DnsResponseCode::NoError), 0);
    assert_eq!(u16::from(DnsResponseCode::FormErr), 1);
    assert_eq!(u16::from(DnsResponseCode::ServFail), 2);
    assert_eq!(u16::from(DnsResponseCode::NXDomain), 3);
    assert_eq!(u16::from(DnsResponseCode::NotImp), 4);
    assert_eq!(u16::from(DnsResponseCode::Refused), 5);
    assert_eq!(u16::from(DnsResponseCode::OTHER(99)), 99);

    assert_eq!(
        DnsResponseCode::try_from(0).unwrap(),
        DnsResponseCode::NoError
    );
    assert_eq!(
        DnsResponseCode::try_from(99).unwrap(),
        DnsResponseCode::OTHER(99)
    );
}

#[test]
fn test_parse_empty_packet() {
    // Packet with no questions or answers
    let raw_packet: Vec<u8> = vec![
        0x00, 0x01, // ID
        0x00, 0x00, // Flags (standard query)
        0x00, 0x00, // QDCOUNT: 0
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    ];

    let message = DnsMessage::from_bytes(&raw_packet).expect("Failed to parse");

    assert_eq!(message.header.id, 1);
    assert_eq!(message.questions.len(), 0);
    assert_eq!(message.answers.len(), 0);
    assert_eq!(message.authorities.len(), 0);
    assert_eq!(message.additionals.len(), 0);
}

#[test]
fn test_packet_too_short_for_header() {
    let raw_packet: Vec<u8> = vec![0x00, 0x01, 0x00, 0x00];

    // DnsHeader::from_bytes properly checks length and returns an error
    let result = DnsMessage::from_bytes(&raw_packet);
    assert!(result.is_err(), "Expected an error for buffer too short");
}

#[test]
fn test_header_serialization() {
    let header = DnsHeader {
        id: 0x1234,
        message_type: DnsMessageType::Query,
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
    assert_eq!(bytes[2], 0x01); // QR=0, RD=1
    assert_eq!(bytes[4], 0x00);
    assert_eq!(bytes[5], 0x01); // QDCOUNT: 1
    assert_eq!(bytes[6], 0x00);
    assert_eq!(bytes[7], 0x02); // ANCOUNT: 2
    assert_eq!(bytes[8], 0x00);
    assert_eq!(bytes[9], 0x03); // NSCOUNT: 3
    assert_eq!(bytes[10], 0x00);
    assert_eq!(bytes[11], 0x04); // ARCOUNT: 4
}

#[test]
fn test_dns_query_aaaa_for_google_com() {
    let raw_dns_packet: Vec<u8> = vec![
        0xd3, 0x04, // Transaction ID: 0xd304
        0x01, 0x00, // Flags: standard query (0x0100) - RD=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
        0x03, 0x63, 0x6f, 0x6d, // "com"
        0x00, // null terminator
        0x00, 0x1c, // QTYPE: AAAA (28)
        0x00, 0x01, // QCLASS: IN (1)
    ];

    // Test 1: Parse the raw packet
    let message = DnsMessage::from_bytes(&raw_dns_packet)
        .expect("Failed to parse DNS packet");

    // Test 2: Verify header fields
    assert_eq!(message.header.id, 0xd304);
    assert_eq!(message.header.message_type, DnsMessageType::Query);
    assert!(!message.header.qr);
    assert_eq!(message.header.opcode, 0);
    assert!(!message.header.aa);
    assert!(!message.header.tc);
    assert!(message.header.rd);
    assert!(!message.header.ra);
    assert_eq!(message.header.rcode, DnsResponseCode::NoError);
    assert_eq!(message.header.qdcount, 1);
    assert_eq!(message.header.ancount, 0);
    assert_eq!(message.header.nscount, 0);
    assert_eq!(message.header.arcount, 0);

    // Test 3: Verify question section
    assert_eq!(message.questions.len(), 1);
    let question = &message.questions[0];
    assert_eq!(question.domain.to_string(), "google.com");
    assert_eq!(question.domain.labels.len(), 2);
    assert_eq!(question.domain.labels[0], b"google");
    assert_eq!(question.domain.labels[1], b"com");
    assert_eq!(question.query_type, DnsQueryType::AAAA);
    assert_eq!(question.query_class, DnsRecordClass::IN);

    // Test 4: Verify empty sections
    assert_eq!(message.answers.len(), 0);
    assert_eq!(message.authorities.len(), 0);
    assert_eq!(message.additionals.len(), 0);

    // Test 5: Emit the DNS message to bytes
    let emitted = message.to_bytes().expect("Failed to emit DNS packet");

    // Test 6: Verify round-trip produces identical bytes
    assert_eq!(emitted, raw_dns_packet);
}

#[test]
fn test_dns_response_aaaa_with_compression_pointer() {
    // Raw DNS response packet for google.com AAAA query with IP
    // 2607:f8b0:4007:0808::200e
    let raw_packet: Vec<u8> = vec![
        0xd3, 0x04, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x05, 0x00, 0x10, 0x26, 0x07, 0xf8, 0xb0, 0x40, 0x07, 0x08, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e,
    ];

    // Test 1: Parse the raw packet
    let message = DnsMessage::from_bytes(&raw_packet)
        .expect("Failed to parse DNS packet");

    // Verify header
    assert_eq!(message.header.id, 0xd304);
    assert_eq!(message.header.message_type, DnsMessageType::Response);
    assert!(message.header.qr);
    assert_eq!(message.header.opcode, 0);
    assert!(!message.header.aa);
    assert!(!message.header.tc);
    assert!(message.header.rd);
    assert!(message.header.ra);
    assert_eq!(message.header.rcode, DnsResponseCode::NoError);
    assert_eq!(message.header.qdcount, 1);
    assert_eq!(message.header.ancount, 1);
    assert_eq!(message.header.nscount, 0);
    assert_eq!(message.header.arcount, 0);

    // Verify questions
    assert_eq!(message.questions.len(), 1);
    let question = &message.questions[0];
    assert_eq!(question.domain.to_string(), "google.com");
    assert_eq!(question.domain.labels.len(), 2);
    assert_eq!(question.domain.labels[0], b"google");
    assert_eq!(question.domain.labels[1], b"com");
    assert_eq!(question.query_type, DnsQueryType::AAAA);
    assert_eq!(question.query_class, DnsRecordClass::IN);

    // Verify answer records
    assert_eq!(message.answers.len(), 1);
    let answer = &message.answers[0];
    // Domain uses compression pointer (0xc0 0x0c points to offset 12)
    // The parser follows the pointer and gets "google.com"
    assert_eq!(answer.domain.to_string(), "google.com");
    assert_eq!(answer.record_type, DnsQueryType::AAAA);
    assert_eq!(answer.record_class, DnsRecordClass::IN);
    assert_eq!(answer.ttl, 0x0105); // 261 seconds
    assert_eq!(answer.rdlength, 16);
    assert_eq!(answer.rdata.len(), 16);
    // Verify the AAAA record IPv6 address (2607:f8b0:4007:808::200e)
    assert_eq!(
        answer.rdata,
        vec![
            0x26, 0x07, 0xf8, 0xb0, 0x40, 0x07, 0x08, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x20, 0x0e,
        ]
    );

    // Verify no authority or additional records
    assert_eq!(message.authorities.len(), 0);
    assert_eq!(message.additionals.len(), 0);

    // Test 2: Emit the DNS message to bytes
    let emitted = message.to_bytes().expect("Failed to emit DNS packet");

    assert_eq!(emitted, raw_packet);
}

#[test]
fn test_label_too_long_error() {
    // Create a DNS packet with a label that exceeds 63 bytes
    // We use length 128 (0x80) which would be invalid as it has high bits set
    // To properly test label length validation, we'd need a value > 63 with
    // high-order 2 bits as 00, but all such values are either compression
    // pointers (11) or reserved (01, 10). So we test with 64 (0x40) which
    // gets caught as reserved.
    let mut raw_packet = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    ];

    // Add a label with length byte 0x42 (01000010) - reserved prefix
    // This tests that we catch invalid label length prefixes
    raw_packet.push(0x42); // Invalid: has reserved prefix (01xxxxxx)
    raw_packet.extend_from_slice(&[0x41; 66]); // Some data
    raw_packet.push(0x00); // Null terminator
    raw_packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE + QCLASS

    let result = DnsMessage::from_bytes(&raw_packet);
    assert!(result.is_err());
    // Gets caught by reserved prefix check before length validation
    assert_eq!(
        result.unwrap_err().kind,
        ErrorKind::InvalidCompressionPointer
    );
}

#[test]
fn test_domain_name_too_long_error() {
    // Create a domain name that exceeds 255 bytes total
    let mut raw_packet = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    ];

    // Add many labels to exceed 255 byte limit
    // Each label is 10 bytes + 1 length byte = 11 bytes
    // We need about 24 labels to exceed 255 bytes
    for i in 0..24 {
        raw_packet.push(10); // Label length
        raw_packet.extend_from_slice(&[0x41 + (i as u8); 10]); // 10 bytes
    }
    raw_packet.push(0x00); // Null terminator
    raw_packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE + QCLASS

    let result = DnsMessage::from_bytes(&raw_packet);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind, ErrorKind::DomainNameTooLong);
}

#[test]
fn test_reserved_compression_pointer_prefix_error() {
    // Create a domain name with reserved compression pointer prefix (01xxxxxx
    // or 10xxxxxx) Testing 0x80 (10xxxxxx)
    let raw_packet = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        0x80, 0x0C, // Reserved compression pointer (10xxxxxx)
        0x00, 0x01, 0x00, 0x01, // QTYPE + QCLASS
    ];

    let result = DnsMessage::from_bytes(&raw_packet);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().kind,
        ErrorKind::InvalidCompressionPointer
    );
}

#[test]
fn test_compression_pointer_cycle_error() {
    // Create a compression pointer cycle: pointer at offset 12 points to offset
    // 12
    let raw_packet = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        0xC0, 0x0C, // Compression pointer to offset 12 (self-reference)
        0x00, 0x01, 0x00, 0x01, // QTYPE + QCLASS
    ];

    let result = DnsMessage::from_bytes(&raw_packet);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind, ErrorKind::CompressionPointerCycle);
}

#[test]
fn test_compression_pointer_out_of_bounds_error() {
    // Create a compression pointer that points beyond the buffer
    let raw_packet = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        0xC0, 0xFF, // Compression pointer to offset 255 (out of bounds)
        0x00, 0x01, 0x00, 0x01, // QTYPE + QCLASS
    ];

    let result = DnsMessage::from_bytes(&raw_packet);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().kind,
        ErrorKind::InvalidCompressionPointer
    );
}

#[test]
fn test_z_field_parsing() {
    // Test that Z field is correctly parsed (should be 0)
    let raw_packet: Vec<u8> = vec![
        0xef, 0x8e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];

    let message = DnsMessage::from_bytes(&raw_packet).expect("Failed to parse");
    assert_eq!(message.header.z, 0);
}

#[test]
fn test_z_field_serialization() {
    // Test that Z field is correctly serialized
    let header = DnsHeader {
        id: 0x1234,
        message_type: DnsMessageType::Query,
        qr: false,
        opcode: 0,
        aa: false,
        tc: false,
        rd: true,
        ra: false,
        z: 0, // Must be zero per RFC 1035
        rcode: DnsResponseCode::NoError,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), 12);
    // Flags byte should be 0x01 (RD=1), Z bits should be 0
    assert_eq!(bytes[2], 0x01);
    assert_eq!(bytes[3], 0x00);
}

#[test]
fn test_empty_domain_name() {
    // Test parsing root domain (empty domain name, just null terminator)
    let raw_packet = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        0x00, // Root domain (null label)
        0x00, 0x01, 0x00, 0x01, // QTYPE + QCLASS
    ];

    let message = DnsMessage::from_bytes(&raw_packet).expect("Failed to parse");
    assert_eq!(message.questions.len(), 1);
    assert_eq!(message.questions[0].domain.labels.len(), 0);
}

#[test]
fn test_multiple_labels_domain_name() {
    // Test parsing domain with many labels: a.b.c.d.e.f.g.h.example.com
    let raw_packet = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        0x01, 0x61, // "a"
        0x01, 0x62, // "b"
        0x01, 0x63, // "c"
        0x01, 0x64, // "d"
        0x01, 0x65, // "e"
        0x01, 0x66, // "f"
        0x01, 0x67, // "g"
        0x01, 0x68, // "h"
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
        0x03, 0x63, 0x6f, 0x6d, // "com"
        0x00, // Null terminator
        0x00, 0x01, 0x00, 0x01, // QTYPE + QCLASS
    ];

    let message = DnsMessage::from_bytes(&raw_packet).expect("Failed to parse");
    assert_eq!(message.questions.len(), 1);
    let domain = &message.questions[0].domain;
    assert_eq!(domain.labels.len(), 10);
    assert_eq!(domain.labels[0], b"a");
    assert_eq!(domain.labels[8], b"example");
    assert_eq!(domain.labels[9], b"com");
    assert_eq!(domain.to_string(), "a.b.c.d.e.f.g.h.example.com");
}
