// SPDX-License-Identifier: Apache-2.0

use mudz::MudzConfig;

#[test]
fn test_doh_options_defaults() {
    let config_str = r#"
[fallback]
nameservers = ["https://dns.alidns.com/dns-query"]

[doh]
nameservers = ["223.5.5.5"]
"#;
    let config: MudzConfig =
        toml::from_str(config_str).expect("parse DoH config");
    config.validate().expect("defaults must validate");

    let doh = config.doh.expect("[doh] section");
    assert_eq!(doh.timeout, 5);
    assert_eq!(doh.retries, 1);
    assert_eq!(doh.keepalive_interval, 20);
    assert_eq!(doh.keepalive_timeout, 5);
    assert_eq!(doh.idle_timeout, 60);
}

#[test]
fn test_doh_options_custom_values() {
    let config_str = r#"
[fallback]
nameservers = ["https://dns.alidns.com/dns-query"]

[doh]
nameservers = ["223.5.5.5"]
timeout = 3
retries = 2
keepalive_interval = 10
keepalive_timeout = 3
idle_timeout = 30
"#;
    let config: MudzConfig =
        toml::from_str(config_str).expect("parse DoH config");
    config.validate().expect("custom values must validate");

    let doh = config.doh.expect("[doh] section");
    assert_eq!(doh.timeout, 3);
    assert_eq!(doh.retries, 2);
    assert_eq!(doh.keepalive_interval, 10);
    assert_eq!(doh.keepalive_timeout, 3);
    assert_eq!(doh.idle_timeout, 30);
}

#[test]
fn test_invalid_doh_options_rejected() {
    let cases = [
        ("timeout", "timeout = 0"),
        ("timeout", "timeout = 6"),
        ("retries", "retries = 6"),
        ("keepalive", "keepalive_interval = 5\nkeepalive_timeout = 5"),
        ("idle", "idle_timeout = 0"),
    ];

    for (name, extra) in cases {
        let config_str = format!(
            r#"
[fallback]
nameservers = ["https://dns.alidns.com/dns-query"]

[doh]
nameservers = ["223.5.5.5"]
{extra}
"#
        );
        let config: MudzConfig =
            toml::from_str(&config_str).expect("parse DoH config");
        assert!(
            config.validate().is_err(),
            "invalid DoH option '{name}' must be rejected"
        );
    }
}

#[test]
fn test_unknown_field_in_group_rejected() {
    let config_str = r#"
[main]
udp_bind = "127.0.0.1:53"

[fallback]
nameservers = ["8.8.8.8"]

[group.test]
nameservers = ["1.1.1.1"]
domains = ["example.com"]
unknown_field = "bad"
"#;
    let result = toml::from_str::<MudzConfig>(config_str);
    assert!(
        result.is_err(),
        "Expected error for unknown field in [group.*] section"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("unknown field `unknown_field`"),
        "Error should mention unknown_field, got: {err}"
    );
}

#[test]
fn test_valid_group_accepted() {
    let config_str = r#"
[main]
udp_bind = "127.0.0.1:53"

[fallback]
nameservers = ["8.8.8.8"]

[group.google]
nameservers = ["8.8.4.4"]
domains = ["google.com"]
disable_ipv6 = true
"#;
    let result = toml::from_str::<MudzConfig>(config_str);
    assert!(result.is_ok(), "Expected valid config, got: {result:?}");
    let config = result.unwrap();
    assert_eq!(config.groups.len(), 1);
    assert!(config.groups.contains_key("google"));
    let google_group = &config.groups["google"];
    assert_eq!(google_group.nameservers, vec!["8.8.4.4"]);
    assert_eq!(google_group.domains, vec!["google.com"]);
    assert!(google_group.disable_ipv6);
}

#[test]
fn test_doh_fallback_without_doh_section_rejected() {
    let config_str = r#"
[main]
udp_bind = "127.0.0.1:53"

[fallback]
nameservers = ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"]
"#;
    let config: MudzConfig =
        toml::from_str(config_str).expect("Should parse TOML successfully");
    let result = config.validate();
    assert!(
        result.is_err(),
        "Expected error when DoH fallback without [doh] section"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("no [doh] section found"),
        "Error should mention missing [doh] section, got: {err}"
    );
}

#[test]
fn test_doh_fallback_with_doh_section_accepted() {
    let config_str = r#"
[main]
udp_bind = "127.0.0.1:53"

[fallback]
nameservers = ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"]

[doh]
nameservers = ["223.5.5.5", "119.29.29.29"]
"#;
    let config: MudzConfig =
        toml::from_str(config_str).expect("Should parse TOML successfully");
    let result = config.validate();
    assert!(
        result.is_ok(),
        "Expected valid config with [doh] section for DoH hostnames, got: \
         {result:?}"
    );
}

#[test]
fn test_doh_in_group_with_doh_section_accepted() {
    let config_str = r#"
[main]
udp_bind = "127.0.0.1:53"

[fallback]
nameservers = ["8.8.8.8"]

[doh]
nameservers = ["223.5.5.5"]

[group.doh]
nameservers = ["https://dns.google/dns-query"]
domains = ["google.com"]
"#;
    let config: MudzConfig =
        toml::from_str(config_str).expect("Should parse TOML successfully");
    let result = config.validate();
    assert!(
        result.is_ok(),
        "Expected valid config when DoH is in a group with [doh] section, \
         got: {result:?}"
    );
}

#[test]
fn test_doh_nameservers_rejected_if_not_ip() {
    let config_str = r#"
[main]
udp_bind = "127.0.0.1:53"

[fallback]
nameservers = ["https://dns.alidns.com/dns-query"]

[doh]
nameservers = ["https://dns.google/dns-query"]
"#;
    let result = toml::from_str::<MudzConfig>(config_str);
    assert!(
        result.is_err(),
        "Expected error when [doh] nameserver is not a valid IP address"
    );
}

#[test]
fn test_mixed_fallback_with_doh_accepted() {
    let config_str = r#"
[main]
udp_bind = "127.0.0.1:53"

[fallback]
nameservers = ["https://dns.alidns.com/dns-query", "8.8.8.8"]

[doh]
nameservers = ["223.5.5.5"]
"#;
    let result = toml::from_str::<MudzConfig>(config_str);
    assert!(
        result.is_ok(),
        "Expected valid config with mixed fallback (DoH + plain IP), got: \
         {result:?}"
    );
}

#[test]
fn test_plain_fallback_needs_no_doh_section() {
    let config_str = r#"
[main]
udp_bind = "127.0.0.1:53"

[fallback]
nameservers = ["8.8.8.8"]
"#;
    let config: MudzConfig =
        toml::from_str(config_str).expect("Should parse TOML successfully");
    let result = config.validate();
    assert!(
        result.is_ok(),
        "Expected valid config with plain IP fallback and no [doh] section, \
         got: {result:?}"
    );
}
