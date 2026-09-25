//! Outbound-webhook egress guard (SSRF protection).
//!
//! Every outbound webhook path in the workspace — `epigraph-api`'s
//! registration gate and delivery dispatcher, and this crate's
//! [`crate::ConfigurableWebhookHandler`] — decides "may this address be dialled?"
//! here, and only here. Two classifiers are two definitions of "internal" that
//! can drift, and the one that drifts open is the one nobody notices.
//!
//! # The address table
//!
//! [`internal_category`] is the single table. An address is refused when it is
//! not globally reachable according to the IANA IPv4 and IPv6 Special-Purpose
//! Address Registries, plus the multicast blocks. Addresses that *carry* an IPv4
//! address inside IPv6 (IPv4-mapped `::ffff:a.b.c.d`, NAT64 `64:ff9b::a.b.c.d`,
//! 6to4 `2002:aabb:ccdd::`) are judged by the IPv4 address they carry, through
//! the SAME IPv4 table — an inline copy of the IPv4 list in the IPv6 arm is how
//! the previous table drifted.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Name the reason `addr` must not be dialled, or `None` if it is a globally
/// reachable unicast address.
///
/// The category is returned rather than a bare `bool` so a refusal can say
/// which rule the caller tripped. [`is_internal_addr`] is the boolean view.
#[must_use]
pub fn internal_category(addr: IpAddr) -> Option<&'static str> {
    match addr {
        IpAddr::V4(v4) => ipv4_category(v4),
        IpAddr::V6(v6) => ipv6_category(v6),
    }
}

/// Is `addr` internal, private, or otherwise not a legitimate webhook target?
///
/// `true` means refuse. See [`internal_category`] for the table.
#[must_use]
pub fn is_internal_addr(addr: IpAddr) -> bool {
    internal_category(addr).is_some()
}

/// Does `addr` lie inside `net/prefix`?
fn v4_in(addr: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(addr) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

/// Does `addr` lie inside `net/prefix`?
fn v6_in(addr: Ipv6Addr, net: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(addr) & mask) == (u128::from(net) & mask)
}

/// The IPv4 table, most specific first.
fn ipv4_category(v4: Ipv4Addr) -> Option<&'static str> {
    // (network, prefix, category). Order matters only where blocks nest:
    // the limited-broadcast address sits inside 240/4 and is named on its own.
    const TABLE: &[([u8; 4], u32, &str)] = &[
        ([255, 255, 255, 255], 32, "limited broadcast"),
        ([0, 0, 0, 0], 8, "this network / unspecified"),
        ([10, 0, 0, 0], 8, "private range"),
        ([100, 64, 0, 0], 10, "shared address space (CGNAT)"),
        ([127, 0, 0, 0], 8, "loopback"),
        // 169.254.0.0/16 is where cloud instance-metadata services live.
        ([169, 254, 0, 0], 16, "link-local"),
        ([172, 16, 0, 0], 12, "private range"),
        ([192, 0, 0, 0], 24, "IETF protocol assignments"),
        ([192, 0, 2, 0], 24, "documentation (TEST-NET-1)"),
        ([192, 88, 99, 0], 24, "6to4 relay anycast (deprecated)"),
        ([192, 168, 0, 0], 16, "private range"),
        ([198, 18, 0, 0], 15, "benchmarking"),
        ([198, 51, 100, 0], 24, "documentation (TEST-NET-2)"),
        ([203, 0, 113, 0], 24, "documentation (TEST-NET-3)"),
        ([224, 0, 0, 0], 4, "multicast"),
        ([240, 0, 0, 0], 4, "reserved"),
    ];
    TABLE
        .iter()
        .find(|(net, prefix, _)| v4_in(v4, *net, *prefix))
        .map(|(_, _, category)| *category)
}

/// The IPv6 table. Embedded-IPv4 forms defer to [`ipv4_category`].
fn ipv6_category(v6: Ipv6Addr) -> Option<&'static str> {
    let seg = v6.segments();
    let bits = u128::from(v6);

    if v6.is_unspecified() {
        return Some("unspecified");
    }
    if v6.is_loopback() {
        return Some("loopback");
    }

    // ::ffff:a.b.c.d — IPv4-mapped. The same destination as the IPv4 address,
    // written differently, so it is judged as that address.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return ipv4_category(v4);
    }

    // ::a.b.c.d — IPv4-compatible (::/96, deprecated by RFC 4291). Not mapped,
    // so `to_ipv4_mapped` returns None for it and it used to fall through as
    // public; `::127.0.0.1` is the loopback address in this spelling. Nothing
    // legitimate is addressed this way any more, so the whole block is refused.
    if v6_in(v6, Ipv6Addr::UNSPECIFIED, 96) {
        return Some("IPv4-compatible (deprecated)");
    }

    // ::ffff:0:a.b.c.d — IPv4-translated (RFC 2765). Refused outright.
    if v6_in(v6, Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, 0, 0), 96) {
        return Some("IPv4-translated");
    }

    // 64:ff9b::/96 — NAT64 well-known prefix. A DNS64 resolver synthesises
    // these for ordinary public IPv4-only names, so the block cannot be refused
    // wholesale without breaking delivery on IPv6-only hosts; the embedded IPv4
    // address is judged instead, which is what the translator will dial.
    if v6_in(v6, Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96) {
        #[allow(clippy::cast_possible_truncation)]
        let embedded = Ipv4Addr::from(bits as u32);
        return ipv4_category(embedded).map(|_| "NAT64 of an internal IPv4 address");
    }

    // 2002::/16 — 6to4. The 32 bits after the prefix are the IPv4 address the
    // relay tunnels to; judge that.
    if seg[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            (seg[1] & 0xff) as u8,
            (seg[2] >> 8) as u8,
            (seg[2] & 0xff) as u8,
        );
        return ipv4_category(embedded).map(|_| "6to4 of an internal IPv4 address");
    }

    const TABLE: &[(Ipv6Addr, u32, &str)] = &[
        // 64:ff9b:1::/48 — local-use NAT64 (RFC 8215): translates into a
        // network-local IPv4 space by definition.
        (
            Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0),
            48,
            "local-use NAT64",
        ),
        (
            Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0),
            64,
            "discard-only",
        ),
        // 2001:db8::/32 is inside 2001::/16 but not 2001::/23; checked first
        // only for the better name.
        (
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            32,
            "documentation",
        ),
        // 2001::/23 — IETF protocol assignments: Teredo (2001::/32, whose
        // embedded client address is obfuscated and cannot be judged), ORCHID,
        // benchmarking, AMT, AS112. None is a webhook receiver.
        (
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
            23,
            "IETF protocol assignments (incl. Teredo)",
        ),
        (
            Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0),
            20,
            "documentation",
        ),
        (Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16, "SRv6 SIDs"),
        (
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
            7,
            "unique-local",
        ),
        (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10, "link-local"),
        (
            Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0),
            10,
            "site-local (deprecated)",
        ),
        (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8, "multicast"),
    ];
    TABLE
        .iter()
        .find(|(net, prefix, _)| v6_in(v6, *net, *prefix))
        .map(|(_, _, category)| *category)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    /// Backlog b159a7fd: every range the previous table classified as public,
    /// each one a reachable-but-not-public destination, plus the ranges that
    /// were already refused (so a rewrite cannot lose one).
    #[test]
    fn refuses_every_non_global_range() {
        for s in [
            // Previously refused — must stay refused.
            "127.0.0.1",
            "127.255.255.254",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "0.1.2.3",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            // b159a7fd — previously ALLOWED.
            "100.64.0.1",             // CGNAT
            "100.127.255.254",        // CGNAT, top of the /10
            "224.0.0.1",              // multicast
            "239.255.255.250",        // multicast (SSDP)
            "255.255.255.255",        // limited broadcast
            "240.0.0.1",              // reserved
            "192.0.0.1",              // IETF protocol assignments
            "192.0.0.170",            // NAT64 discovery
            "192.0.2.1",              // TEST-NET-1
            "198.51.100.1",           // TEST-NET-2
            "203.0.113.1",            // TEST-NET-3
            "198.18.0.1",             // benchmarking
            "198.19.255.255",         // benchmarking, top of the /15
            "192.88.99.1",            // 6to4 relay anycast
            "::127.0.0.1",            // IPv4-compatible loopback (::7f00:1)
            "::7f00:1",               // same address, hex spelling
            "::8.8.8.8",              // IPv4-compatible is refused wholesale
            "::ffff:0:127.0.0.1",     // IPv4-translated
            "::ffff:100.64.0.1",      // IPv4-mapped CGNAT
            "::ffff:255.255.255.255", // IPv4-mapped broadcast
            "fec0::1",                // deprecated site-local
            "feff::1",                // site-local, top of the /10
            "ff02::1",                // multicast
            "ff05::1:3",              // multicast
            "2002:7f00:1::",          // 6to4 of 127.0.0.1
            "2002:a9fe:a9fe::1",      // 6to4 of 169.254.169.254
            "64:ff9b::7f00:1",        // NAT64 of 127.0.0.1
            "64:ff9b::a9fe:a9fe",     // NAT64 of 169.254.169.254
            "64:ff9b::a00:1",         // NAT64 of 10.0.0.1
            "64:ff9b:1::1",           // local-use NAT64
            "100::1",                 // discard-only
            "2001::1",                // Teredo
            "2001:db8::1",            // documentation
            "2001:10::1",             // ORCHID
            "3fff::1",                // documentation (RFC 9637)
            "5f00::1",                // SRv6 SIDs
        ] {
            assert!(
                is_internal_addr(ip(s)),
                "{s} must be refused (category {:?})",
                internal_category(ip(s))
            );
        }
    }

    /// The control: a table that refuses everything passes the test above.
    /// Public unicast — including the public forms of every embedded-IPv4
    /// encoding that is judged by its payload rather than refused wholesale —
    /// must stay dialable.
    #[test]
    fn allows_global_unicast() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "100.63.255.255",  // just below CGNAT
            "100.128.0.0",     // just above CGNAT
            "172.15.255.255",  // just below 172.16/12
            "172.32.0.0",      // just above 172.16/12
            "192.0.1.1",       // just above 192.0.0/24
            "198.17.255.255",  // just below benchmarking
            "198.20.0.0",      // just above benchmarking
            "223.255.255.255", // just below multicast
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "2001:200::1",      // just above 2001::/23
            "::ffff:8.8.8.8",   // IPv4-mapped public
            "64:ff9b::808:808", // NAT64 of 8.8.8.8 (DNS64)
            "2002:808:808::1",  // 6to4 of 8.8.8.8
        ] {
            assert!(
                !is_internal_addr(ip(s)),
                "{s} is globally reachable and must be allowed (category {:?})",
                internal_category(ip(s))
            );
        }
    }
}
