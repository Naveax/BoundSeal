use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationClass {
    Public,
    Unspecified,
    Loopback,
    Private,
    SharedAddressSpace,
    LinkLocal,
    Documentation,
    Benchmarking,
    ProtocolAssignment,
    Multicast,
    Reserved,
    Broadcast,
    UniqueLocal,
    SiteLocal,
    Orchid,
    DiscardOnly,
    Ipv4MappedNonPublic,
}

impl DestinationClass {
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Public)
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::SharedAddressSpace => "shared_address_space",
            Self::LinkLocal => "link_local",
            Self::Documentation => "documentation",
            Self::Benchmarking => "benchmarking",
            Self::ProtocolAssignment => "protocol_assignment",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved",
            Self::Broadcast => "broadcast",
            Self::UniqueLocal => "unique_local",
            Self::SiteLocal => "site_local",
            Self::Orchid => "orchid",
            Self::DiscardOnly => "discard_only",
            Self::Ipv4MappedNonPublic => "ipv4_mapped_non_public",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct DestinationAssessment {
    pub ip: IpAddr,
    pub class: DestinationClass,
}

impl DestinationAssessment {
    pub fn is_allowed(self) -> bool {
        self.class.is_allowed()
    }
}

pub fn assess_destination(ip: IpAddr) -> DestinationAssessment {
    let class = match ip {
        IpAddr::V4(ip) => classify_ipv4(ip),
        IpAddr::V6(ip) => classify_ipv6(ip),
    };

    DestinationAssessment { ip, class }
}

pub fn is_public_destination(ip: IpAddr) -> bool {
    assess_destination(ip).is_allowed()
}

fn classify_ipv4(ip: Ipv4Addr) -> DestinationClass {
    if in_ipv4_prefix(ip, Ipv4Addr::new(0, 0, 0, 0), 8) {
        return DestinationClass::Unspecified;
    }
    if ip.is_loopback() {
        return DestinationClass::Loopback;
    }
    if ip.is_private() {
        return DestinationClass::Private;
    }
    if in_ipv4_prefix(ip, Ipv4Addr::new(100, 64, 0, 0), 10) {
        return DestinationClass::SharedAddressSpace;
    }
    if ip.is_link_local() {
        return DestinationClass::LinkLocal;
    }
    if in_ipv4_prefix(ip, Ipv4Addr::new(192, 0, 0, 0), 24)
        || in_ipv4_prefix(ip, Ipv4Addr::new(192, 88, 99, 0), 24)
    {
        return DestinationClass::ProtocolAssignment;
    }
    if in_ipv4_prefix(ip, Ipv4Addr::new(192, 0, 2, 0), 24)
        || in_ipv4_prefix(ip, Ipv4Addr::new(198, 51, 100, 0), 24)
        || in_ipv4_prefix(ip, Ipv4Addr::new(203, 0, 113, 0), 24)
    {
        return DestinationClass::Documentation;
    }
    if in_ipv4_prefix(ip, Ipv4Addr::new(198, 18, 0, 0), 15) {
        return DestinationClass::Benchmarking;
    }
    if ip.is_multicast() {
        return DestinationClass::Multicast;
    }
    if ip == Ipv4Addr::BROADCAST {
        return DestinationClass::Broadcast;
    }
    if in_ipv4_prefix(ip, Ipv4Addr::new(240, 0, 0, 0), 4) {
        return DestinationClass::Reserved;
    }

    DestinationClass::Public
}

fn classify_ipv6(ip: Ipv6Addr) -> DestinationClass {
    if ip.is_unspecified() {
        return DestinationClass::Unspecified;
    }
    if ip.is_loopback() {
        return DestinationClass::Loopback;
    }
    if let Some(mapped) = ip.to_ipv4_mapped() {
        let embedded = classify_ipv4(mapped);
        return if embedded.is_allowed() {
            DestinationClass::Public
        } else {
            DestinationClass::Ipv4MappedNonPublic
        };
    }

    let segments = ip.segments();
    let first = segments[0];

    if first & 0xfe00 == 0xfc00 {
        return DestinationClass::UniqueLocal;
    }
    if first & 0xffc0 == 0xfe80 {
        return DestinationClass::LinkLocal;
    }
    if first & 0xffc0 == 0xfec0 {
        return DestinationClass::SiteLocal;
    }
    if first & 0xff00 == 0xff00 {
        return DestinationClass::Multicast;
    }
    if in_ipv6_prefix(ip, Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64) {
        return DestinationClass::DiscardOnly;
    }
    if in_ipv6_prefix(ip, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32) {
        return DestinationClass::Documentation;
    }
    if in_ipv6_prefix(ip, Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0), 48) {
        return DestinationClass::Benchmarking;
    }
    if in_ipv6_prefix(ip, Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 0), 28)
        || in_ipv6_prefix(ip, Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28)
    {
        return DestinationClass::Orchid;
    }
    if in_ipv6_prefix(ip, Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96)
        || in_ipv6_prefix(ip, Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0, 0), 48)
        || in_ipv6_prefix(ip, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23)
        || in_ipv6_prefix(ip, Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16)
    {
        return DestinationClass::ProtocolAssignment;
    }
    if in_ipv6_prefix(ip, Ipv6Addr::new(0x3ffe, 0, 0, 0, 0, 0, 0, 0), 16) {
        return DestinationClass::Reserved;
    }

    DestinationClass::Public
}

fn in_ipv4_prefix(ip: Ipv4Addr, network: Ipv4Addr, prefix_length: u32) -> bool {
    let mask = if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_length)
    };
    u32::from(ip) & mask == u32::from(network) & mask
}

fn in_ipv6_prefix(ip: Ipv6Addr, network: Ipv6Addr, prefix_length: u32) -> bool {
    let mask = if prefix_length == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_length)
    };
    u128::from(ip) & mask == u128::from(network) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ipv4_special_ranges() {
        let cases = [
            ("0.12.0.1", DestinationClass::Unspecified),
            ("10.1.2.3", DestinationClass::Private),
            ("100.64.0.1", DestinationClass::SharedAddressSpace),
            ("127.0.0.1", DestinationClass::Loopback),
            ("169.254.1.1", DestinationClass::LinkLocal),
            ("192.0.0.9", DestinationClass::ProtocolAssignment),
            ("192.0.2.10", DestinationClass::Documentation),
            ("198.18.0.1", DestinationClass::Benchmarking),
            ("224.0.0.1", DestinationClass::Multicast),
            ("240.0.0.1", DestinationClass::Reserved),
            ("255.255.255.255", DestinationClass::Broadcast),
            ("8.8.8.8", DestinationClass::Public),
        ];

        for (value, expected) in cases {
            let assessment = assess_destination(value.parse().unwrap());
            assert_eq!(assessment.class, expected, "{value}");
        }
    }

    #[test]
    fn classifies_ipv6_special_ranges() {
        let cases = [
            ("::", DestinationClass::Unspecified),
            ("::1", DestinationClass::Loopback),
            ("fc00::1", DestinationClass::UniqueLocal),
            ("fe80::1", DestinationClass::LinkLocal),
            ("fec0::1", DestinationClass::SiteLocal),
            ("ff02::1", DestinationClass::Multicast),
            ("100::1", DestinationClass::DiscardOnly),
            ("2001:db8::1", DestinationClass::Documentation),
            ("2001:2::1", DestinationClass::Benchmarking),
            ("2001:20::1", DestinationClass::Orchid),
            ("2002::1", DestinationClass::ProtocolAssignment),
            ("3ffe::1", DestinationClass::Reserved),
            ("2606:4700:4700::1111", DestinationClass::Public),
        ];

        for (value, expected) in cases {
            let assessment = assess_destination(value.parse().unwrap());
            assert_eq!(assessment.class, expected, "{value}");
        }
    }

    #[test]
    fn rejects_non_public_ipv4_mapped_ipv6() {
        let private = assess_destination("::ffff:127.0.0.1".parse().unwrap());
        assert_eq!(private.class, DestinationClass::Ipv4MappedNonPublic);

        let public = assess_destination("::ffff:8.8.8.8".parse().unwrap());
        assert_eq!(public.class, DestinationClass::Public);
    }
}
