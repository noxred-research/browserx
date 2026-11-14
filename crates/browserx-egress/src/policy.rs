//! Destination policy: which addresses the forwarder may dial.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use browserx_core::{Error, Result};
use serde::{Deserialize, Serialize};

/// Upper bound on allow-list entries; keeps per-connection checks cheap.
const MAX_ALLOW_CIDRS: usize = 1024;

/// What the forwarder may reach.
///
/// With `block_private` (the default) destinations in private, loopback,
/// link-local, carrier-grade NAT, multicast, reserved and cloud-metadata ranges
/// are refused, for both IPv4 and IPv6 (including IPv4-mapped, NAT64 and 6to4
/// forms). Addresses inside `allow_cidrs` are exempt.
///
/// How strictly the check applies depends on who resolves the name:
///
/// * direct egress and `socks5://` upstreams resolve locally, so every
///   resolved address is checked and only checked addresses are dialed;
/// * `http://`, `https://` and `socks5h://` upstreams resolve remotely, so only
///   IP literals and `localhost` names can be checked here. Enforcing the
///   policy on remote resolution is the upstream operator's responsibility.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EgressPolicy {
    /// Refuse private and otherwise non-public destinations.
    pub block_private: bool,
    /// CIDR blocks (`10.1.0.0/16`, `fd00::/8`) or single addresses exempt from blocking.
    pub allow_cidrs: Vec<String>,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            block_private: true,
            allow_cidrs: Vec::new(),
        }
    }
}

impl EgressPolicy {
    /// Checks that every `allow_cidrs` entry parses.
    pub fn validate(&self) -> Result<()> {
        self.compile().map(|_| ())
    }

    pub(crate) fn compile(&self) -> Result<CompiledPolicy> {
        if self.allow_cidrs.len() > MAX_ALLOW_CIDRS {
            return Err(Error::InvalidRequest(format!(
                "at most {MAX_ALLOW_CIDRS} allow_cidrs entries are supported"
            )));
        }
        let allow = self
            .allow_cidrs
            .iter()
            .map(|s| Cidr::parse(s))
            .collect::<Result<Vec<_>>>()?;
        Ok(CompiledPolicy {
            block_private: self.block_private,
            allow,
        })
    }
}

/// A parsed, normalized network prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let bad = || Error::InvalidRequest(format!("invalid CIDR in allow_cidrs: {text:?}"));
        let (addr_text, prefix_text) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let addr = IpAddr::from_str(addr_text.trim()).map_err(|_| bad())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            Some(p) => p.trim().parse::<u8>().map_err(|_| bad())?,
            None => max,
        };
        if prefix > max {
            return Err(bad());
        }
        // An IPv4-mapped IPv6 block is the same set as its IPv4 form.
        if let IpAddr::V6(v6) = addr
            && let Some(v4) = v6.to_ipv4_mapped()
            && prefix >= 96
        {
            return Ok(Self::masked(IpAddr::V4(v4), prefix - 96));
        }
        Ok(Self::masked(addr, prefix))
    }

    fn masked(addr: IpAddr, prefix: u8) -> Self {
        let addr = match addr {
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask32(prefix))),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask128(prefix))),
        };
        Self { addr, prefix }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                u32::from(ip) & mask32(self.prefix) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                u128::from(ip) & mask128(self.prefix) == u128::from(net)
            }
            _ => false,
        }
    }
}

fn mask32(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask128(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

/// Outcome of a policy check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allowed,
    Refused(&'static str),
}

/// The policy in its checkable form.
#[derive(Clone, Debug)]
pub(crate) struct CompiledPolicy {
    block_private: bool,
    allow: Vec<Cidr>,
}

impl CompiledPolicy {
    pub(crate) fn check_ip(&self, ip: IpAddr) -> Verdict {
        if !self.block_private {
            return Verdict::Allowed;
        }
        let forms = address_forms(ip);
        if forms
            .iter()
            .any(|f| self.allow.iter().any(|c| c.contains(*f)))
        {
            return Verdict::Allowed;
        }
        for f in &forms {
            if let Some(reason) = blocked_reason(*f) {
                return Verdict::Refused(reason);
            }
        }
        Verdict::Allowed
    }
}

/// The address itself plus any IPv4 address embedded in a transition form, so
/// `::ffff:10.0.0.1`, `64:ff9b::a00:1` and `2002:a00:1::` are judged as `10.0.0.1`.
fn address_forms(ip: IpAddr) -> Vec<IpAddr> {
    match ip {
        IpAddr::V4(_) => vec![ip],
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return vec![IpAddr::V4(v4)];
            }
            let o = v6.octets();
            let mut forms = vec![ip];
            // NAT64 well-known prefix 64:ff9b::/96
            if o[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
                forms.push(IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15])));
            }
            // 6to4 2002::/16
            if o[0] == 0x20 && o[1] == 0x02 {
                forms.push(IpAddr::V4(Ipv4Addr::new(o[2], o[3], o[4], o[5])));
            }
            forms
        }
    }
}

fn blocked_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(a) => blocked_v4(a),
        IpAddr::V6(a) => blocked_v6(a),
    }
}

fn blocked_v4(a: Ipv4Addr) -> Option<&'static str> {
    let o = a.octets();
    let reason = match o {
        [169, 254, 169, 254] | [168, 63, 129, 16] => "cloud metadata address",
        [127, ..] => "loopback address",
        [10, ..] | [192, 168, ..] => "private network address",
        [172, b, ..] if (16..=31).contains(&b) => "private network address",
        [169, 254, ..] => "link-local address",
        [100, b, ..] if (64..=127).contains(&b) => "carrier-grade NAT address",
        [0, ..] => "unspecified address",
        [224..=239, ..] => "multicast address",
        [240..=255, ..] => "reserved address",
        [192, 0, 0, _] | [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => {
            "reserved documentation address"
        }
        [198, b, ..] if b == 18 || b == 19 => "benchmarking address",
        _ => return None,
    };
    Some(reason)
}

fn blocked_v6(a: Ipv6Addr) -> Option<&'static str> {
    let s = a.segments();
    if a.is_loopback() {
        return Some("loopback address");
    }
    if a.is_unspecified() {
        return Some("unspecified address");
    }
    // fd00:ec2::254 and the rest of the unique-local range
    if s[0] & 0xfe00 == 0xfc00 {
        return Some("private network address");
    }
    if s[0] & 0xffc0 == 0xfe80 {
        return Some("link-local address");
    }
    if s[0] & 0xffc0 == 0xfec0 {
        return Some("site-local address");
    }
    if s[0] & 0xff00 == 0xff00 {
        return Some("multicast address");
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return Some("reserved documentation address");
    }
    // ::/8 holds the unspecified, loopback and deprecated IPv4-compatible forms,
    // except the NAT64 prefix 64:ff9b::/96 (judged by its embedded IPv4 address);
    // 100::/64 is the discard prefix.
    let nat64 = s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0];
    if (s[0] & 0xff00 == 0 && !nat64) || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) {
        return Some("reserved address");
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn policy(block: bool, allow: &[&str]) -> CompiledPolicy {
        EgressPolicy {
            block_private: block,
            allow_cidrs: allow.iter().map(|s| (*s).into()).collect(),
        }
        .compile()
        .unwrap()
    }

    fn refused(p: &CompiledPolicy, ip: &str) -> bool {
        matches!(p.check_ip(ip.parse().unwrap()), Verdict::Refused(_))
    }

    #[test]
    fn blocks_non_public_ranges() {
        let p = policy(true, &[]);
        for ip in [
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.0.5",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "168.63.129.16",
            "::1",
            "::",
            "fe80::1",
            "fd00:ec2::254",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "2002:a00:1::1",
            "::10.0.0.1",
        ] {
            assert!(refused(&p, ip), "{ip} should be refused");
        }
    }

    #[test]
    fn allows_public_addresses() {
        let p = policy(true, &[]);
        for ip in [
            "8.8.8.8",
            "93.184.216.34",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(!refused(&p, ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn allow_list_exempts_and_normalizes() {
        let p = policy(
            true,
            &["10.1.0.0/16", "192.168.5.5", "fd00::/8", "127.0.0.1/32"],
        );
        assert!(!refused(&p, "10.1.2.3"));
        assert!(refused(&p, "10.2.0.1"));
        assert!(!refused(&p, "192.168.5.5"));
        assert!(refused(&p, "192.168.5.6"));
        assert!(!refused(&p, "fd12::1"));
        assert!(!refused(&p, "::ffff:10.1.2.3"));
        assert!(!refused(&p, "127.0.0.1"));
        assert!(refused(&p, "127.0.0.2"));
        // the metadata address stays blocked unless named explicitly
        assert!(refused(&p, "169.254.169.254"));
        assert!(!refused(
            &policy(true, &["169.254.169.254/32"]),
            "169.254.169.254"
        ));
    }

    #[test]
    fn block_private_false_allows_everything() {
        let p = policy(false, &[]);
        assert!(!refused(&p, "127.0.0.1"));
        assert!(!refused(&p, "169.254.169.254"));
    }

    #[test]
    fn rejects_bad_cidrs() {
        for bad in [
            "",
            "10.0.0.0/33",
            "nope",
            "10.0.0.0/-1",
            "::/129",
            "10.0.0.0/8/8",
        ] {
            let policy = EgressPolicy {
                block_private: true,
                allow_cidrs: vec![bad.into()],
            };
            assert!(policy.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn host_bits_are_masked() {
        let cidr = Cidr::parse("10.1.2.3/8").unwrap();
        assert_eq!(cidr, Cidr::parse("10.0.0.0/8").unwrap());
        assert!(cidr.contains("10.200.0.1".parse().unwrap()));
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains("1.2.3.4".parse().unwrap())
        );
    }

    #[test]
    fn policy_deserializes_with_defaults() {
        let p: EgressPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p, EgressPolicy::default());
        assert!(serde_json::from_str::<EgressPolicy>(r#"{"nope":1}"#).is_err());
    }
}
