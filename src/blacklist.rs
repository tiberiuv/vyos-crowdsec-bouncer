use arc_swap::ArcSwap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct Blacklist {
    pub ip_ranges: IpRangeMixed,
}

impl Blacklist {
    pub fn new(ip_ranges: IpRangeMixed) -> Self {
        Self { ip_ranges }
    }
    pub fn exclude(&self, other: &IpRangeMixed) -> Self {
        Self {
            ip_ranges: self.ip_ranges.exclude(other),
        }
    }
    pub fn merge(&self, other: &IpRangeMixed) -> Self {
        Self {
            ip_ranges: self.ip_ranges.merge(other),
        }
    }
    pub fn interset(&self, other: &IpRangeMixed) -> Self {
        Self {
            ip_ranges: self.ip_ranges.intersect(other),
        }
    }
}

#[derive(Debug, Default)]
pub struct BlacklistCache(pub ArcSwap<Blacklist>);

impl BlacklistCache {
    pub fn store(&self, blacklist: Blacklist) {
        self.0.store(Arc::new(blacklist));
    }
    pub fn load(&self) -> Arc<Blacklist> {
        self.0.load_full()
    }
}

#[derive(Debug, Clone, Default)]
pub struct IpRangeMixed {
    pub v4: IpRange<Ipv4Net>,
    pub v6: IpRange<Ipv6Net>,
}
impl From<Vec<IpNet>> for IpRangeMixed {
    fn from(value: Vec<IpNet>) -> Self {
        let (allow_list_v4, allow_list_v6) = split_nets(value);
        let mut allow_list_v4 = merge_nets(allow_list_v4);
        allow_list_v4.simplify();
        let mut allow_list_v6 = merge_nets(allow_list_v6);
        allow_list_v6.simplify();

        Self {
            v4: allow_list_v4,
            v6: allow_list_v6,
        }
    }
}
impl IpRangeMixed {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn into_ips(&self) -> Vec<IpAddr> {
        self.v4
            .iter()
            .flat_map(|net| net.hosts())
            .map(IpAddr::V4)
            .chain(self.v6.iter().flat_map(|net| net.hosts()).map(IpAddr::V6))
            .collect()
    }

    pub fn into_nets(&self) -> Vec<IpNet> {
        self.v4
            .iter()
            .map(IpNet::V4)
            .chain(self.v6.iter().map(IpNet::V6))
            .collect()
    }

    pub fn exclude(&self, other: &IpRangeMixed) -> Self {
        Self {
            v4: self.v4.exclude(&other.v4),
            v6: self.v6.exclude(&other.v6),
        }
    }

    pub fn merge(&self, other: &IpRangeMixed) -> Self {
        Self {
            v4: self.v4.merge(&other.v4),
            v6: self.v6.merge(&other.v6),
        }
    }
    pub fn intersect(&self, other: &IpRangeMixed) -> Self {
        Self {
            v4: self.v4.intersect(&other.v4),
            v6: self.v6.intersect(&other.v6),
        }
    }
}

fn split_nets(nets: Vec<IpNet>) -> (Vec<Ipv4Net>, Vec<Ipv6Net>) {
    let mut nets_ipv4 = Vec::new();
    let mut nets_ipv6 = Vec::new();

    for net in nets {
        match net {
            IpNet::V4(ipv4) => nets_ipv4.push(ipv4),
            IpNet::V6(ipv6) => nets_ipv6.push(ipv6),
        }
    }

    (nets_ipv4, nets_ipv6)
}

fn merge_nets<T: iprange::IpNet>(ipnets: Vec<T>) -> IpRange<T> {
    let mut ips_range = iprange::IpRange::new();
    for ipnet in ipnets {
        ips_range.add(ipnet);
    }
    ips_range
}
