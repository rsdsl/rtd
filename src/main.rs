use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use rsdsl_netlinklib::blocking::Connection;
use rsdsl_netlinklib::rule::RuleAction;

const ROUTES_PATH: &str = "/data/static.rt";
const RULES_PATH: &str = "/data/policies.rl";

#[derive(Debug)]
enum RouteParseError {
    DstNotIpv4,
    DstNotIpv6,
    DuplicateAttr(String),
    InvalidAttr(String),
    InvalidCidr(String),
    InvalidCmd(String),
    InvalidVersion(String),
    NoAttrValue(String),
    NoCmd,
    NoDst,
    NoLink,
    NoVersion,
    ParseAddr(std::net::AddrParseError),
    ParseBool(std::str::ParseBoolError),
    ParseInt(std::num::ParseIntError),
    RtrNotIpv4,
    RtrNotIpv6,
}

impl fmt::Display for RouteParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DstNotIpv4 => write!(f, "route4 with missing or non-IPv4 destination")?,
            Self::DstNotIpv6 => write!(f, "route6 with missing or non-IPv6 destination")?,
            Self::DuplicateAttr(a) => write!(f, "duplicate attribute {}", a)?,
            Self::InvalidAttr(a) => write!(f, "invalid attribute {}", a)?,
            Self::InvalidCidr(c) => write!(f, "invalid CIDR {} (want exactly 1 /)", c)?,
            Self::InvalidCmd(c) => write!(f, "invalid command {} (want \"add\" or \"del\")", c)?,
            Self::InvalidVersion(v) => {
                write!(f, "invalid version: {} (want \"route4\" or \"route6\")", v)?
            }
            Self::NoAttrValue(a) => write!(f, "missing value for attribute {}", a)?,
            Self::NoCmd => write!(f, "missing command (want \"add\" or \"del\")")?,
            Self::NoDst => write!(f, "missing destination network (\"to\" attribute)")?,
            Self::NoLink => write!(f, "missing network interface (\"dev\" attribute)")?,
            Self::NoVersion => write!(f, "missing version (want \"route4\" or \"route6\")")?,
            Self::ParseAddr(e) => write!(f, "parse network address: {}", e)?,
            Self::ParseBool(e) => write!(f, "parse bool: {}", e)?,
            Self::ParseInt(e) => write!(f, "parse integer: {}", e)?,
            Self::RtrNotIpv4 => write!(f, "route4 with non-IPv4 gateway")?,
            Self::RtrNotIpv6 => write!(f, "route6 with non-IPv6 gateway")?,
        }

        Ok(())
    }
}

impl From<std::net::AddrParseError> for RouteParseError {
    fn from(e: std::net::AddrParseError) -> RouteParseError {
        RouteParseError::ParseAddr(e)
    }
}

impl From<std::str::ParseBoolError> for RouteParseError {
    fn from(e: std::str::ParseBoolError) -> RouteParseError {
        RouteParseError::ParseBool(e)
    }
}

impl From<std::num::ParseIntError> for RouteParseError {
    fn from(e: std::num::ParseIntError) -> RouteParseError {
        RouteParseError::ParseInt(e)
    }
}

impl std::error::Error for RouteParseError {}

#[derive(Debug)]
enum RuleParseError {
    DstIllegal,
    DstNotIpv4,
    DstNotIpv6,
    DuplicateAttr(String),
    InvalidAction(String),
    InvalidAttr(String),
    InvalidCidr(String),
    InvalidCmd(String),
    InvalidVersion(String),
    NoAction,
    NoAttrValue(String),
    NoCmd,
    NoVersion,
    ParseAddr(std::net::AddrParseError),
    ParseBool(std::str::ParseBoolError),
    ParseInt(std::num::ParseIntError),
    SrcIllegal,
    SrcNotIpv4,
    SrcNotIpv6,
}

impl fmt::Display for RuleParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DstIllegal => write!(f, "protocol-agnostic rule with destination prefix")?,
            Self::DstNotIpv4 => write!(f, "rule4 with non-IPv4 destination")?,
            Self::DstNotIpv6 => write!(f, "rule6 with non-IPv6 destination")?,
            Self::DuplicateAttr(a) => write!(f, "duplicate attribute {}", a)?,
            Self::InvalidAction(a) => write!(f, "invalid action {}", a)?,
            Self::InvalidAttr(a) => write!(f, "invalid attribute {}", a)?,
            Self::InvalidCidr(c) => write!(f, "invalid CIDR {} (want exactly 1 /)", c)?,
            Self::InvalidCmd(c) => write!(f, "invalid command {} (want \"add\" or \"del\")", c)?,
            Self::InvalidVersion(v) => write!(
                f,
                "invalid version: {} (want \"rule\", \"rule4\" or \"rule6\")",
                v
            )?,
            Self::NoAction => write!(f, "missing action (\"action\" attribute)")?,
            Self::NoAttrValue(a) => write!(f, "missing value for attribute {}", a)?,
            Self::NoCmd => write!(f, "missing command (want \"add\" or \"del\")")?,
            Self::NoVersion => {
                write!(f, "missing version (want \"rule\", \"rule4\" or \"rule6\")")?
            }
            Self::ParseAddr(e) => write!(f, "parse network address: {}", e)?,
            Self::ParseBool(e) => write!(f, "parse bool: {}", e)?,
            Self::ParseInt(e) => write!(f, "parse integer: {}", e)?,
            Self::SrcIllegal => write!(f, "protocol-agnostic rule with source prefix")?,
            Self::SrcNotIpv4 => write!(f, "rule4 with non-IPv4 source")?,
            Self::SrcNotIpv6 => write!(f, "rule6 with non-IPv6 source")?,
        }

        Ok(())
    }
}

impl From<std::net::AddrParseError> for RuleParseError {
    fn from(e: std::net::AddrParseError) -> RuleParseError {
        RuleParseError::ParseAddr(e)
    }
}

impl From<std::str::ParseBoolError> for RuleParseError {
    fn from(e: std::str::ParseBoolError) -> RuleParseError {
        RuleParseError::ParseBool(e)
    }
}

impl From<std::num::ParseIntError> for RuleParseError {
    fn from(e: std::num::ParseIntError) -> RuleParseError {
        RuleParseError::ParseInt(e)
    }
}

impl std::error::Error for RuleParseError {}

#[derive(Debug)]
enum SetupError {
    Netlinklib(rsdsl_netlinklib::Error),
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Netlinklib(e) => write!(f, "rsdsl_netlinklib: {}", e)?,
        }

        Ok(())
    }
}

impl From<rsdsl_netlinklib::Error> for SetupError {
    fn from(e: rsdsl_netlinklib::Error) -> SetupError {
        SetupError::Netlinklib(e)
    }
}

impl std::error::Error for SetupError {}

#[derive(Debug)]
enum Error {
    ParseRoutes(RouteParseError),
    ParseRules(RuleParseError),
    ReadRoutes(std::io::Error),
    ReadRules(std::io::Error),
    Setup(SetupError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseRoutes(e) => write!(f, "parse routes: {}", e)?,
            Self::ParseRules(e) => write!(f, "parse rules: {}", e)?,
            Self::ReadRoutes(e) => write!(f, "read routes ({}): {}", ROUTES_PATH, e)?,
            Self::ReadRules(e) => write!(f, "read rules ({}): {}", RULES_PATH, e)?,
            Self::Setup(e) => write!(f, "set up route/rule: {}", e)?,
        }

        Ok(())
    }
}

impl From<RouteParseError> for Error {
    fn from(e: RouteParseError) -> Error {
        Error::ParseRoutes(e)
    }
}

impl From<RuleParseError> for Error {
    fn from(e: RuleParseError) -> Error {
        Error::ParseRules(e)
    }
}

impl From<SetupError> for Error {
    fn from(e: SetupError) -> Error {
        Error::Setup(e)
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
enum RouteVersion {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug)]
enum RouteDef {
    V4(rsdsl_netlinklib::route::Route4),
    V6(rsdsl_netlinklib::route::Route6),
}

impl RouteDef {
    fn add(self, c: &Connection) -> Result<(), SetupError> {
        match self {
            Self::V4(r) => c.route_add4(r)?,
            Self::V6(r) => c.route_add6(r)?,
        }

        Ok(())
    }

    fn delete(self, c: &Connection) -> Result<(), SetupError> {
        match self {
            Self::V4(r) => c.route_del4(r)?,
            Self::V6(r) => c.route_del6(r)?,
        }

        Ok(())
    }

    fn link(&self) -> &str {
        match self {
            Self::V4(r) => &r.link,
            Self::V6(r) => &r.link,
        }
    }
}

impl fmt::Display for RouteDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(r) => {
                write!(f, "route4 {}/{}", r.dst, r.prefix_len)?;
                if let Some(rtr) = r.rtr {
                    write!(f, " via {}", rtr)?;
                }
                if r.on_link {
                    write!(f, " onlink")?;
                }
                if let Some(table) = r.table {
                    write!(f, " table {}", table)?;
                }
                if let Some(metric) = r.metric {
                    write!(f, " metric {}", metric)?;
                }
                write!(f, " dev {}", r.link)?;
            }
            Self::V6(r) => {
                write!(f, "route6 {}/{}", r.dst, r.prefix_len)?;
                if let Some(rtr) = r.rtr {
                    write!(f, " via {}", rtr)?;
                }
                if r.on_link {
                    write!(f, " onlink")?;
                }
                if let Some(table) = r.table {
                    write!(f, " table {}", table)?;
                }
                if let Some(metric) = r.metric {
                    write!(f, " metric {}", metric)?;
                }
                write!(f, " dev {}", r.link)?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
struct Route {
    delete: bool,
    def: RouteDef,
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.def.fmt(f)
    }
}

impl FromStr for Route {
    type Err = RouteParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut words = s.split_whitespace();

        let version_str = words.next().ok_or(RouteParseError::NoVersion)?;
        let version = match version_str {
            "route4" => RouteVersion::Ipv4,
            "route6" => RouteVersion::Ipv6,
            _ => return Err(RouteParseError::InvalidVersion(version_str.to_string())),
        };

        let cmd = words.next().ok_or(RouteParseError::NoCmd)?;
        let delete = match cmd {
            "add" => false,
            "del" => true,
            _ => return Err(RouteParseError::InvalidCmd(cmd.to_string())),
        };

        let mut attrs = HashMap::<&str, &str>::new();
        let mut current_attr = None;
        for word in words {
            if let Some(attr) = current_attr {
                if attrs.insert(attr, word).is_some() {
                    return Err(RouteParseError::DuplicateAttr(attr.to_string()));
                }
                current_attr = None;
            } else {
                current_attr = Some(word);
            }
        }

        if let Some(attr) = current_attr {
            return Err(RouteParseError::NoAttrValue(attr.to_string()));
        }

        let mut dst = None;
        let mut prefix_len = None;
        let mut rtr = None;
        let mut on_link = false;
        let mut table = None;
        let mut metric = None;
        let mut link = None;

        for (attr, value) in attrs {
            match attr {
                "to" => {
                    let mut prefix = value.split('/');

                    let addr = prefix
                        .next()
                        .ok_or(RouteParseError::InvalidCidr(value.to_string()))?;
                    let cidr = prefix
                        .next()
                        .ok_or(RouteParseError::InvalidCidr(value.to_string()))?;

                    if prefix.next().is_some() {
                        return Err(RouteParseError::InvalidCidr(value.to_string()));
                    }

                    dst = Some(addr.parse()?);
                    prefix_len = Some(cidr.parse()?);
                }
                "via" => rtr = Some(value.parse()?),
                "onlink" => on_link = value.parse()?,
                "table" => table = Some(value.parse()?),
                "metric" => metric = Some(value.parse()?),
                "dev" => link = Some(value.to_string()),
                _ => return Err(RouteParseError::InvalidAttr(attr.to_string())),
            }
        }

        match version {
            RouteVersion::Ipv4 => Ok(Route {
                delete,
                def: RouteDef::V4(rsdsl_netlinklib::route::Route4 {
                    dst: if let Some(IpAddr::V4(dst)) = dst {
                        dst
                    } else {
                        return Err(RouteParseError::DstNotIpv4);
                    },
                    prefix_len: prefix_len.ok_or(RouteParseError::NoDst)?,
                    rtr: match rtr {
                        Some(IpAddr::V4(rtr)) => Some(rtr),
                        Some(_) => return Err(RouteParseError::RtrNotIpv4),
                        None => None,
                    },
                    on_link,
                    table,
                    metric,
                    link: link.ok_or(RouteParseError::NoLink)?,
                }),
            }),
            RouteVersion::Ipv6 => Ok(Route {
                delete,
                def: RouteDef::V6(rsdsl_netlinklib::route::Route6 {
                    dst: if let Some(IpAddr::V6(dst)) = dst {
                        dst
                    } else {
                        return Err(RouteParseError::DstNotIpv6);
                    },
                    prefix_len: prefix_len.ok_or(RouteParseError::NoDst)?,
                    rtr: match rtr {
                        Some(IpAddr::V6(rtr)) => Some(rtr),
                        Some(_) => return Err(RouteParseError::RtrNotIpv6),
                        None => None,
                    },
                    on_link,
                    table,
                    metric,
                    link: link.ok_or(RouteParseError::NoLink)?,
                }),
            }),
        }
    }
}

#[derive(Debug)]
struct Routes {
    routes: Vec<Route>,
}

impl FromStr for Routes {
    type Err = RouteParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let routes = s
            .lines()
            .map(|l| l.parse::<Route>())
            .collect::<Result<Vec<Route>, Self::Err>>()?;

        Ok(Self { routes })
    }
}

#[derive(Clone, Debug, Default)]
enum RuleVersion {
    #[default]
    Both,
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug)]
struct Rule {
    delete: bool,
    version: RuleVersion,
    invert: bool,
    fwmark: Option<u32>,
    dst: Option<(IpAddr, u8)>,
    src: Option<(IpAddr, u8)>,
    action: RuleAction,
    table: u32,
}

impl Rule {
    fn add(self, c: &Connection) -> Result<(), SetupError> {
        match self.version {
            RuleVersion::Both => {
                rsdsl_netlinklib::rule::Rule::<Ipv4Addr> {
                    invert: self.invert,
                    fwmark: self.fwmark,
                    dst: None,
                    src: None,
                    action: self.action,
                    table: self.table,
                }
                .blocking_add(c)?;
                rsdsl_netlinklib::rule::Rule::<Ipv6Addr> {
                    invert: self.invert,
                    fwmark: self.fwmark,
                    dst: None,
                    src: None,
                    action: self.action,
                    table: self.table,
                }
                .blocking_add(c)?;
            }
            RuleVersion::Ipv4 => rsdsl_netlinklib::rule::Rule::<Ipv4Addr> {
                invert: self.invert,
                fwmark: self.fwmark,
                dst: self.dst.map(|dst| {
                    if let (IpAddr::V4(addr), cidr) = dst {
                        (addr, cidr)
                    } else {
                        unreachable!()
                    }
                }),
                src: self.src.map(|src| {
                    if let (IpAddr::V4(addr), cidr) = src {
                        (addr, cidr)
                    } else {
                        unreachable!()
                    }
                }),
                action: self.action,
                table: self.table,
            }
            .blocking_add(c)?,
            RuleVersion::Ipv6 => rsdsl_netlinklib::rule::Rule::<Ipv6Addr> {
                invert: self.invert,
                fwmark: self.fwmark,
                dst: self.dst.map(|dst| {
                    if let (IpAddr::V6(addr), cidr) = dst {
                        (addr, cidr)
                    } else {
                        unreachable!()
                    }
                }),
                src: self.src.map(|src| {
                    if let (IpAddr::V6(addr), cidr) = src {
                        (addr, cidr)
                    } else {
                        unreachable!()
                    }
                }),
                action: self.action,
                table: self.table,
            }
            .blocking_add(c)?,
        };

        Ok(())
    }

    fn delete(self, c: &Connection) -> Result<(), SetupError> {
        match self.version {
            RuleVersion::Both => {
                rsdsl_netlinklib::rule::Rule::<Ipv4Addr> {
                    invert: self.invert,
                    fwmark: self.fwmark,
                    dst: None,
                    src: None,
                    action: self.action,
                    table: self.table,
                }
                .blocking_del(c)?;
                rsdsl_netlinklib::rule::Rule::<Ipv6Addr> {
                    invert: self.invert,
                    fwmark: self.fwmark,
                    dst: None,
                    src: None,
                    action: self.action,
                    table: self.table,
                }
                .blocking_del(c)?;
            }
            RuleVersion::Ipv4 => rsdsl_netlinklib::rule::Rule::<Ipv4Addr> {
                invert: self.invert,
                fwmark: self.fwmark,
                dst: self.dst.map(|dst| {
                    if let (IpAddr::V4(addr), cidr) = dst {
                        (addr, cidr)
                    } else {
                        unreachable!()
                    }
                }),
                src: self.src.map(|src| {
                    if let (IpAddr::V4(addr), cidr) = src {
                        (addr, cidr)
                    } else {
                        unreachable!()
                    }
                }),
                action: self.action,
                table: self.table,
            }
            .blocking_del(c)?,
            RuleVersion::Ipv6 => rsdsl_netlinklib::rule::Rule::<Ipv6Addr> {
                invert: self.invert,
                fwmark: self.fwmark,
                dst: self.dst.map(|dst| {
                    if let (IpAddr::V6(addr), cidr) = dst {
                        (addr, cidr)
                    } else {
                        unreachable!()
                    }
                }),
                src: self.src.map(|src| {
                    if let (IpAddr::V6(addr), cidr) = src {
                        (addr, cidr)
                    } else {
                        unreachable!()
                    }
                }),
                action: self.action,
                table: self.table,
            }
            .blocking_del(c)?,
        };

        Ok(())
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.version {
            RuleVersion::Both => write!(f, "rule")?,
            RuleVersion::Ipv4 => write!(f, "rule4")?,
            RuleVersion::Ipv6 => write!(f, "rule6")?,
        }
        if self.invert {
            write!(f, " invert true")?;
        }
        if let Some(fwmark) = self.fwmark {
            write!(f, " fwmark {}", fwmark)?;
        }
        if let Some(dst) = self.dst {
            write!(f, " dst {}/{}", dst.0, dst.1)?;
        }
        if let Some(src) = self.src {
            write!(f, " src {}/{}", src.0, src.1)?;
        }
        match self.action {
            RuleAction::Unspec => write!(f, " action unspec")?,
            RuleAction::ToTable => write!(f, " action to_table")?,
            RuleAction::Goto => write!(f, " action goto")?,
            RuleAction::Nop => write!(f, " action nop")?,
            RuleAction::Blackhole => write!(f, " action blackhole")?,
            RuleAction::Unreachable => write!(f, " action unreachable")?,
            RuleAction::Prohibit => write!(f, " action prohibit")?,
            RuleAction::Other(a) => write!(f, " action {}", a)?,
            _ => write!(f, " action ?")?,
        }
        if self.action == RuleAction::ToTable {
            write!(f, " table {}", self.table)?;
        }

        Ok(())
    }
}

impl FromStr for Rule {
    type Err = RuleParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut words = s.split_whitespace();

        let version_str = words.next().ok_or(RuleParseError::NoVersion)?;
        let version = match version_str {
            "rule" => RuleVersion::Both,
            "rule4" => RuleVersion::Ipv4,
            "rule6" => RuleVersion::Ipv6,
            _ => return Err(RuleParseError::InvalidVersion(version_str.to_string())),
        };

        let cmd = words.next().ok_or(RuleParseError::NoCmd)?;
        let delete = match cmd {
            "add" => false,
            "del" => true,
            _ => return Err(RuleParseError::InvalidCmd(cmd.to_string())),
        };

        let mut attrs = HashMap::<&str, &str>::new();
        let mut current_attr = None;
        for word in words {
            if let Some(attr) = current_attr {
                if attrs.insert(attr, word).is_some() {
                    return Err(RuleParseError::DuplicateAttr(attr.to_string()));
                }
                current_attr = None;
            } else {
                current_attr = Some(word);
            }
        }

        if let Some(attr) = current_attr {
            return Err(RuleParseError::NoAttrValue(attr.to_string()));
        }

        let mut invert = false;
        let mut fwmark = None;
        let mut dst = None;
        let mut src = None;
        let mut action = None;
        let mut table = None;

        for (attr, value) in attrs {
            match attr {
                "invert" => invert = value.parse()?,
                "fwmark" => fwmark = Some(value.parse()?),
                "dst" => {
                    let mut prefix = value.split('/');

                    let addr = prefix
                        .next()
                        .ok_or(RuleParseError::InvalidCidr(value.to_string()))?;
                    let cidr = prefix
                        .next()
                        .ok_or(RuleParseError::InvalidCidr(value.to_string()))?;

                    if prefix.next().is_some() {
                        return Err(RuleParseError::InvalidCidr(value.to_string()));
                    }

                    dst = Some((addr.parse()?, cidr.parse()?));
                }
                "src" => {
                    let mut prefix = value.split('/');

                    let addr = prefix
                        .next()
                        .ok_or(RuleParseError::InvalidCidr(value.to_string()))?;
                    let cidr = prefix
                        .next()
                        .ok_or(RuleParseError::InvalidCidr(value.to_string()))?;

                    if prefix.next().is_some() {
                        return Err(RuleParseError::InvalidCidr(value.to_string()));
                    }

                    src = Some((addr.parse()?, cidr.parse()?));
                }
                "action" => match value {
                    "to_table" => action = Some(RuleAction::ToTable),
                    "blackhole" => action = Some(RuleAction::Blackhole),
                    "unreachable" => action = Some(RuleAction::Unreachable),
                    "prohibit" => action = Some(RuleAction::Prohibit),
                    a => return Err(RuleParseError::InvalidAction(a.to_string())),
                },
                "table" => table = Some(value.parse()?),
                _ => return Err(RuleParseError::InvalidAttr(attr.to_string())),
            }
        }

        match version {
            RuleVersion::Both => Ok(Rule {
                delete,
                version,
                invert,
                fwmark,
                dst: if dst.is_some() {
                    return Err(RuleParseError::DstIllegal);
                } else {
                    None
                },
                src: if src.is_some() {
                    return Err(RuleParseError::SrcIllegal);
                } else {
                    None
                },
                action: action.ok_or(RuleParseError::NoAction)?,
                table: table.unwrap_or_default(),
            }),
            RuleVersion::Ipv4 => Ok(Rule {
                delete,
                version,
                invert,
                fwmark,
                dst: match dst {
                    Some((IpAddr::V4(dst), cidr)) => Some((IpAddr::V4(dst), cidr)),
                    Some(_) => return Err(RuleParseError::DstNotIpv4),
                    None => None,
                },
                src: match src {
                    Some((IpAddr::V4(src), cidr)) => Some((IpAddr::V4(src), cidr)),
                    Some(_) => return Err(RuleParseError::SrcNotIpv4),
                    None => None,
                },
                action: action.ok_or(RuleParseError::NoAction)?,
                table: table.unwrap_or_default(),
            }),
            RuleVersion::Ipv6 => Ok(Rule {
                delete,
                version,
                invert,
                fwmark,
                dst: match dst {
                    Some((IpAddr::V6(dst), cidr)) => Some((IpAddr::V6(dst), cidr)),
                    Some(_) => return Err(RuleParseError::DstNotIpv6),
                    None => None,
                },
                src: match src {
                    Some((IpAddr::V6(src), cidr)) => Some((IpAddr::V6(src), cidr)),
                    Some(_) => return Err(RuleParseError::SrcNotIpv6),
                    None => None,
                },
                action: action.ok_or(RuleParseError::NoAction)?,
                table: table.unwrap_or_default(),
            }),
        }
    }
}

#[derive(Debug)]
struct Rules {
    rules: Vec<Rule>,
}

impl FromStr for Rules {
    type Err = RuleParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rules = s
            .lines()
            .map(|l| l.parse::<Rule>())
            .collect::<Result<Vec<Rule>, Self::Err>>()?;

        Ok(Self { rules })
    }
}

fn main() {
    println!("[info] init");

    match run() {
        Ok(()) => loop {
            std::thread::park()
        },
        Err(e) => eprintln!("[warn] {}", e),
    }
}

fn run() -> Result<(), Error> {
    let routes = match std::fs::read_to_string(ROUTES_PATH) {
        Ok(s) => s,
        Err(e) => return Err(Error::ReadRoutes(e)),
    };
    let routes: Routes = routes.parse()?;

    let rules = match std::fs::read_to_string(RULES_PATH) {
        Ok(s) => s,
        Err(e) => return Err(Error::ReadRules(e)),
    };
    let rules: Rules = rules.parse()?;

    let conn = Connection::new().map_err(SetupError::from)?;

    for route in routes.routes {
        match route.def.clone().delete(&conn) {
            Ok(_) => println!("[info] del {}", route),
            Err(e) => println!("[warn] del {}: {}", route, e),
        }

        println!("[info] wait for link {}", route.def.link());
        conn.link_wait_exists(route.def.link().to_string())
            .map_err(SetupError::from)?;

        if !route.delete {
            match route.def.clone().add(&conn) {
                Ok(_) => println!("[info] add {}", route),
                Err(e) => println!("[warn] add {}: {}", route, e),
            }
        }
    }

    for rule in rules.rules {
        match rule.clone().delete(&conn) {
            Ok(_) => println!("[info] del {}", rule),
            Err(e) => println!("[warn] del {}: {}", rule, e),
        }

        if !rule.delete {
            match rule.clone().add(&conn) {
                Ok(_) => println!("[info] add {}", rule),
                Err(e) => println!("[warn] add {}: {}", rule, e),
            }
        }
    }

    Ok(())
}
