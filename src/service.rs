use std::collections::BTreeSet;

use anyhow::{Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServePolicy {
    ports: BTreeSet<u16>,
    pub all_ports: bool,
    pub no_auth_ssh: bool,
    pub exit_node: bool,
}

impl ServePolicy {
    pub fn parse(values: &[String]) -> Result<Self> {
        let mut policy = Self {
            ports: BTreeSet::new(),
            all_ports: false,
            no_auth_ssh: false,
            exit_node: false,
        };
        for value in values {
            let value = value.trim();
            match value {
                "" => {}
                "all" => policy.all_ports = true,
                "no-auth-ssh" => policy.no_auth_ssh = true,
                "exit-node" => policy.exit_node = true,
                _ => {
                    if let Some((first, last)) = value.split_once('-') {
                        let first = parse_port(first)?;
                        let last = parse_port(last)?;
                        for port in first.min(last)..=first.max(last) {
                            policy.ports.insert(port);
                        }
                    } else {
                        policy.ports.insert(parse_port(value)?);
                    }
                }
            }
        }
        Ok(policy)
    }

    pub fn allows(&self, port: u16) -> bool {
        self.all_ports || self.exit_node || self.ports.contains(&port)
    }
}

fn parse_port(value: &str) -> Result<u16> {
    let port = value
        .parse::<u16>()
        .with_context(|| format!("invalid port {value:?}"))?;
    if port == 0 {
        anyhow::bail!("port 0 is reserved for etcat's stream mode");
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ports_ranges_and_services() {
        let policy = ServePolicy::parse(&[
            "22".to_owned(),
            "81-80".to_owned(),
            "no-auth-ssh".to_owned(),
        ])
        .unwrap();
        assert!(policy.allows(22));
        assert!(policy.allows(80));
        assert!(policy.allows(81));
        assert!(!policy.allows(82));
        assert!(policy.no_auth_ssh);
        assert!(!policy.exit_node);
    }

    #[test]
    fn rejects_zero_and_non_ports() {
        assert!(ServePolicy::parse(&["0".to_owned()]).is_err());
        assert!(ServePolicy::parse(&["ssh".to_owned()]).is_err());
    }
}
