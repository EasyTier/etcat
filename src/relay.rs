use std::{fs, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;

const BUILTIN_REGISTRY: &str = include_str!("../relays.toml");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    pub id: String,
    pub region: String,
    pub endpoints: Vec<Url>,
    pub probe: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default)]
    pub priority: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayFile {
    version: u16,
    relay: Vec<Relay>,
}

#[derive(Debug, Clone)]
pub struct RelayRegistry {
    relays: Vec<Relay>,
}

impl RelayRegistry {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let input = match path {
            Some(path) => fs::read_to_string(path)
                .with_context(|| format!("failed to read relay registry {}", path.display()))?,
            None => BUILTIN_REGISTRY.to_owned(),
        };
        let file: RelayFile = toml::from_str(&input).context("invalid relay registry")?;
        if file.version != 1 {
            anyhow::bail!("unsupported relay registry version {}", file.version);
        }
        if file.relay.is_empty() {
            anyhow::bail!("relay registry is empty");
        }

        let mut ids = std::collections::HashSet::new();
        for relay in &file.relay {
            if relay.id.is_empty() || !ids.insert(relay.id.clone()) {
                anyhow::bail!("relay IDs must be non-empty and unique");
            }
            if relay.endpoints.is_empty() {
                anyhow::bail!("relay {} has no endpoints", relay.id);
            }
            if let Some(key) = &relay.public_key {
                let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key)
                    .with_context(|| format!("relay {} has an invalid public key", relay.id))?;
                if bytes.len() != 32 {
                    anyhow::bail!("relay {} public key must contain 32 bytes", relay.id);
                }
            }
        }
        Ok(Self { relays: file.relay })
    }

    pub fn relays(&self) -> &[Relay] {
        &self.relays
    }

    pub fn get(&self, id: &str) -> Option<&Relay> {
        self.relays.iter().find(|relay| relay.id == id)
    }

    pub async fn select(&self, requested: Option<&str>) -> Result<Relay> {
        if let Some(id) = requested {
            return self
                .get(id)
                .cloned()
                .with_context(|| format!("relay {id:?} is not in this registry"));
        }

        let relays = Arc::new(self.relays.clone());
        let mut probes = tokio::task::JoinSet::new();
        for index in 0..relays.len() {
            let relays = relays.clone();
            probes.spawn(async move {
                let relay = &relays[index];
                let mut samples = Vec::with_capacity(3);
                for _ in 0..3 {
                    let started = tokio::time::Instant::now();
                    let result = tokio::time::timeout(
                        Duration::from_millis(1500),
                        tokio::net::TcpStream::connect(&relay.probe),
                    )
                    .await;
                    if matches!(result, Ok(Ok(_))) {
                        samples.push(started.elapsed());
                    }
                }
                samples.sort_unstable();
                samples
                    .get(samples.len() / 2)
                    .copied()
                    .map(|rtt| (index, rtt))
            });
        }

        let mut best = None;
        while let Some(result) = probes.join_next().await {
            if let Some(candidate) = result.context("relay probe task failed")?
                && best.is_none_or(|(_, best_rtt)| candidate.1 < best_rtt)
            {
                best = Some(candidate);
            }
        }
        if let Some((index, _)) = best {
            return Ok(self.relays[index].clone());
        }

        self.relays
            .iter()
            .min_by_key(|relay| relay.priority)
            .cloned()
            .context("relay registry is empty")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_registry_is_valid() {
        let registry = RelayRegistry::load(None).unwrap();
        assert!(!registry.relays().is_empty());
    }
}
