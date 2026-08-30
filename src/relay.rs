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
        Ok(self
            .select_candidates(requested)
            .await?
            .into_iter()
            .next()
            .expect("relay candidates are never empty"))
    }

    pub async fn select_candidates(&self, requested: Option<&str>) -> Result<Vec<Relay>> {
        if let Some(id) = requested {
            return self
                .get(id)
                .cloned()
                .map(|relay| vec![relay])
                .with_context(|| format!("relay {id:?} is not in this registry"));
        }
        if self.relays.is_empty() {
            anyhow::bail!("relay registry is empty; provide one with --relay-file");
        }

        let relays = Arc::new(self.relays.clone());
        let mut probes = tokio::task::JoinSet::new();
        for index in 0..relays.len() {
            let relays = relays.clone();
            probes.spawn(async move {
                let relay = &relays[index];
                let mut samples = Vec::with_capacity(3);
                let mut last_error = None;
                for _ in 0..3 {
                    let started = tokio::time::Instant::now();
                    let result = tokio::time::timeout(
                        Duration::from_millis(1500),
                        tokio::net::TcpStream::connect(&relay.probe),
                    )
                    .await;
                    match result {
                        Ok(Ok(_)) => samples.push(started.elapsed()),
                        Ok(Err(error)) => last_error = Some(error.to_string()),
                        Err(_) => last_error = Some("timed out after 1.5s".to_owned()),
                    }
                }
                samples.sort_unstable();
                (index, samples.get(samples.len() / 2).copied(), last_error)
            });
        }

        let mut reachable = Vec::new();
        let mut failures = vec![None; self.relays.len()];
        while let Some(result) = probes.join_next().await {
            let (index, rtt, error) = result.context("relay probe task failed")?;
            if let Some(rtt) = rtt {
                reachable.push((index, rtt));
            } else {
                failures[index] = error;
            }
        }
        if !reachable.is_empty() {
            reachable
                .sort_unstable_by_key(|&(index, rtt)| (rtt, self.relays[index].priority, index));
            return Ok(reachable
                .into_iter()
                .map(|(index, _)| self.relays[index].clone())
                .collect());
        }

        let failures = self
            .relays
            .iter()
            .zip(failures)
            .map(|(relay, error)| {
                format!(
                    "{}: {}",
                    relay.id,
                    error.unwrap_or_else(|| "probe failed".to_owned())
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!("no reachable relay after three TCP probes each ({failures})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(id: &str, probe: String) -> Relay {
        Relay {
            id: id.to_owned(),
            region: "test".to_owned(),
            endpoints: vec![format!("tcp://{probe}").parse().unwrap()],
            probe,
            public_key: None,
            priority: 0,
        }
    }

    #[test]
    fn built_in_registry_does_not_advertise_an_unverified_relay() {
        let registry = RelayRegistry::load(None).unwrap();
        assert!(registry.relays().is_empty());
    }

    #[tokio::test]
    async fn automatic_selection_explains_an_empty_registry() {
        let registry = RelayRegistry { relays: Vec::new() };

        let error = registry.select(None).await.unwrap_err().to_string();

        assert!(error.contains("relay registry is empty"));
        assert!(error.contains("--relay-file"));
    }

    #[tokio::test]
    async fn automatic_selection_rejects_unreachable_relays() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let probe = listener.local_addr().unwrap();
        drop(listener);
        let registry = RelayRegistry {
            relays: vec![relay("unreachable", probe.to_string())],
        };

        let error = registry.select(None).await.unwrap_err().to_string();

        assert!(error.contains("no reachable relay"));
        assert!(error.contains("unreachable"));
    }

    #[tokio::test]
    async fn automatic_selection_returns_a_reachable_relay() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let expected = relay("reachable", listener.local_addr().unwrap().to_string());
        let registry = RelayRegistry {
            relays: vec![expected.clone()],
        };

        assert_eq!(registry.select(None).await.unwrap(), expected);
    }

    #[tokio::test]
    async fn automatic_selection_keeps_all_reachable_candidates() {
        let first_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let second_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let registry = RelayRegistry {
            relays: vec![
                relay("first", first_listener.local_addr().unwrap().to_string()),
                relay("second", second_listener.local_addr().unwrap().to_string()),
            ],
        };

        let mut ids = registry
            .select_candidates(None)
            .await
            .unwrap()
            .into_iter()
            .map(|relay| relay.id)
            .collect::<Vec<_>>();
        ids.sort_unstable();

        assert_eq!(ids, ["first", "second"]);
    }
}
