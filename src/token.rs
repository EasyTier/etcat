use std::io::Cursor;

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::relay::{Relay, RelayRegistry};

pub const TOKEN_PREFIX: &str = "etc1";
const MAX_ENCODED_TOKEN_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionToken {
    pub version: u8,
    pub network_name: String,
    pub client_ipv4: String,
    pub credential: CredentialEnvelope,
    pub server: ServerIdentity,
    pub relay: RelayLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialEnvelope {
    Bearer { secret: String },
    Sealed { recipients: Vec<SealedCredential> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedCredential {
    pub recipient: String,
    pub client_ipv4: String,
    pub encapsulated_key: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerIdentity {
    pub hostname: String,
    pub virtual_ipv4: String,
    pub gateway_ipv4: String,
    pub public_key: String,
    pub noise_public_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_map: Vec<PortMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortMapping {
    pub logical: u16,
    pub actual: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelayLocator {
    Registry { id: String },
    Inline { relay: Relay },
}

impl ConnectionToken {
    pub fn credential_aad(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct CredentialAad<'a> {
            version: u8,
            network_name: &'a str,
            server: &'a ServerIdentity,
            relay: &'a RelayLocator,
            expires_unix: Option<i64>,
        }

        let mut bytes = Vec::new();
        ciborium::into_writer(
            &CredentialAad {
                version: self.version,
                network_name: &self.network_name,
                server: &self.server,
                relay: &self.relay,
                expires_unix: self.expires_unix,
            },
            &mut bytes,
        )?;
        Ok(bytes)
    }

    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes).context("failed to encode connection token")?;
        let encoded = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        if encoded.len() > MAX_ENCODED_TOKEN_LEN {
            anyhow::bail!("connection token exceeds {MAX_ENCODED_TOKEN_LEN} bytes");
        }
        Ok(encoded)
    }

    pub fn decode(input: &str) -> Result<Self> {
        if input.len() > MAX_ENCODED_TOKEN_LEN {
            anyhow::bail!("connection token exceeds {MAX_ENCODED_TOKEN_LEN} bytes");
        }
        let payload = input
            .strip_prefix(TOKEN_PREFIX)
            .context("connection token must start with 'etc1'")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .context("connection token is not valid base64url")?;
        let token: Self = ciborium::from_reader(Cursor::new(bytes))
            .context("connection token contains invalid CBOR")?;
        token.validate()?;
        Ok(token)
    }

    pub fn resolve(mut self, registry: &RelayRegistry) -> Result<Self> {
        if let RelayLocator::Registry { id } = &self.relay {
            let relay = registry
                .get(id)
                .with_context(|| format!("relay {id:?} is not in this registry"))?
                .clone();
            self.relay = RelayLocator::Inline { relay };
        }
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            anyhow::bail!("unsupported connection token version {}", self.version);
        }
        if self.network_name.is_empty() || self.network_name.len() > 128 {
            anyhow::bail!("invalid network name in connection token");
        }
        self.client_ipv4
            .parse::<std::net::Ipv4Addr>()
            .context("invalid client IPv4 address in connection token")?;
        self.server
            .virtual_ipv4
            .parse::<std::net::Ipv4Addr>()
            .context("invalid server IPv4 address in connection token")?;
        self.server
            .gateway_ipv4
            .parse::<std::net::Ipv4Addr>()
            .context("invalid gateway IPv4 address in connection token")?;
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&self.server.public_key)
            .context("invalid server public key in connection token")?;
        if public_key.len() != 32 {
            anyhow::bail!("server public key must contain 32 bytes");
        }
        let noise_public_key = base64::engine::general_purpose::STANDARD
            .decode(&self.server.noise_public_key)
            .context("invalid server Noise public key in connection token")?;
        if noise_public_key.len() != 32 {
            anyhow::bail!("server Noise public key must contain 32 bytes");
        }
        if let CredentialEnvelope::Sealed { recipients } = &self.credential
            && recipients.is_empty()
        {
            anyhow::bail!("sealed credential has no recipients");
        }
        if let CredentialEnvelope::Sealed { recipients } = &self.credential {
            for recipient in recipients {
                recipient
                    .client_ipv4
                    .parse::<std::net::Ipv4Addr>()
                    .context("invalid sealed client IPv4 address")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConnectionToken {
        ConnectionToken {
            version: 1,
            network_name: "test-network".to_owned(),
            client_ipv4: "10.42.1.2".to_owned(),
            credential: CredentialEnvelope::Bearer {
                secret: "credential".to_owned(),
            },
            server: ServerIdentity {
                hostname: "host".to_owned(),
                virtual_ipv4: "10.42.1.1".to_owned(),
                gateway_ipv4: "10.42.1.254".to_owned(),
                public_key: base64::engine::general_purpose::STANDARD.encode([7_u8; 32]),
                noise_public_key: base64::engine::general_purpose::STANDARD.encode([8_u8; 32]),
                port_map: vec![PortMapping {
                    logical: 0,
                    actual: 49152,
                }],
            },
            relay: RelayLocator::Registry {
                id: "official-global".to_owned(),
            },
            expires_unix: None,
        }
    }

    #[test]
    fn round_trips() {
        let token = sample();
        let encoded = token.encode().unwrap();
        assert_eq!(ConnectionToken::decode(&encoded).unwrap(), token);
    }

    #[test]
    fn rejects_wrong_prefix_and_version() {
        assert!(ConnectionToken::decode("tcgarbage").is_err());
        let mut token = sample();
        token.version = 2;
        assert!(token.encode().is_err());
    }

    #[test]
    fn resolves_registry_reference() {
        let registry = RelayRegistry::load(None).unwrap();
        let token = sample().resolve(&registry).unwrap();
        assert!(matches!(token.relay, RelayLocator::Inline { .. }));
    }
}
