use std::{io::Cursor, net::Ipv4Addr};

use anyhow::{Context, Result};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};

use crate::{
    identity::{
        gateway_ipv4_from_network_name, network_name_from_signing_key,
        server_ipv4_from_network_name,
    },
    relay::{Relay, RelayRegistry},
};

pub const TOKEN_PREFIX: &str = "etc1";
const MAX_ENCODED_TOKEN_LEN: usize = 16 * 1024;
const TOKEN_LABEL_LEN: usize = 63;
const CLIENT_PUBLIC_KEY_PREFIX: &str = "etcp1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionToken {
    pub version: u8,
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
    pub public_key: String,
    pub gateway_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelayLocator {
    Registry { id: String },
    Inline { relay: Relay },
}

#[derive(Serialize, Deserialize)]
struct WireToken(
    u8,
    WireCredential,
    #[serde(with = "serde_bytes")] Vec<u8>,
    u16,
    WireRelay,
    Option<i64>,
);

#[derive(Serialize, Deserialize)]
struct WireCredential(
    u8,
    #[serde(with = "serde_bytes")] Vec<u8>,
    Vec<WireRecipient>,
);

#[derive(Serialize, Deserialize)]
struct WireRecipient(
    #[serde(with = "serde_bytes")] Vec<u8>,
    u8,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize, Deserialize)]
struct WireRelay(
    u8,
    String,
    Vec<String>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

impl ConnectionToken {
    pub fn credential_aad(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct CredentialAad(u8, #[serde(with = "serde_bytes")] Vec<u8>, u16, Option<i64>);

        let mut bytes = Vec::new();
        ciborium::into_writer(
            &CredentialAad(
                self.version,
                self.server_public_key()?.to_vec(),
                self.server.gateway_port,
                self.expires_unix,
            ),
            &mut bytes,
        )?;
        Ok(bytes)
    }

    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        let wire = self.to_wire()?;
        let mut bytes = Vec::new();
        ciborium::into_writer(&wire, &mut bytes).context("failed to encode connection token")?;
        let compact = format!(
            "{TOKEN_PREFIX}{}",
            BASE32_NOPAD.encode(&bytes).to_ascii_lowercase()
        );
        let encoded = compact
            .as_bytes()
            .chunks(TOKEN_LABEL_LEN)
            .map(|label| std::str::from_utf8(label).expect("token encoding is ASCII"))
            .collect::<Vec<_>>()
            .join(".");
        if encoded.len() > MAX_ENCODED_TOKEN_LEN {
            anyhow::bail!("connection token exceeds {MAX_ENCODED_TOKEN_LEN} bytes");
        }
        Ok(encoded)
    }

    pub fn decode(input: &str) -> Result<Self> {
        if input.len() > MAX_ENCODED_TOKEN_LEN {
            anyhow::bail!("connection token exceeds {MAX_ENCODED_TOKEN_LEN} bytes");
        }
        anyhow::ensure!(
            input
                .split('.')
                .all(|label| !label.is_empty() && label.len() <= TOKEN_LABEL_LEN),
            "connection token contains an invalid hostname label"
        );
        let compact = input.replace('.', "");
        anyhow::ensure!(
            compact
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
            "connection token must use lowercase hostname characters"
        );
        let payload = compact
            .strip_prefix(TOKEN_PREFIX)
            .context("connection token must start with 'etc1'")?;
        let bytes = BASE32_NOPAD
            .decode(payload.to_ascii_uppercase().as_bytes())
            .context("connection token is not valid base32")?;
        let wire: WireToken = ciborium::from_reader(Cursor::new(bytes))
            .context("connection token contains invalid CBOR")?;
        let token = Self::from_wire(wire)?;
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

    pub fn network_name(&self) -> Result<String> {
        Ok(network_name_from_signing_key(&self.server_public_key()?))
    }

    pub fn server_virtual_ipv4(&self) -> Result<Ipv4Addr> {
        Ok(server_ipv4_from_network_name(&self.network_name()?))
    }

    pub fn gateway_ipv4(&self) -> Result<Ipv4Addr> {
        Ok(gateway_ipv4_from_network_name(&self.network_name()?))
    }

    pub fn client_ipv4(&self, host: u8) -> Result<Ipv4Addr> {
        anyhow::ensure!((2..=254).contains(&host), "invalid client address slot");
        let [a, b, c, _] = self.server_virtual_ipv4()?.octets();
        Ok(Ipv4Addr::new(a, b, c, host))
    }

    fn to_wire(&self) -> Result<WireToken> {
        let server_ipv4 = self.server_virtual_ipv4()?;
        let credential = match &self.credential {
            CredentialEnvelope::Bearer { secret } => WireCredential(
                0,
                decode_standard_32(secret, "bearer credential")?.to_vec(),
                Vec::new(),
            ),
            CredentialEnvelope::Sealed { recipients } => WireCredential(
                1,
                Vec::new(),
                recipients
                    .iter()
                    .map(|recipient| recipient_to_wire(recipient, server_ipv4))
                    .collect::<Result<_>>()?,
            ),
        };
        Ok(WireToken(
            self.version,
            credential,
            self.server_public_key()?.to_vec(),
            self.server.gateway_port,
            relay_to_wire(&self.relay)?,
            self.expires_unix,
        ))
    }

    fn from_wire(wire: WireToken) -> Result<Self> {
        let WireToken(version, credential, public_key, gateway_port, relay, expires_unix) = wire;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("server public key must contain 32 bytes"))?;
        let network_name = network_name_from_signing_key(&public_key);
        let server_ipv4 = server_ipv4_from_network_name(&network_name);
        let WireCredential(kind, secret, recipients) = credential;
        let credential = match kind {
            0 => {
                anyhow::ensure!(recipients.is_empty(), "bearer token has sealed recipients");
                let secret: [u8; 32] = secret
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("bearer credential must contain 32 bytes"))?;
                CredentialEnvelope::Bearer {
                    secret: STANDARD.encode(secret),
                }
            }
            1 => {
                anyhow::ensure!(secret.is_empty(), "sealed token has a bearer credential");
                CredentialEnvelope::Sealed {
                    recipients: recipients
                        .into_iter()
                        .map(|recipient| recipient_from_wire(recipient, server_ipv4))
                        .collect::<Result<_>>()?,
                }
            }
            _ => anyhow::bail!("unsupported credential type {kind}"),
        };
        Ok(Self {
            version,
            credential,
            server: ServerIdentity {
                public_key: STANDARD.encode(public_key),
                gateway_port,
            },
            relay: relay_from_wire(relay)?,
            expires_unix,
        })
    }

    fn server_public_key(&self) -> Result<[u8; 32]> {
        decode_standard_32(&self.server.public_key, "server public key")
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.version == 1,
            "unsupported connection token version {}",
            self.version
        );
        self.server_public_key()?;
        anyhow::ensure!(
            self.server.gateway_port != 0,
            "gateway port must be non-zero"
        );
        let server_ipv4 = self.server_virtual_ipv4()?;
        match &self.credential {
            CredentialEnvelope::Bearer { secret } => {
                decode_standard_32(secret, "bearer credential")?;
            }
            CredentialEnvelope::Sealed { recipients } => {
                anyhow::ensure!(
                    !recipients.is_empty(),
                    "sealed credential has no recipients"
                );
                for recipient in recipients {
                    recipient_to_wire(recipient, server_ipv4)?;
                }
            }
        }
        relay_to_wire(&self.relay)?;
        Ok(())
    }
}

fn recipient_to_wire(recipient: &SealedCredential, server_ipv4: Ipv4Addr) -> Result<WireRecipient> {
    let public_key = recipient
        .recipient
        .strip_prefix(CLIENT_PUBLIC_KEY_PREFIX)
        .context("client public key must start with 'etcp1'")?;
    let public_key = decode_url_32(public_key, "client public key")?;
    let client_ipv4 = recipient
        .client_ipv4
        .parse::<Ipv4Addr>()
        .context("invalid sealed client IPv4 address")?;
    let server = server_ipv4.octets();
    let client = client_ipv4.octets();
    anyhow::ensure!(
        client[..3] == server[..3],
        "sealed client address is outside the token network"
    );
    anyhow::ensure!(
        (2..=254).contains(&client[3]),
        "invalid sealed client address slot"
    );
    Ok(WireRecipient(
        public_key.to_vec(),
        client[3],
        decode_url_32(&recipient.encapsulated_key, "encapsulated HPKE key")?.to_vec(),
        URL_SAFE_NO_PAD
            .decode(&recipient.ciphertext)
            .context("invalid HPKE ciphertext")?,
    ))
}

fn recipient_from_wire(
    recipient: WireRecipient,
    server_ipv4: Ipv4Addr,
) -> Result<SealedCredential> {
    let WireRecipient(public_key, host, encapsulated_key, ciphertext) = recipient;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("client public key must contain 32 bytes"))?;
    let encapsulated_key: [u8; 32] = encapsulated_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("encapsulated HPKE key must contain 32 bytes"))?;
    anyhow::ensure!(!ciphertext.is_empty(), "HPKE ciphertext is empty");
    anyhow::ensure!(
        (2..=254).contains(&host),
        "invalid sealed client address slot"
    );
    let [a, b, c, _] = server_ipv4.octets();
    Ok(SealedCredential {
        recipient: format!(
            "{CLIENT_PUBLIC_KEY_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(public_key)
        ),
        client_ipv4: Ipv4Addr::new(a, b, c, host).to_string(),
        encapsulated_key: URL_SAFE_NO_PAD.encode(encapsulated_key),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

fn relay_to_wire(relay: &RelayLocator) -> Result<WireRelay> {
    match relay {
        RelayLocator::Registry { id } => {
            anyhow::ensure!(
                !id.is_empty() && id.len() <= 128,
                "invalid relay registry ID"
            );
            Ok(WireRelay(0, id.clone(), Vec::new(), Vec::new()))
        }
        RelayLocator::Inline { relay } => {
            anyhow::ensure!(
                !relay.endpoints.is_empty(),
                "embedded relay has no endpoints"
            );
            let public_key = relay
                .public_key
                .as_deref()
                .map(|key| decode_standard_32(key, "relay public key").map(|key| key.to_vec()))
                .transpose()?
                .unwrap_or_default();
            Ok(WireRelay(
                1,
                String::new(),
                relay.endpoints.iter().map(ToString::to_string).collect(),
                public_key,
            ))
        }
    }
}

fn relay_from_wire(relay: WireRelay) -> Result<RelayLocator> {
    let WireRelay(kind, id, endpoints, public_key) = relay;
    match kind {
        0 => {
            anyhow::ensure!(
                endpoints.is_empty() && public_key.is_empty(),
                "registry relay contains inline metadata"
            );
            anyhow::ensure!(
                !id.is_empty() && id.len() <= 128,
                "invalid relay registry ID"
            );
            Ok(RelayLocator::Registry { id })
        }
        1 => {
            anyhow::ensure!(id.is_empty(), "embedded relay contains a registry ID");
            let endpoints = endpoints
                .into_iter()
                .map(|endpoint| endpoint.parse().context("invalid embedded relay endpoint"))
                .collect::<Result<Vec<_>>>()?;
            anyhow::ensure!(!endpoints.is_empty(), "embedded relay has no endpoints");
            let public_key = if public_key.is_empty() {
                None
            } else {
                let public_key: [u8; 32] = public_key
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("relay public key must contain 32 bytes"))?;
                Some(STANDARD.encode(public_key))
            };
            Ok(RelayLocator::Inline {
                relay: Relay {
                    id: "inline-token".to_owned(),
                    region: "Embedded relay".to_owned(),
                    probe: String::new(),
                    endpoints,
                    public_key,
                    priority: 0,
                },
            })
        }
        _ => anyhow::bail!("unsupported relay locator type {kind}"),
    }
}

fn decode_standard_32(value: &str, name: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(value)
        .with_context(|| format!("invalid {name}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain 32 bytes"))
}

fn decode_url_32(value: &str, name: &str) -> Result<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("invalid {name}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConnectionToken {
        let public_key = [7_u8; 32];
        ConnectionToken {
            version: 1,
            credential: CredentialEnvelope::Bearer {
                secret: STANDARD.encode([9_u8; 32]),
            },
            server: ServerIdentity {
                public_key: STANDARD.encode(public_key),
                gateway_port: 49_152,
            },
            relay: RelayLocator::Registry {
                id: "official-global".to_owned(),
            },
            expires_unix: None,
        }
    }

    #[test]
    fn round_trips_compactly() {
        let token = sample();
        let encoded = token.encode().unwrap();
        assert!(
            encoded.len() <= 170,
            "token is {} characters",
            encoded.len()
        );
        assert_eq!(encoded, encoded.to_ascii_lowercase());
        assert!(encoded.split('.').all(|label| label.len() <= 63));
        let url = url::Url::parse(&format!("http://{encoded}:8080/")).unwrap();
        assert_eq!(url.host_str().unwrap(), encoded);
        assert_eq!(ConnectionToken::decode(&encoded).unwrap(), token);
    }

    #[test]
    fn derives_network_addresses_from_the_server_key() {
        let token = sample();
        assert!(token.network_name().unwrap().starts_with("etcat-"));
        assert_eq!(token.server_virtual_ipv4().unwrap().octets()[0], 10);
        assert_eq!(token.client_ipv4(2).unwrap().octets()[3], 2);
        let gateway = token.gateway_ipv4().unwrap().octets();
        assert_eq!(gateway[0], 100);
        assert!((64..=127).contains(&gateway[1]));
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
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(
            &mut file,
            br#"version = 1

[[relay]]
id = "official-global"
region = "test"
probe = "127.0.0.1:11010"
endpoints = ["tcp://127.0.0.1:11010"]
"#,
        )
        .unwrap();
        let registry = RelayRegistry::load(Some(file.path())).unwrap();
        let original = sample();
        let original_aad = original.credential_aad().unwrap();
        let token = original.resolve(&registry).unwrap();
        assert!(matches!(token.relay, RelayLocator::Inline { .. }));
        assert!(token.encode().unwrap().len() > sample().encode().unwrap().len());
        assert_eq!(token.credential_aad().unwrap(), original_aad);
    }
}
