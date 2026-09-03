use std::{
    io::{Cursor, Read},
    net::Ipv4Addr,
};

use anyhow::{Context, Result};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    identity::{
        gateway_ipv4_from_network_name, network_name_from_fingerprint,
        server_ipv4_from_network_name,
    },
    relay::{Relay, RelayRegistry},
};

pub const TOKEN_PREFIX: &str = "etc2";
const MAX_ENCODED_TOKEN_LEN: usize = 16 * 1024;
const TOKEN_LABEL_LEN: usize = 63;
const CLIENT_PUBLIC_KEY_PREFIX: &str = "etcp1";
const CLIENT_KEY_ID_PREFIX: &str = "etci1";
const CREDENTIAL_MASK: u8 = 0b0000_0011;
const RELAY_MASK: u8 = 0b0000_1100;
const RELAY_SHIFT: u8 = 2;
const EXPIRY: u8 = 0b0001_0000;
const RESERVED: u8 = 0b1110_0000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionToken {
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
    pub fingerprint: String,
    pub gateway_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelayLocator {
    Registry { id: String },
    RegistryCode { code: u16 },
    Inline { relay: Relay },
}

impl ConnectionToken {
    pub fn credential_aad(&self) -> Result<Vec<u8>> {
        let mut bytes = b"etcat credential aad v2\0".to_vec();
        bytes.extend_from_slice(&self.server_fingerprint()?);
        bytes.extend_from_slice(&self.server.gateway_port.to_be_bytes());
        match self.expires_unix {
            Some(expiry) => {
                bytes.push(1);
                bytes.extend_from_slice(&wire_expiry(expiry)?.to_be_bytes());
            }
            None => bytes.push(0),
        }
        Ok(bytes)
    }

    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        encode_payload(&self.encode_wire()?)
    }

    pub fn decode(input: &str) -> Result<Self> {
        validate_encoded_token(input)?;
        let compact = input.replace('.', "");
        let payload = compact
            .strip_prefix(TOKEN_PREFIX)
            .context("connection token must start with 'etc2'")?;
        let bytes = BASE32_NOPAD
            .decode(payload.to_ascii_uppercase().as_bytes())
            .context("connection token is not valid base32")?;
        let token = Self::decode_wire(&bytes)?;
        token.validate()?;
        Ok(token)
    }

    pub fn resolve(mut self, registry: &RelayRegistry) -> Result<Self> {
        let resolved = match &self.relay {
            RelayLocator::Registry { id } => Some(
                registry
                    .get(id)
                    .with_context(|| format!("relay {id:?} is not in this registry"))?
                    .clone(),
            ),
            RelayLocator::RegistryCode { code } => Some(
                registry
                    .get_by_token_id(*code)
                    .with_context(|| format!("relay token ID {code} is not in this registry"))?
                    .clone(),
            ),
            RelayLocator::Inline { .. } => None,
        };
        if let Some(relay) = resolved {
            self.relay = RelayLocator::Inline { relay };
        }
        Ok(self)
    }

    pub fn network_name(&self) -> Result<String> {
        Ok(network_name_from_fingerprint(&self.server_fingerprint()?))
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

    pub fn server_fingerprint(&self) -> Result<[u8; 16]> {
        decode_standard(&self.server.fingerprint, "server fingerprint")
    }

    fn encode_wire(&self) -> Result<Vec<u8>> {
        let credential_kind = match self.credential {
            CredentialEnvelope::Bearer { .. } => 0,
            CredentialEnvelope::Sealed { .. } => 1,
        };
        let relay_kind = match self.relay {
            RelayLocator::RegistryCode { .. } => 0,
            RelayLocator::Registry { .. } => 1,
            RelayLocator::Inline { .. } => 2,
        };
        let mut flags = credential_kind | (relay_kind << RELAY_SHIFT);
        if self.expires_unix.is_some() {
            flags |= EXPIRY;
        }

        let mut bytes = Vec::new();
        bytes.push(flags);
        bytes.extend_from_slice(&self.server_fingerprint()?);
        bytes.extend_from_slice(&self.server.gateway_port.to_be_bytes());
        if let Some(expiry) = self.expires_unix {
            bytes.extend_from_slice(&wire_expiry(expiry)?.to_be_bytes());
        }
        match &self.credential {
            CredentialEnvelope::Bearer { secret } => {
                bytes.extend_from_slice(&decode_standard::<16>(secret, "bearer credential seed")?);
            }
            CredentialEnvelope::Sealed { recipients } => {
                bytes.push(u8::try_from(recipients.len()).context("too many sealed recipients")?);
                let server_ipv4 = self.server_virtual_ipv4()?;
                for recipient in recipients {
                    let recipient = recipient_to_wire(recipient, server_ipv4)?;
                    bytes.extend_from_slice(&recipient.recipient_id);
                    bytes.push(recipient.host);
                    bytes.extend_from_slice(&recipient.encapsulated_key);
                    bytes.extend_from_slice(&recipient.ciphertext);
                }
            }
        }
        match &self.relay {
            RelayLocator::RegistryCode { code } => bytes.extend_from_slice(&code.to_be_bytes()),
            RelayLocator::Registry { id } => write_short_string(&mut bytes, id)?,
            RelayLocator::Inline { relay } => write_inline_relay(&mut bytes, relay)?,
        }
        Ok(bytes)
    }

    fn decode_wire(bytes: &[u8]) -> Result<Self> {
        let mut input = Cursor::new(bytes);
        let flags = read_u8(&mut input)?;
        anyhow::ensure!(flags & RESERVED == 0, "token has unsupported flags");
        let credential_kind = flags & CREDENTIAL_MASK;
        let relay_kind = (flags & RELAY_MASK) >> RELAY_SHIFT;
        anyhow::ensure!(
            credential_kind <= 1,
            "token has unsupported credential type"
        );
        anyhow::ensure!(relay_kind <= 2, "token has unsupported relay type");

        let fingerprint = read_array::<16>(&mut input)?;
        let gateway_port = read_u16(&mut input)?;
        let expires_unix = if flags & EXPIRY != 0 {
            Some(i64::from(read_u32(&mut input)?))
        } else {
            None
        };
        let network_name = network_name_from_fingerprint(&fingerprint);
        let server_ipv4 = server_ipv4_from_network_name(&network_name);
        let credential = match credential_kind {
            0 => CredentialEnvelope::Bearer {
                secret: STANDARD.encode(read_array::<16>(&mut input)?),
            },
            1 => {
                let count = read_u8(&mut input)?;
                anyhow::ensure!(count != 0, "sealed credential has no recipients");
                let mut recipients = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    let recipient_id = read_array::<8>(&mut input)?;
                    let host = read_u8(&mut input)?;
                    anyhow::ensure!((2..=254).contains(&host), "invalid client address slot");
                    let encapsulated_key = read_array::<32>(&mut input)?;
                    let ciphertext = read_array::<32>(&mut input)?;
                    let [a, b, c, _] = server_ipv4.octets();
                    recipients.push(SealedCredential {
                        recipient: encode_recipient_id(recipient_id),
                        client_ipv4: Ipv4Addr::new(a, b, c, host).to_string(),
                        encapsulated_key: URL_SAFE_NO_PAD.encode(encapsulated_key),
                        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
                    });
                }
                CredentialEnvelope::Sealed { recipients }
            }
            _ => unreachable!(),
        };
        let relay = match relay_kind {
            0 => RelayLocator::RegistryCode {
                code: read_u16(&mut input)?,
            },
            1 => RelayLocator::Registry {
                id: read_short_string(&mut input)?,
            },
            2 => RelayLocator::Inline {
                relay: read_inline_relay(&mut input)?,
            },
            _ => unreachable!(),
        };
        anyhow::ensure!(
            input.position() == bytes.len() as u64,
            "connection token contains trailing data"
        );
        Ok(Self {
            credential,
            server: ServerIdentity {
                fingerprint: STANDARD.encode(fingerprint),
                gateway_port,
            },
            relay,
            expires_unix,
        })
    }

    fn validate(&self) -> Result<()> {
        self.server_fingerprint()?;
        anyhow::ensure!(
            self.server.gateway_port != 0,
            "gateway port must be non-zero"
        );
        let server_ipv4 = self.server_virtual_ipv4()?;
        match &self.credential {
            CredentialEnvelope::Bearer { secret } => {
                decode_standard::<16>(secret, "bearer credential seed")?;
            }
            CredentialEnvelope::Sealed { recipients } => {
                anyhow::ensure!(
                    !recipients.is_empty() && recipients.len() <= 253,
                    "sealed credential must contain between 1 and 253 recipients"
                );
                for recipient in recipients {
                    recipient_to_wire(recipient, server_ipv4)?;
                }
            }
        }
        match &self.relay {
            RelayLocator::RegistryCode { code } => {
                anyhow::ensure!(*code != 0, "relay token ID must be non-zero");
            }
            RelayLocator::Registry { id } => validate_registry_id(id)?,
            RelayLocator::Inline { relay } => validate_inline_relay(relay)?,
        }
        if let Some(expiry) = self.expires_unix {
            wire_expiry(expiry)?;
        }
        Ok(())
    }
}

pub fn has_token_prefix(value: &str) -> bool {
    value.starts_with(TOKEN_PREFIX)
}

pub fn client_key_id(public_key: &str) -> Result<String> {
    let payload = public_key
        .strip_prefix(CLIENT_PUBLIC_KEY_PREFIX)
        .context("client public key must start with 'etcp1'")?;
    let public_key = decode_url::<32>(payload, "client public key")?;
    let digest = Sha256::digest(public_key);
    let mut id = [0_u8; 8];
    id.copy_from_slice(&digest[..8]);
    Ok(encode_recipient_id(id))
}

pub fn recipient_matches_public_key(recipient: &str, public_key: &str) -> Result<bool> {
    Ok(recipient == client_key_id(public_key)?)
}

fn validate_encoded_token(input: &str) -> Result<()> {
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
    Ok(())
}

fn encode_payload(bytes: &[u8]) -> Result<String> {
    let compact = format!(
        "{TOKEN_PREFIX}{}",
        BASE32_NOPAD.encode(bytes).to_ascii_lowercase()
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

struct WireRecipient {
    recipient_id: [u8; 8],
    host: u8,
    encapsulated_key: [u8; 32],
    ciphertext: [u8; 32],
}

fn recipient_to_wire(recipient: &SealedCredential, server_ipv4: Ipv4Addr) -> Result<WireRecipient> {
    let client_ipv4 = validate_client_ipv4(&recipient.client_ipv4, server_ipv4)?;
    Ok(WireRecipient {
        recipient_id: decode_recipient_id(&recipient.recipient)?,
        host: client_ipv4.octets()[3],
        encapsulated_key: decode_url(&recipient.encapsulated_key, "encapsulated HPKE key")?,
        ciphertext: decode_url(&recipient.ciphertext, "HPKE ciphertext")?,
    })
}

fn validate_client_ipv4(value: &str, server_ipv4: Ipv4Addr) -> Result<Ipv4Addr> {
    let client_ipv4 = value
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
        "invalid client address slot"
    );
    Ok(client_ipv4)
}

fn encode_recipient_id(id: [u8; 8]) -> String {
    format!(
        "{CLIENT_KEY_ID_PREFIX}{}",
        BASE32_NOPAD.encode(&id).to_ascii_lowercase()
    )
}

fn decode_recipient_id(value: &str) -> Result<[u8; 8]> {
    let payload = value
        .strip_prefix(CLIENT_KEY_ID_PREFIX)
        .context("client key ID must start with 'etci1'")?;
    BASE32_NOPAD
        .decode(payload.to_ascii_uppercase().as_bytes())
        .context("invalid client key ID")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("client key ID must contain 8 bytes"))
}

fn validate_registry_id(id: &str) -> Result<()> {
    anyhow::ensure!(
        !id.is_empty() && id.len() <= 128,
        "invalid relay registry ID"
    );
    Ok(())
}

fn validate_inline_relay(relay: &Relay) -> Result<()> {
    anyhow::ensure!(
        !relay.endpoints.is_empty() && u8::try_from(relay.endpoints.len()).is_ok(),
        "embedded relay must contain between 1 and 255 endpoints"
    );
    for endpoint in &relay.endpoints {
        u16::try_from(endpoint.as_str().len()).context("embedded relay endpoint is too long")?;
    }
    if let Some(key) = &relay.public_key {
        decode_standard::<32>(key, "relay public key")?;
    }
    Ok(())
}

fn write_inline_relay(bytes: &mut Vec<u8>, relay: &Relay) -> Result<()> {
    validate_inline_relay(relay)?;
    bytes.push(u8::try_from(relay.endpoints.len())?);
    for endpoint in &relay.endpoints {
        let endpoint = endpoint.as_str().as_bytes();
        bytes.extend_from_slice(&u16::try_from(endpoint.len())?.to_be_bytes());
        bytes.extend_from_slice(endpoint);
    }
    match relay.public_key.as_deref() {
        Some(public_key) => {
            bytes.push(1);
            bytes.extend_from_slice(&decode_standard::<32>(public_key, "relay public key")?);
        }
        None => bytes.push(0),
    }
    Ok(())
}

fn read_inline_relay(input: &mut Cursor<&[u8]>) -> Result<Relay> {
    let count = read_u8(input)?;
    anyhow::ensure!(count != 0, "embedded relay has no endpoints");
    let mut endpoints = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let length = usize::from(read_u16(input)?);
        let mut endpoint = vec![0_u8; length];
        input.read_exact(&mut endpoint)?;
        let endpoint =
            String::from_utf8(endpoint).context("embedded relay endpoint is not UTF-8")?;
        endpoints.push(
            endpoint
                .parse()
                .context("invalid embedded relay endpoint")?,
        );
    }
    let public_key = match read_u8(input)? {
        0 => None,
        1 => Some(STANDARD.encode(read_array::<32>(input)?)),
        _ => anyhow::bail!("embedded relay has invalid public key flag"),
    };
    Ok(Relay {
        id: "inline-token".to_owned(),
        region: "Embedded relay".to_owned(),
        probe: String::new(),
        endpoints,
        public_key,
        priority: 0,
        token_id: None,
    })
}

fn write_short_string(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    validate_registry_id(value)?;
    bytes.push(u8::try_from(value.len())?);
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn read_short_string(input: &mut Cursor<&[u8]>) -> Result<String> {
    let length = usize::from(read_u8(input)?);
    anyhow::ensure!(length != 0, "invalid relay registry ID");
    let mut bytes = vec![0_u8; length];
    input.read_exact(&mut bytes)?;
    let value = String::from_utf8(bytes).context("relay registry ID is not UTF-8")?;
    validate_registry_id(&value)?;
    Ok(value)
}

fn read_u8(input: &mut Cursor<&[u8]>) -> Result<u8> {
    Ok(read_array::<1>(input)?[0])
}

fn read_u16(input: &mut Cursor<&[u8]>) -> Result<u16> {
    Ok(u16::from_be_bytes(read_array(input)?))
}

fn read_u32(input: &mut Cursor<&[u8]>) -> Result<u32> {
    Ok(u32::from_be_bytes(read_array(input)?))
}

fn read_array<const N: usize>(input: &mut Cursor<&[u8]>) -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    input
        .read_exact(&mut bytes)
        .context("connection token is truncated")?;
    Ok(bytes)
}

fn wire_expiry(expiry: i64) -> Result<u32> {
    u32::try_from(expiry).context("token expiry must fit a Unix u32 timestamp")
}

fn decode_standard<const N: usize>(value: &str, name: &str) -> Result<[u8; N]> {
    STANDARD
        .decode(value)
        .with_context(|| format!("invalid {name}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain {N} bytes"))
}

fn decode_url<const N: usize>(value: &str, name: &str) -> Result<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("invalid {name}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain {N} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::server_fingerprint;

    fn sample() -> ConnectionToken {
        ConnectionToken {
            credential: CredentialEnvelope::Bearer {
                secret: STANDARD.encode([9_u8; 16]),
            },
            server: ServerIdentity {
                fingerprint: STANDARD.encode(server_fingerprint(&[7_u8; 32])),
                gateway_port: 49_152,
            },
            relay: RelayLocator::RegistryCode { code: 1 },
            expires_unix: None,
        }
    }

    #[test]
    fn bearer_round_trips_within_one_hostname() {
        let token = sample();
        let encoded = token.encode().unwrap();

        assert_eq!(encoded.len(), 65, "token is {} characters", encoded.len());
        assert_eq!(encoded, encoded.to_ascii_lowercase());
        assert!(encoded.split('.').all(|label| label.len() <= 63));
        let url = url::Url::parse(&format!("http://{encoded}:8080/")).unwrap();
        assert_eq!(url.host_str().unwrap(), encoded);
        assert_eq!(ConnectionToken::decode(&encoded).unwrap(), token);
    }

    #[test]
    fn expiry_adds_only_six_characters() {
        let mut token = sample();
        token.expires_unix = Some(1_800_000_000);
        let encoded = token.encode().unwrap();

        assert_eq!(encoded.len(), 71);
        assert_eq!(ConnectionToken::decode(&encoded).unwrap(), token);
    }

    #[test]
    fn derives_network_addresses_from_the_server_fingerprint() {
        let token = sample();
        assert!(token.network_name().unwrap().starts_with("etcat-"));
        assert_eq!(token.server_virtual_ipv4().unwrap().octets()[0], 10);
        assert_eq!(token.client_ipv4(2).unwrap().octets()[3], 2);
        let gateway = token.gateway_ipv4().unwrap().octets();
        assert_eq!(gateway[0], 100);
        assert!((64..=127).contains(&gateway[1]));
    }

    #[test]
    fn rejects_wrong_prefix_and_trailing_data() {
        assert!(ConnectionToken::decode("etc0garbage").is_err());
        assert!(ConnectionToken::decode("tcgarbage").is_err());

        let mut encoded = sample().encode_wire().unwrap();
        encoded.push(0);
        assert!(ConnectionToken::decode_wire(&encoded).is_err());
    }

    #[test]
    fn resolves_registry_references_without_changing_credential_aad() {
        let original = sample();
        let original_aad = original.credential_aad().unwrap();
        let token = original
            .resolve(&RelayRegistry::load(None).unwrap())
            .unwrap();

        assert!(matches!(token.relay, RelayLocator::Inline { .. }));
        let encoded = token.encode().unwrap();
        assert!(encoded.len() > sample().encode().unwrap().len());
        let decoded = ConnectionToken::decode(&encoded).unwrap();
        assert!(matches!(decoded.relay, RelayLocator::Inline { .. }));
        assert_eq!(decoded.credential_aad().unwrap(), original_aad);
    }

    #[test]
    fn custom_registry_ids_round_trip() {
        let mut token = sample();
        token.relay = RelayLocator::Registry {
            id: "private-relay".to_owned(),
        };

        let decoded = ConnectionToken::decode(&token.encode().unwrap()).unwrap();
        assert_eq!(decoded, token);
    }
}
