use std::net::Ipv4Addr;

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerIdentity {
    pub network_name: String,
    pub network_secret: String,
    pub private_key: String,
    pub signing_key: String,
    pub hostname: String,
    pub server_ipv4: Ipv4Addr,
}

impl std::fmt::Debug for ServerIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerIdentity")
            .field("network_name", &self.network_name)
            .field("network_secret", &"<redacted>")
            .field("private_key", &"<redacted>")
            .field("signing_key", &"<redacted>")
            .field("hostname", &self.hostname)
            .field("server_ipv4", &self.server_ipv4)
            .finish()
    }
}

impl ServerIdentity {
    pub fn generate() -> Self {
        let mut secret = [0_u8; 32];
        OsRng.fill_bytes(&mut secret);
        let private = StaticSecret::random_from_rng(OsRng);
        let signing = SigningKey::generate(&mut OsRng);
        let network_name = network_name_from_signing_key(&signing.verifying_key().to_bytes());
        let server_ipv4 = server_ipv4_from_network_name(&network_name);
        let hostname = hostname::get()
            .ok()
            .and_then(|value| value.into_string().ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "etcat-server".to_owned());

        Self {
            network_name,
            network_secret: STANDARD.encode(secret),
            private_key: STANDARD.encode(private.as_bytes()),
            signing_key: STANDARD.encode(signing.to_bytes()),
            hostname,
            server_ipv4,
        }
    }

    pub fn client_ipv4(&self, slot: u8) -> Ipv4Addr {
        let octets = self.server_ipv4.octets();
        Ipv4Addr::new(octets[0], octets[1], octets[2], slot.max(2))
    }

    pub fn gateway_ipv4(&self) -> Ipv4Addr {
        gateway_ipv4_from_network_name(&self.network_name)
    }

    pub fn signing_key(&self) -> anyhow::Result<SigningKey> {
        let bytes: [u8; 32] = STANDARD
            .decode(&self.signing_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key must contain 32 bytes"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    pub fn verifying_key(&self) -> anyhow::Result<VerifyingKey> {
        Ok(self.signing_key()?.verifying_key())
    }
}

pub fn network_name_from_signing_key(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!("etcat-{}", hex::encode(&digest[..16]))
}

pub fn server_ipv4_from_network_name(network_name: &str) -> Ipv4Addr {
    let digest = Sha256::digest(network_name.as_bytes());
    Ipv4Addr::new(10, digest[0], digest[1], 1)
}

pub fn gateway_ipv4_from_network_name(network_name: &str) -> Ipv4Addr {
    let digest = Sha256::digest(network_name.as_bytes());
    Ipv4Addr::new(100, 64 + digest[0] % 64, digest[1], digest[2])
}

pub fn generate_credential_secret() -> String {
    let private = StaticSecret::random_from_rng(OsRng);
    STANDARD.encode(private.as_bytes())
}

pub fn secure_mode(private_key: &str) -> anyhow::Result<easytier::proto::common::SecureModeConfig> {
    let private = decode_private_key(private_key)?;
    Ok(easytier::proto::common::SecureModeConfig {
        enabled: true,
        local_private_key: Some(STANDARD.encode(private.as_bytes())),
        local_public_key: Some(STANDARD.encode(PublicKey::from(&private).as_bytes())),
    })
}

pub fn decode_private_key(encoded: &str) -> anyhow::Result<StaticSecret> {
    let bytes: [u8; 32] = STANDARD
        .decode(encoded)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must contain 32 bytes"))?;
    Ok(StaticSecret::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_has_stable_public_material() {
        let identity = ServerIdentity::generate();
        assert_eq!(identity.verifying_key().unwrap().to_bytes().len(), 32);
        assert_eq!(
            identity.network_name,
            network_name_from_signing_key(&identity.verifying_key().unwrap().to_bytes())
        );
        assert_eq!(identity.server_ipv4.octets()[0], 10);
        assert_eq!(identity.client_ipv4(2).octets()[3], 2);
    }

    #[test]
    fn gateway_does_not_overlap_the_virtual_network() {
        let identity = ServerIdentity::generate();
        let gateway = identity.gateway_ipv4().octets();
        let server = identity.server_ipv4.octets();

        assert_eq!(gateway[0], 100);
        assert!((64..=127).contains(&gateway[1]));
        assert_ne!(gateway[..3], server[..3]);
        assert_eq!(identity.gateway_ipv4(), identity.gateway_ipv4());
    }
}
