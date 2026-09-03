use crate::token::{SealedCredential, client_key_id, recipient_matches_public_key};
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open, single_shot_seal,
};

const PUBLIC_KEY_PREFIX: &str = "etcp1";
const HPKE_INFO: &[u8] = b"etcat credential v2";
const RECIPIENT_AAD_DOMAIN: &[u8] = b"\0etcat recipient v2\0";

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

pub fn generate_client_key() -> String {
    let (private_key, _) = Kem::gen_keypair();
    URL_SAFE_NO_PAD.encode(private_key.to_bytes())
}

pub fn client_public_key(private_key: &str) -> Result<String> {
    let private_key = decode_private_key(private_key)?;
    Ok(encode_public_key(&Kem::sk_to_pk(&private_key)))
}

pub fn seal_credential(
    recipient: &str,
    secret: &str,
    client_ipv4: &str,
    aad: &[u8],
) -> Result<SealedCredential> {
    let public_key = decode_public_key(recipient)?;
    let recipient = client_key_id(recipient)?;
    let host = client_host(client_ipv4)?;
    let plaintext: [u8; 16] = base64::engine::general_purpose::STANDARD
        .decode(secret)
        .context("invalid credential seed")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("credential seed must contain 16 bytes"))?;
    let aad = recipient_aad(aad, &recipient, host);
    let (encapsulated_key, ciphertext) = single_shot_seal::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &public_key,
        HPKE_INFO,
        &plaintext,
        &aad,
    )
    .map_err(|error| anyhow::anyhow!("failed to seal credential: {error:?}"))?;
    Ok(SealedCredential {
        recipient,
        client_ipv4: client_ipv4.to_owned(),
        encapsulated_key: URL_SAFE_NO_PAD.encode(encapsulated_key.to_bytes()),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn open_credential(
    private_key: &str,
    sealed: &SealedCredential,
    aad: &[u8],
) -> Result<(String, String)> {
    let private_key = decode_private_key(private_key)?;
    let public_key = encode_public_key(&Kem::sk_to_pk(&private_key));
    anyhow::ensure!(
        recipient_matches_public_key(&sealed.recipient, &public_key)?,
        "credential is sealed to a different client key"
    );
    let encapsulated_key = URL_SAFE_NO_PAD
        .decode(&sealed.encapsulated_key)
        .context("invalid encapsulated HPKE key")?;
    let encapsulated_key = <Kem as KemTrait>::EncappedKey::from_bytes(&encapsulated_key)
        .map_err(|error| anyhow::anyhow!("invalid encapsulated HPKE key: {error:?}"))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&sealed.ciphertext)
        .context("invalid HPKE ciphertext")?;
    let aad = recipient_aad(aad, &sealed.recipient, client_host(&sealed.client_ipv4)?);
    let plaintext = single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &private_key,
        &encapsulated_key,
        HPKE_INFO,
        &ciphertext,
        &aad,
    )
    .map_err(|_| anyhow::anyhow!("failed to decrypt credential"))?;
    let seed: [u8; 16] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("decrypted credential seed must contain 16 bytes"))?;
    Ok((
        base64::engine::general_purpose::STANDARD.encode(seed),
        sealed.client_ipv4.clone(),
    ))
}

fn recipient_aad(aad: &[u8], recipient: &str, host: u8) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(aad.len() + RECIPIENT_AAD_DOMAIN.len() + recipient.len() + 1);
    bytes.extend_from_slice(aad);
    bytes.extend_from_slice(RECIPIENT_AAD_DOMAIN);
    bytes.extend_from_slice(recipient.as_bytes());
    bytes.push(host);
    bytes
}

fn client_host(client_ipv4: &str) -> Result<u8> {
    let address = client_ipv4
        .parse::<std::net::Ipv4Addr>()
        .context("invalid sealed client IPv4 address")?;
    let host = address.octets()[3];
    anyhow::ensure!(
        (2..=254).contains(&host),
        "invalid sealed client address slot"
    );
    Ok(host)
}

pub fn validate_public_key(value: &str) -> Result<()> {
    decode_public_key(value).map(|_| ())
}

fn decode_private_key(value: &str) -> Result<<Kem as KemTrait>::PrivateKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .context("invalid client private key")?;
    <Kem as KemTrait>::PrivateKey::from_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid client private key: {error:?}"))
}

fn decode_public_key(value: &str) -> Result<<Kem as KemTrait>::PublicKey> {
    let payload = value
        .strip_prefix(PUBLIC_KEY_PREFIX)
        .context("client public key must start with 'etcp1'")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .context("invalid client public key")?;
    <Kem as KemTrait>::PublicKey::from_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid client public key: {error:?}"))
}

fn encode_public_key(public_key: &<Kem as KemTrait>::PublicKey) -> String {
    format!(
        "{PUBLIC_KEY_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(public_key.to_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_to_one_recipient() {
        let private_key = generate_client_key();
        let public_key = client_public_key(&private_key).unwrap();
        let secret = base64::engine::general_purpose::STANDARD.encode([7_u8; 16]);
        let sealed = seal_credential(&public_key, &secret, "10.1.2.3", b"metadata").unwrap();
        assert_eq!(
            open_credential(&private_key, &sealed, b"metadata").unwrap(),
            (secret, "10.1.2.3".to_owned())
        );
        assert!(open_credential(&private_key, &sealed, b"different").is_err());
    }
}
