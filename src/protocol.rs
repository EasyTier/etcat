use std::{
    future::Future,
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME_LEN: usize = 4096;
const SIGNATURE_DOMAIN: &[u8] = b"etcat-gateway-v1\0";
const CLIENT_AUTH_DOMAIN: &[u8] = b"etcat-client-auth-v1\0";
const REQUEST_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(5)
};
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum GatewayHandshakeError {
    #[error("gateway rejected the connection: {0}")]
    Rejected(String),
    #[error("gateway identity does not match the connection token")]
    IdentityMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Destination {
    Stream,
    ServerPort { port: u16 },
    ExitNode { host: String, port: u16 },
    NoAuthSsh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayRequest {
    pub version: u8,
    pub nonce: [u8; 32],
    pub destination: Destination,
    #[serde(with = "serde_bytes")]
    authenticator: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayResponse {
    accepted: bool,
    message: String,
    signature: String,
}

impl GatewayRequest {
    pub fn new(
        network_name: &str,
        destination: Destination,
        authentication_key: &[u8; 32],
    ) -> Result<Self> {
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let mut request = Self {
            version: 1,
            nonce,
            destination,
            authenticator: Vec::new(),
        };
        request.authenticator = authenticate_request(network_name, &request, authentication_key)?;
        Ok(request)
    }
}

pub async fn client_handshake<S>(
    stream: &mut S,
    network_name: &str,
    destination: Destination,
    server_key: &VerifyingKey,
    authentication_key: &[u8; 32],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = GatewayRequest::new(network_name, destination, authentication_key)?;
    let request_bytes = encode(&request)?;
    write_frame(stream, &request_bytes).await?;
    let response: GatewayResponse = decode(&read_frame(stream).await?)?;
    let signature = Signature::from_slice(
        &STANDARD
            .decode(&response.signature)
            .context("gateway returned an invalid signature encoding")?,
    )
    .context("gateway returned an invalid signature")?;
    let transcript = transcript(
        network_name,
        &request_bytes,
        response.accepted,
        &response.message,
    );
    server_key
        .verify(&transcript, &signature)
        .map_err(|_| GatewayHandshakeError::IdentityMismatch)?;
    if !response.accepted {
        return Err(GatewayHandshakeError::Rejected(response.message).into());
    }
    Ok(())
}

pub async fn server_handshake<S, F, Fut, T>(
    stream: &mut S,
    network_name: &str,
    signing_key: &SigningKey,
    authentication_keys: &[[u8; 32]],
    authentication_expiry: Option<i64>,
    connect: F,
) -> Result<(Destination, T)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(Destination) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let request_bytes = tokio::time::timeout(REQUEST_TIMEOUT, read_frame(stream))
        .await
        .context("gateway request timed out")??;
    let request: GatewayRequest = decode(&request_bytes)?;
    if request.version != 1 {
        anyhow::bail!("unsupported gateway protocol version {}", request.version);
    }
    let expired = authentication_expiry.is_some_and(|expiry| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .is_ok_and(|now| i64::try_from(now.as_secs()).is_ok_and(|now| now >= expiry))
    });
    let authentication_bytes = request_authentication_bytes(network_name, &request)?;
    let authenticated = authentication_keys.iter().fold(false, |valid, key| {
        let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
            return valid;
        };
        mac.update(&authentication_bytes);
        valid | mac.verify_slice(&request.authenticator).is_ok()
    });
    let result = if expired {
        Err(anyhow::anyhow!("client credential has expired"))
    } else if authenticated {
        connect(request.destination.clone()).await
    } else {
        Err(anyhow::anyhow!("client authentication failed"))
    };
    let (accepted, message) = match &result {
        Ok(_) => (true, String::new()),
        Err(error) => (false, format!("{error:#}")),
    };
    let transcript = transcript(network_name, &request_bytes, accepted, &message);
    let response = GatewayResponse {
        accepted,
        message: message.clone(),
        signature: STANDARD.encode(signing_key.sign(&transcript).to_bytes()),
    };
    write_frame(stream, &encode(&response)?).await?;
    match result {
        Ok(connected) => Ok((request.destination, connected)),
        Err(_) => Err(GatewayHandshakeError::Rejected(message).into()),
    }
}

fn authenticate_request(
    network_name: &str,
    request: &GatewayRequest,
    authentication_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let bytes = request_authentication_bytes(network_name, request)?;
    let mut mac = HmacSha256::new_from_slice(authentication_key)?;
    mac.update(&bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn request_authentication_bytes(network_name: &str, request: &GatewayRequest) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct ClientAuth<'a> {
        domain: &'a [u8],
        network_name: &'a str,
        version: u8,
        nonce: &'a [u8; 32],
        destination: &'a Destination,
    }

    let mut bytes = Vec::new();
    ciborium::into_writer(
        &ClientAuth {
            domain: CLIENT_AUTH_DOMAIN,
            network_name,
            version: request.version,
            nonce: &request.nonce,
            destination: &request.destination,
        },
        &mut bytes,
    )?;
    Ok(bytes)
}

fn transcript(network_name: &str, request: &[u8], accepted: bool, message: &str) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(SIGNATURE_DOMAIN);
    hash.update(network_name.len().to_be_bytes());
    hash.update(network_name.as_bytes());
    hash.update(request.len().to_be_bytes());
    hash.update(request);
    hash.update([u8::from(accepted)]);
    hash.update(message.len().to_be_bytes());
    hash.update(message.as_bytes());
    hash.finalize().to_vec()
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    if bytes.len() > MAX_FRAME_LEN {
        anyhow::bail!("gateway frame exceeds {MAX_FRAME_LEN} bytes");
    }
    Ok(bytes)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).context("invalid gateway frame")
}

async fn write_frame(stream: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "gateway frame too large"))?;
    stream.write_u32(length).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

async fn read_frame(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let length = usize::try_from(stream.read_u32().await?)?;
    if length > MAX_FRAME_LEN {
        anyhow::bail!("gateway frame exceeds {MAX_FRAME_LEN} bytes");
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn signed_handshake_authenticates_and_authorizes() {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let authentication_key = [7_u8; 32];
        let (mut client, mut server) = tokio::io::duplex(8192);
        let server_task = tokio::spawn(async move {
            server_handshake(
                &mut server,
                "network",
                &signing,
                &[authentication_key],
                None,
                |destination| async move {
                    anyhow::ensure!(
                        destination == Destination::ServerPort { port: 80 },
                        "not allowed"
                    );
                    Ok(())
                },
            )
            .await
        });
        client_handshake(
            &mut client,
            "network",
            Destination::ServerPort { port: 80 },
            &verifying,
            &authentication_key,
        )
        .await
        .unwrap();
        assert_eq!(
            server_task.await.unwrap().unwrap(),
            (Destination::ServerPort { port: 80 }, ())
        );
    }

    #[tokio::test]
    async fn rejected_handshake_is_still_authenticated() {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let authentication_key = [7_u8; 32];
        let (mut client, mut server) = tokio::io::duplex(8192);
        let server_task = tokio::spawn(async move {
            server_handshake(
                &mut server,
                "network",
                &signing,
                &[authentication_key],
                None,
                |_| async { Err::<(), _>(anyhow::anyhow!("blocked")) },
            )
            .await
        });
        let error = client_handshake(
            &mut client,
            "network",
            Destination::ServerPort { port: 22 },
            &verifying,
            &authentication_key,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("blocked"));
        let server_error = server_task.await.unwrap().unwrap_err();
        assert!(
            server_error
                .downcast_ref::<GatewayHandshakeError>()
                .is_some()
        );
    }

    #[tokio::test]
    async fn success_waits_until_the_destination_is_connected() {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let authentication_key = [7_u8; 32];
        let (mut client, mut server) = tokio::io::duplex(8192);
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server_handshake(
                &mut server,
                "network",
                &signing,
                &[authentication_key],
                None,
                |_| async { connected_rx.await.context("destination signal was dropped") },
            )
            .await
        });
        let client_task = tokio::spawn(async move {
            client_handshake(
                &mut client,
                "network",
                Destination::ServerPort { port: 80 },
                &verifying,
                &authentication_key,
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!client_task.is_finished());
        connected_tx.send(()).unwrap();
        client_task.await.unwrap().unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_clients_without_the_credential_secret() {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let (mut client, mut server) = tokio::io::duplex(8192);
        let server_task = tokio::spawn(async move {
            server_handshake(
                &mut server,
                "network",
                &signing,
                &[[7_u8; 32]],
                None,
                |_| async { Ok(()) },
            )
            .await
        });

        let error = client_handshake(
            &mut client,
            "network",
            Destination::NoAuthSsh,
            &verifying,
            &[8_u8; 32],
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("client authentication failed"));
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn incomplete_gateway_requests_time_out() {
        let signing = SigningKey::generate(&mut OsRng);
        let (_client, mut server) = tokio::io::duplex(8192);

        let error = server_handshake(
            &mut server,
            "network",
            &signing,
            &[[7_u8; 32]],
            None,
            |_| async { Ok(()) },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("gateway request timed out"));
    }

    #[tokio::test]
    async fn expired_credentials_cannot_use_the_local_gateway() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let authentication_key = [7_u8; 32];
        let connected = Arc::new(AtomicBool::new(false));
        let server_connected = connected.clone();
        let (mut client, mut server) = tokio::io::duplex(8192);
        let server_task = tokio::spawn(async move {
            server_handshake(
                &mut server,
                "network",
                &signing,
                &[authentication_key],
                Some(0),
                |_| async move {
                    server_connected.store(true, Ordering::Relaxed);
                    Ok(())
                },
            )
            .await
        });

        let error = client_handshake(
            &mut client,
            "network",
            Destination::NoAuthSsh,
            &verifying,
            &authentication_key,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("credential has expired"));
        assert!(server_task.await.unwrap().is_err());
        assert!(!connected.load(Ordering::Relaxed));
    }
}
