use std::{
    collections::HashSet,
    net::Ipv4Addr,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use easytier::common::config::ManagedCredentialConfig;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};

use crate::{
    crypto::{seal_credential, validate_public_key},
    identity::{
        ServerIdentity, credential_authentication_key, generate_credential_secret,
        server_fingerprint,
    },
    key::SavedServerKey,
    network::{AccessPolicy, CLIENT_GROUP, MeshInstance, managed_credential, server_config},
    protocol::{Destination, server_handshake},
    relay::{Relay, RelayRegistry},
    token::{
        ConnectionToken, CredentialEnvelope, RelayLocator, ServerIdentity as TokenServerIdentity,
    },
};

const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Options for starting an authenticated etcat gateway.
#[derive(Clone, Default)]
pub struct ServerOptions {
    pub relay_file: Option<PathBuf>,
    pub relay: Option<String>,
    pub key: Option<SavedServerKey>,
    pub allowed_clients: Vec<String>,
    pub deny_all_clients: bool,
    pub full_address: bool,
    pub credential_lifetime: Option<Duration>,
}

impl std::fmt::Debug for ServerOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerOptions")
            .field("relay_file", &self.relay_file)
            .field("relay", &self.relay)
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .field("allowed_clients", &self.allowed_clients)
            .field("deny_all_clients", &self.deny_all_clients)
            .field("full_address", &self.full_address)
            .field("credential_lifetime", &self.credential_lifetime)
            .finish()
    }
}

/// An authenticated incoming stream and its requested logical destination.
pub struct IncomingConnection {
    pub destination: Destination,
    pub stream: TcpStream,
}

/// A reusable etcat server transport.
pub struct Server {
    mesh: MeshInstance,
    incoming: Mutex<mpsc::Receiver<Result<IncomingConnection>>>,
    accept_task: Mutex<Option<JoinHandle<()>>>,
    token: ConnectionToken,
    relay: Relay,
}

impl Server {
    pub async fn bind(options: &ServerOptions) -> Result<Self> {
        anyhow::ensure!(
            !options.deny_all_clients || options.allowed_clients.is_empty(),
            "deny_all_clients cannot be combined with allowed_clients"
        );
        let registry = RelayRegistry::load(options.relay_file.as_deref())?;
        let (identity, credential_secret, saved_port, saved_relay) =
            options.key.as_ref().map_or_else(
                || {
                    (
                        ServerIdentity::generate(),
                        generate_credential_secret(),
                        None,
                        None,
                    )
                },
                |key| {
                    (
                        key.identity.clone(),
                        key.credential_secret.clone(),
                        Some(key.gateway_port),
                        key.fixed_relay.then_some(key.relay_id.as_str()),
                    )
                },
            );
        let requested_relay = options.relay.as_deref().or(saved_relay);
        let relays = registry.select_candidates(requested_relay).await?;
        let gateway = bind_gateway(saved_port).await?;
        let gateway_port = gateway.local_addr()?.port();
        let expires_unix = expiry(options.credential_lifetime)?;
        let first_relay = relays.first().expect("relay candidates are never empty");
        let (credentials, credential, authentication_keys) = prepare_credentials(
            &identity,
            &credential_secret,
            &options.allowed_clients,
            options.deny_all_clients,
            first_relay,
            gateway_port,
            options.full_address,
            expires_unix,
        )?;
        let access = AccessPolicy {
            destination_ip: identity.gateway_ipv4(),
            ports: vec![gateway_port],
        };
        let (mesh, relay) = connect_mesh(&identity, &relays, &credentials, &access).await?;
        let token = make_token(
            &identity,
            credential,
            &relay,
            gateway_port,
            options.full_address,
            expires_unix,
        )?;
        let (incoming_tx, incoming_rx) = mpsc::channel(256);
        let accept_task = tokio::spawn(accept_gateway_connections(
            gateway,
            identity.network_name.clone(),
            identity.signing_key()?,
            authentication_keys,
            expires_unix,
            incoming_tx,
        ));
        Ok(Self {
            mesh,
            incoming: Mutex::new(incoming_rx),
            accept_task: Mutex::new(Some(accept_task)),
            token,
            relay,
        })
    }

    pub const fn token(&self) -> &ConnectionToken {
        &self.token
    }

    pub const fn relay(&self) -> &Relay {
        &self.relay
    }

    pub async fn accept(&self) -> Result<IncomingConnection> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .context("etcat server has stopped accepting connections")?
    }

    pub async fn stop(&self) {
        if let Some(task) = self.accept_task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        self.mesh.stop().await;
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = self.accept_task.get_mut().take() {
            task.abort();
        }
    }
}

async fn accept_gateway_connections(
    gateway: TcpListener,
    network_name: String,
    signing_key: ed25519_dalek::SigningKey,
    authentication_keys: Vec<[u8; 32]>,
    authentication_expiry: Option<i64>,
    incoming: mpsc::Sender<Result<IncomingConnection>>,
) {
    let signing_key = std::sync::Arc::new(signing_key);
    let authentication_keys = std::sync::Arc::new(authentication_keys);
    let slots = std::sync::Arc::new(Semaphore::new(256));
    let mut handshakes = JoinSet::new();
    loop {
        tokio::select! {
            accepted = gateway.accept() => {
                let (mut stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        let _ = incoming.send(Err(error.into())).await;
                        break;
                    }
                };
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    tracing::warn!("server authentication connection limit reached");
                    continue;
                };
                let network_name = network_name.clone();
                let signing_key = signing_key.clone();
                let authentication_keys = authentication_keys.clone();
                let incoming = incoming.clone();
                handshakes.spawn(async move {
                    let _slot = slot;
                    match server_handshake(
                        &mut stream,
                        &network_name,
                        signing_key.as_ref(),
                        authentication_keys.as_ref(),
                        authentication_expiry,
                        |_| async { Ok(()) },
                    )
                    .await
                    {
                        Ok((destination, ())) => {
                            let _ = incoming
                                .send(Ok(IncomingConnection { destination, stream }))
                                .await;
                        }
                        Err(error) => tracing::debug!(?error, "gateway connection closed"),
                    }
                });
            }
            result = handshakes.join_next(), if !handshakes.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::debug!(?error, "gateway authentication task failed");
                }
            }
        }
    }
}

async fn bind_gateway(port: Option<u16>) -> Result<TcpListener> {
    let port = port.unwrap_or(0);
    TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("gateway port {port} is unavailable"))
}

async fn connect_mesh(
    identity: &ServerIdentity,
    relays: &[Relay],
    credentials: &[ManagedCredentialConfig],
    access: &AccessPolicy,
) -> Result<(MeshInstance, Relay)> {
    let mut failures = Vec::with_capacity(relays.len());
    for relay in relays {
        let config = match server_config(identity, relay, credentials.to_vec(), access) {
            Ok(config) => config,
            Err(error) => {
                failures.push(format!("{}: {error:#}", relay.id));
                continue;
            }
        };
        let mesh = match MeshInstance::start(config).await {
            Ok(mesh) => mesh,
            Err(error) => {
                failures.push(format!("{}: {error:#}", relay.id));
                continue;
            }
        };
        match mesh
            .wait_for_relay_connection(relay, RELAY_CONNECT_TIMEOUT)
            .await
        {
            Ok(()) => return Ok((mesh, relay.clone())),
            Err(error) => {
                mesh.stop().await;
                failures.push(format!("{}: {error:#}", relay.id));
            }
        }
    }
    anyhow::bail!(
        "failed to connect to any reachable relay ({})",
        failures.join("; ")
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_credentials(
    identity: &ServerIdentity,
    bearer_secret: &str,
    allowed_clients: &[String],
    deny_all: bool,
    relay: &Relay,
    gateway_port: u16,
    full_address: bool,
    expires_unix: Option<i64>,
) -> Result<(
    Vec<ManagedCredentialConfig>,
    CredentialEnvelope,
    Vec<[u8; 32]>,
)> {
    let expiry = expires_unix.unwrap_or(i64::MAX);
    if allowed_clients.is_empty() {
        let credentials = if deny_all {
            Vec::new()
        } else {
            vec![managed_credential(
                "etcat-default".to_owned(),
                bearer_secret,
                vec![CLIENT_GROUP.to_owned()],
                expiry,
            )?]
        };
        let authentication_keys = if deny_all {
            Vec::new()
        } else {
            vec![credential_authentication_key(bearer_secret)?]
        };
        return Ok((
            credentials,
            CredentialEnvelope::Bearer {
                secret: bearer_secret.to_owned(),
            },
            authentication_keys,
        ));
    }

    let mut credentials = Vec::with_capacity(allowed_clients.len());
    let mut pending = Vec::with_capacity(allowed_clients.len());
    let mut recipients = HashSet::with_capacity(allowed_clients.len());
    for (index, recipient) in allowed_clients.iter().enumerate() {
        validate_public_key(recipient)
            .with_context(|| format!("invalid allowed client public key {recipient:?}"))?;
        anyhow::ensure!(recipients.insert(recipient), "duplicate allowed client key");
        let host = u8::try_from(index + 2).context("too many allowed clients")?;
        anyhow::ensure!(host < 255, "at most 253 allowed clients are supported");
        let client_ipv4 = identity.client_ipv4(host).to_string();
        let secret = generate_credential_secret();
        credentials.push(managed_credential(
            format!("etcat-{index}"),
            &secret,
            vec![CLIENT_GROUP.to_owned()],
            expiry,
        )?);
        pending.push((recipient, secret, client_ipv4));
    }

    let token = make_token(
        identity,
        CredentialEnvelope::Sealed {
            recipients: Vec::new(),
        },
        relay,
        gateway_port,
        full_address,
        expires_unix,
    )?;
    let aad = token.credential_aad()?;
    let authentication_keys = pending
        .iter()
        .map(|(_, secret, _)| credential_authentication_key(secret))
        .collect::<Result<Vec<_>>>()?;
    let sealed = pending
        .into_iter()
        .map(|(recipient, secret, client_ipv4)| {
            seal_credential(recipient, &secret, &client_ipv4, &aad)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((
        credentials,
        CredentialEnvelope::Sealed { recipients: sealed },
        authentication_keys,
    ))
}

fn make_token(
    identity: &ServerIdentity,
    credential: CredentialEnvelope,
    relay: &Relay,
    gateway_port: u16,
    full_address: bool,
    expires_unix: Option<i64>,
) -> Result<ConnectionToken> {
    let public_key = identity.verifying_key()?.to_bytes();
    let token = ConnectionToken {
        credential,
        server: TokenServerIdentity {
            fingerprint: STANDARD.encode(server_fingerprint(&public_key)),
            gateway_port,
        },
        relay: if full_address {
            RelayLocator::Inline {
                relay: relay.clone(),
            }
        } else if let Some(code) = relay.token_id() {
            RelayLocator::RegistryCode { code }
        } else {
            RelayLocator::Registry {
                id: relay.id.clone(),
            }
        },
        expires_unix,
    };
    token.credential_aad()?;
    anyhow::ensure!(
        token.network_name()? == identity.network_name,
        "server identity has an inconsistent network name"
    );
    Ok(token)
}

fn expiry(lifetime: Option<Duration>) -> Result<Option<i64>> {
    let Some(lifetime) = lifetime else {
        return Ok(None);
    };
    let deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .checked_add(lifetime)
        .context("credential lifetime is too large")?;
    i64::try_from(deadline.as_secs())
        .map(Some)
        .context("credential lifetime is too large")
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener as StdTcpListener;

    use super::*;
    use crate::{identity::server_fingerprint, protocol::client_handshake};

    #[test]
    fn library_server_options_are_constructible() {
        let options = ServerOptions {
            credential_lifetime: Some(Duration::from_mins(1)),
            ..Default::default()
        };
        assert_eq!(options.credential_lifetime, Some(Duration::from_mins(1)));
    }

    #[test]
    fn gateway_port_reservation_uses_loopback() {
        let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    #[tokio::test]
    async fn slow_handshake_does_not_block_an_authenticated_connection() {
        let gateway = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = gateway.local_addr().unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let fingerprint = server_fingerprint(&signing_key.verifying_key().to_bytes());
        let authentication_key = [7_u8; 32];
        let (incoming_tx, mut incoming_rx) = mpsc::channel(1);
        let accept_task = tokio::spawn(accept_gateway_connections(
            gateway,
            "etcat-test".to_owned(),
            signing_key,
            vec![authentication_key],
            None,
            incoming_tx,
        ));

        let stalled = TcpStream::connect(address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut valid = TcpStream::connect(address).await.unwrap();
        client_handshake(
            &mut valid,
            "etcat-test",
            Destination::ServerPort { port: 8080 },
            &fingerprint,
            &authentication_key,
        )
        .await
        .unwrap();

        let incoming = tokio::time::timeout(Duration::from_secs(1), incoming_rx.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            incoming.destination,
            Destination::ServerPort { port: 8080 }
        );

        drop(stalled);
        accept_task.abort();
        let _ = accept_task.await;
        assert!(TcpStream::connect(address).await.is_err());
    }
}
