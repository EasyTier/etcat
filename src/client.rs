use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    crypto::{client_public_key, open_credential},
    identity::credential_authentication_key,
    key::SavedKey,
    network::{MeshInstance, client_config, tcp_forward},
    protocol::{Destination, GatewayHandshakeError, client_handshake},
    relay::{Relay, RelayRegistry},
    token::{ConnectionToken, CredentialEnvelope, RelayLocator, recipient_matches_public_key},
};

/// Options used when creating an etcat client.
#[derive(Clone, Default)]
pub struct ClientOptions {
    pub relay_file: Option<PathBuf>,
    pub key: Option<String>,
    pub private_key: Option<String>,
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientOptions")
            .field("relay_file", &self.relay_file)
            .field("key", &self.key)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// The network path currently used to reach a server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionPath {
    Direct,
    Relay { region: String },
}

/// Result of an authenticated application-level ping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    pub round_trip: Duration,
    pub path: ConnectionPath,
}

/// A reusable `EasyTier` session to one etcat server.
pub struct Client {
    mesh: MeshInstance,
    gateway: SocketAddr,
    server_ip: Ipv4Addr,
    relay_region: String,
    network_name: String,
    server_fingerprint: [u8; 16],
    authentication_key: [u8; 32],
}

impl Client {
    pub async fn connect(token: ConnectionToken, options: &ClientOptions) -> Result<Self> {
        let registry = RelayRegistry::load(options.relay_file.as_deref())?;
        let relay = resolve_relay(&token, &registry)?;
        let (credential_secret, client_ipv4) = client_credential(
            &token,
            options.key.as_deref(),
            options.private_key.as_deref(),
        )?;
        let authentication_key = credential_authentication_key(&credential_secret)?;
        let gateway_port = token.server.gateway_port;
        let gateway_ip = token.gateway_ipv4()?;
        let server_ip = token.server_virtual_ipv4()?;
        let network_name = token.network_name()?;
        let client_ip = client_ipv4.parse::<Ipv4Addr>()?;
        let local_port = reserve_bound_port().await?;
        let forward = tcp_forward(
            local_port,
            SocketAddr::new(IpAddr::V4(gateway_ip), gateway_port),
        );
        let config = client_config(
            &network_name,
            &credential_secret,
            client_ip,
            &relay,
            vec![forward],
            None,
        )?;
        let mesh = MeshInstance::start(config).await?;
        let server_fingerprint = token.server_fingerprint()?;
        wait_for_gateway_route(&mesh, gateway_ip, Duration::from_secs(30)).await?;
        Ok(Self {
            mesh,
            gateway: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port),
            server_ip,
            relay_region: relay.region,
            network_name,
            server_fingerprint,
            authentication_key,
        })
    }

    pub async fn dial(&self) -> Result<TcpStream> {
        self.dial_port(1).await
    }

    pub async fn dial_port(&self, port: u16) -> Result<TcpStream> {
        anyhow::ensure!(port != 0, "TCP port must be non-zero");
        self.connect_destination(Destination::ServerPort { port })
            .await
    }

    pub async fn dial_tcp(&self, host: IpAddr, port: u16) -> Result<TcpStream> {
        anyhow::ensure!(port != 0, "TCP port must be non-zero");
        self.connect_destination(Destination::ExitNode {
            host: host.to_string(),
            port,
        })
        .await
    }

    pub async fn connect_destination(&self, destination: Destination) -> Result<TcpStream> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let mut stream = connect_with_retry(self.gateway, Duration::from_secs(2)).await?;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let handshake = tokio::time::timeout(
                remaining,
                client_handshake(
                    &mut stream,
                    &self.network_name,
                    destination.clone(),
                    &self.server_fingerprint,
                    &self.authentication_key,
                ),
            )
            .await;
            match handshake {
                Ok(Ok(())) => return Ok(stream),
                Ok(Err(error)) if error.downcast_ref::<GatewayHandshakeError>().is_some() => {
                    return Err(error);
                }
                Ok(Err(error)) if tokio::time::Instant::now() >= deadline => return Err(error),
                Err(_) if tokio::time::Instant::now() >= deadline => {
                    anyhow::bail!("timed out authenticating the etcat gateway")
                }
                Ok(Err(_)) | Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    }

    pub async fn ping(&self) -> Result<ConnectionInfo> {
        let started = tokio::time::Instant::now();
        drop(self.connect_destination(Destination::Ping).await?);
        let round_trip = started.elapsed();
        let path = if self.path_is_direct().await.unwrap_or(false) {
            ConnectionPath::Direct
        } else {
            ConnectionPath::Relay {
                region: self.relay_region.clone(),
            }
        };
        Ok(ConnectionInfo { round_trip, path })
    }

    pub async fn stop(&self) {
        self.mesh.stop().await;
    }

    async fn path_is_direct(&self) -> Option<bool> {
        self.mesh
            .core()
            .route_snapshots()
            .await
            .iter()
            .find_map(|route| {
                route
                    .ipv4_addr
                    .as_ref()
                    .and_then(|inet| inet.address.as_ref())
                    .filter(|address| Ipv4Addr::from(address.addr) == self.server_ip)
                    .map(|_| route.cost == 1)
            })
    }
}

fn resolve_relay(token: &ConnectionToken, registry: &RelayRegistry) -> Result<Relay> {
    let relay = match &token.relay {
        RelayLocator::Registry { id } => registry
            .get(id)
            .cloned()
            .with_context(|| format!("relay {id:?} is not in this registry")),
        RelayLocator::RegistryCode { code } => registry
            .get_by_token_id(*code)
            .cloned()
            .with_context(|| format!("relay token ID {code} is not in this registry")),
        RelayLocator::Inline { relay } => Ok(relay.clone()),
    }?;
    if relay.public_key.is_none() {
        eprintln!(
            "warning: shared relay {:?} is encrypted but its identity is not pinned",
            relay.id
        );
    }
    Ok(relay)
}

async fn reserve_bound_port() -> Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    Ok(listener.local_addr()?.port())
}

async fn connect_with_retry(address: SocketAddr, timeout: Duration) -> Result<TcpStream> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) if tokio::time::Instant::now() >= deadline => return Err(error.into()),
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

async fn wait_for_gateway_route(
    mesh: &MeshInstance,
    gateway_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<()> {
    let expected = format!("{gateway_ip}/32");
    let canonical = gateway_ip.to_string();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let routes = mesh.core().route_snapshots().await;
        if routes.iter().any(|route| {
            route
                .proxy_cidrs
                .iter()
                .any(|cidr| cidr == &canonical || cidr == &expected)
                || route
                    .ipv4_addr
                    .as_ref()
                    .and_then(|inet| inet.address.as_ref())
                    .is_some_and(|address| Ipv4Addr::from(address.addr) == gateway_ip)
        }) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            let announced = routes
                .iter()
                .flat_map(|route| route.proxy_cidrs.iter())
                .cloned()
                .collect::<Vec<_>>();
            anyhow::bail!(
                "gateway route {expected} was not announced after {timeout:?}; announced proxy routes: {announced:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn client_credential(
    token: &ConnectionToken,
    key_name: Option<&str>,
    private_key: Option<&str>,
) -> Result<(String, String)> {
    match &token.credential {
        CredentialEnvelope::Bearer { secret } => {
            Ok((secret.clone(), token.client_ipv4(2)?.to_string()))
        }
        CredentialEnvelope::Sealed { recipients } => {
            anyhow::ensure!(
                private_key.is_none() || key_name.is_none(),
                "key and private_key are mutually exclusive"
            );
            let loaded;
            let private_key = if let Some(private_key) = private_key {
                private_key
            } else {
                let key_name = key_name.unwrap_or("client-default");
                let SavedKey::Client(client) = crate::key::load(key_name)
                    .with_context(|| format!("token requires client key {key_name:?}"))?
                else {
                    anyhow::bail!("selected key is a server key, not a client key")
                };
                loaded = client.private_key;
                &loaded
            };
            let public_key = client_public_key(private_key)?;
            let aad = token.credential_aad()?;
            let mut matched = false;
            let mut last_error = None;
            for sealed in recipients {
                if !recipient_matches_public_key(&sealed.recipient, &public_key)? {
                    continue;
                }
                matched = true;
                match open_credential(private_key, sealed, &aad) {
                    Ok(credential) => return Ok(credential),
                    Err(error) => last_error = Some(error),
                }
            }
            anyhow::ensure!(matched, "selected client key is not allowed by this token");
            Err(last_error.context("failed to open sealed client credential")?)
        }
    }
}
