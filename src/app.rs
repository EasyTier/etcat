use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use easytier::common::config::ManagedCredentialConfig;
use ed25519_dalek::VerifyingKey;
use hickory_resolver::{TokioResolver, name_server::TokioConnectionProvider};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy, copy_bidirectional},
    net::{TcpListener, TcpStream},
    process::Command as ProcessCommand,
};

use crate::{
    cli::{Cli, Command, GenkeyArgs},
    crypto::{
        client_public_key, generate_client_key, open_credential, seal_credential,
        validate_public_key,
    },
    identity::{ServerIdentity as PrivateServerIdentity, generate_credential_secret},
    key::{SavedKey, SavedServerKey},
    network::{
        AccessPolicy, CLIENT_GROUP, MeshInstance, client_config, managed_credential, server_config,
        tcp_forward,
    },
    protocol::{Destination, GatewayHandshakeError, client_handshake, server_handshake},
    relay::{Relay, RelayRegistry},
    service::ServePolicy,
    token::{
        ConnectionToken, CredentialEnvelope, RelayLocator, ServerIdentity as TokenServerIdentity,
    },
};

pub async fn run(cli: Cli) -> Result<()> {
    init_logging(cli.verbose);
    match cli.command.as_ref() {
        Some(Command::Parse(args)) => parse_token(&args.token),
        Some(Command::Resolve(args)) => {
            let registry = RelayRegistry::load(cli.relay_file.as_deref())?;
            let token = resolve_target(&args.token).await?;
            println!("{}", token.resolve(&registry)?.encode()?);
            Ok(())
        }
        Some(Command::Relays) => list_relays(cli.relay_file.as_deref()),
        Some(Command::Genkey(args)) => genkey(args, cli.relay_file.as_deref()).await,
        Some(Command::Printpub) => print_public_key(cli.key.as_deref()),
        Some(Command::Ping(args)) => {
            ping(&args.token, &args.timeout, args.until_direct, &cli).await
        }
        Some(Command::Socks(args)) => run_socks(args, &cli).await,
        Some(Command::Ssh(args)) => run_ssh(args, &cli).await,
        None if cli.target.is_some() => run_client(&cli).await,
        None => run_server(&cli).await,
    }
}

fn init_logging(verbose: u8) {
    let directive = match verbose {
        0 => "etcat=warn,easytier=off,easytier_core=off,quinn=off",
        1 => "etcat=info,easytier=warn,easytier_core=warn,quinn=off",
        _ => "etcat=debug,easytier_core=info,easytier=info",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(directive));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn parse_token(value: &str) -> Result<()> {
    let token = decode_token(value)?;
    let credential = match &token.credential {
        CredentialEnvelope::Bearer { .. } => serde_json::json!({ "kind": "bearer" }),
        CredentialEnvelope::Sealed { recipients } => serde_json::json!({
            "kind": "sealed",
            "recipients": recipients
                .iter()
                .map(|recipient| &recipient.recipient)
                .collect::<Vec<_>>(),
        }),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "version": token.version,
            "network_name": token.network_name()?,
            "credential": credential,
            "server": {
                "virtual_ipv4": token.server_virtual_ipv4()?,
                "gateway_ipv4": token.gateway_ipv4()?,
                "public_key": &token.server.public_key,
                "gateway_port": token.server.gateway_port,
            },
            "relay": &token.relay,
            "expires_unix": token.expires_unix,
        }))?
    );
    if let RelayLocator::Inline { relay } = &token.relay
        && relay.public_key.is_none()
    {
        eprintln!("warning: shared relay is encrypted but its identity is not pinned");
    }
    Ok(())
}

fn list_relays(path: Option<&Path>) -> Result<()> {
    let registry = RelayRegistry::load(path)?;
    for relay in registry.relays() {
        println!(
            "{}\t{}\t{}\t{}",
            relay.id,
            relay.region,
            if relay.public_key.is_some() {
                "pinned"
            } else {
                "encrypted-unpinned"
            },
            relay
                .endpoints
                .iter()
                .map(url::Url::as_str)
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    Ok(())
}

async fn genkey(args: &GenkeyArgs, relay_file: Option<&Path>) -> Result<()> {
    if args.list {
        for name in crate::key::list()? {
            println!("{name}");
        }
        return Ok(());
    }
    if args.client {
        let name = args.key.as_deref().unwrap_or("client-default");
        if args.delete {
            crate::key::delete(name)?;
            return Ok(());
        }
        let saved = crate::key::SavedClientKey {
            private_key: generate_client_key(),
        };
        let path = crate::key::save(name, &SavedKey::Client(saved.clone()), args.force)?;
        eprintln!("# wrote client key to {}", path.display());
        println!("{}", client_public_key(&saved.private_key)?);
        return Ok(());
    }
    let name = args.key.as_deref().unwrap_or("default");
    if args.delete {
        crate::key::delete(name)?;
        return Ok(());
    }

    let registry = RelayRegistry::load(relay_file)?;
    let relay = registry.select(args.relay.as_deref()).await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let gateway_port = listener.local_addr()?.port();
    drop(listener);
    let saved = SavedServerKey {
        identity: PrivateServerIdentity::generate(),
        credential_secret: generate_credential_secret(),
        relay_id: relay.id.clone(),
        fixed_relay: args.fixed_relay || args.relay.is_some(),
        gateway_port,
    };
    let path = crate::key::save(name, &SavedKey::Server(saved.clone()), args.force)?;
    eprintln!("# wrote key to {}", path.display());
    let token = make_token(
        &saved.identity,
        CredentialEnvelope::Bearer {
            secret: saved.credential_secret,
        },
        &relay,
        saved.gateway_port,
        args.full_address,
        None,
    )?;
    println!("{}", token.encode()?);
    Ok(())
}

fn print_public_key(name: Option<&str>) -> Result<()> {
    let name = name.unwrap_or("client-default");
    match crate::key::load(name)? {
        SavedKey::Client(client) => {
            println!("{}", client_public_key(&client.private_key)?);
            Ok(())
        }
        SavedKey::Server(_) => anyhow::bail!("{name:?} is a server key, not a client key"),
    }
}

async fn run_server(cli: &Cli) -> Result<()> {
    let policy = ServePolicy::parse(&cli.serve)?;
    #[cfg(not(unix))]
    anyhow::ensure!(
        !policy.no_auth_ssh,
        "the built-in no-auth SSH server is only supported on Unix"
    );
    let registry = RelayRegistry::load(cli.relay_file.as_deref())?;
    let material = server_material(cli, &registry).await?;

    let gateway = if let Some(port) = material.saved_gateway_port {
        TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .with_context(|| format!("saved gateway port {port} is unavailable"))?
    } else {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?
    };
    let gateway_port = gateway.local_addr()?.port();
    let expires_unix = expiry_from_ttl(cli.ttl.as_deref())?;
    let (credentials, token) =
        prepare_credentials_and_token(cli, &material, gateway_port, expires_unix)?;
    let access = AccessPolicy {
        destination_ip: material.identity.gateway_ipv4(),
        ports: vec![gateway_port],
    };
    let config = server_config(&material.identity, &material.relay, credentials, &access)?;
    let mesh = MeshInstance::start(config).await?;
    let encoded = token.encode()?;
    report_server_address(
        cli,
        &encoded,
        &material.relay,
        material.saved_key_name.as_deref(),
    )
    .await?;

    let signing_key = Arc::new(material.identity.signing_key()?);
    let policy = Arc::new(policy);
    let stream_mode = cli.serve.is_empty();
    loop {
        tokio::select! {
            accepted = gateway.accept() => {
                let (stream, _) = accepted?;
                if stream_mode {
                    handle_stream_connection(
                        stream,
                        &material.identity.network_name,
                        signing_key.as_ref(),
                    ).await?;
                    break;
                }
                let network_name = material.identity.network_name.clone();
                let signing_key = signing_key.clone();
                let policy = policy.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_service_connection(
                        stream,
                        &network_name,
                        signing_key.as_ref(),
                        &policy,
                    ).await {
                        tracing::debug!(?error, "gateway connection closed");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    mesh.stop().await;
    Ok(())
}

struct ServerMaterial {
    identity: PrivateServerIdentity,
    credential_secret: String,
    relay: Relay,
    saved_gateway_port: Option<u16>,
    saved_key_name: Option<String>,
}

async fn server_material(cli: &Cli, registry: &RelayRegistry) -> Result<ServerMaterial> {
    let selected = match cli.key.as_deref() {
        Some("new") => None,
        Some(name) => Some((name.to_owned(), crate::key::load(name)?)),
        None if crate::key::key_path("default")?.exists() => {
            Some(("default".to_owned(), crate::key::load("default")?))
        }
        None => None,
    };
    if let Some((key_name, saved)) = selected {
        let SavedKey::Server(saved) = saved else {
            anyhow::bail!("selected key is a client key")
        };
        let relay = if saved.fixed_relay {
            registry.get(&saved.relay_id).cloned().with_context(|| {
                format!("saved relay {:?} is not in the registry", saved.relay_id)
            })?
        } else {
            registry.select(None).await?
        };
        return Ok(ServerMaterial {
            identity: saved.identity,
            credential_secret: saved.credential_secret,
            relay,
            saved_gateway_port: Some(saved.gateway_port),
            saved_key_name: Some(key_name),
        });
    }
    Ok(ServerMaterial {
        identity: PrivateServerIdentity::generate(),
        credential_secret: generate_credential_secret(),
        relay: registry.select(None).await?,
        saved_gateway_port: None,
        saved_key_name: None,
    })
}

fn make_token(
    identity: &PrivateServerIdentity,
    credential: CredentialEnvelope,
    relay: &Relay,
    gateway_port: u16,
    full_address: bool,
    expires_unix: Option<i64>,
) -> Result<ConnectionToken> {
    let token = ConnectionToken {
        version: 1,
        credential,
        server: TokenServerIdentity {
            public_key: STANDARD.encode(identity.verifying_key()?.to_bytes()),
            gateway_port,
        },
        relay: if full_address {
            RelayLocator::Inline {
                relay: relay.clone(),
            }
        } else {
            RelayLocator::Registry {
                id: relay.id.clone(),
            }
        },
        expires_unix,
    };
    anyhow::ensure!(
        token.network_name()? == identity.network_name,
        "server identity has an inconsistent network name"
    );
    anyhow::ensure!(
        token.server_virtual_ipv4()? == identity.server_ipv4,
        "server identity has an inconsistent virtual address"
    );
    Ok(token)
}

fn prepare_credentials_and_token(
    cli: &Cli,
    material: &ServerMaterial,
    gateway_port: u16,
    expires_unix: Option<i64>,
) -> Result<(Vec<ManagedCredentialConfig>, ConnectionToken)> {
    let expiry = expires_unix.unwrap_or(i64::MAX);
    if cli.allow.is_empty() {
        let credentials = vec![managed_credential(
            "etcat-default".to_owned(),
            material.credential_secret.clone(),
            vec![CLIENT_GROUP.to_owned()],
            expiry,
        )];
        let token = make_token(
            &material.identity,
            CredentialEnvelope::Bearer {
                secret: material.credential_secret.clone(),
            },
            &material.relay,
            gateway_port,
            cli.full_address,
            expires_unix,
        )?;
        return Ok((credentials, token));
    }

    let mut credentials = Vec::with_capacity(cli.allow.len());
    let mut pending = Vec::with_capacity(cli.allow.len());
    let mut recipients = std::collections::HashSet::with_capacity(cli.allow.len());
    for (index, recipient) in cli.allow.iter().enumerate() {
        validate_public_key(recipient)
            .with_context(|| format!("invalid --allow public key {recipient:?}"))?;
        anyhow::ensure!(
            recipients.insert(recipient),
            "duplicate --allow public key {recipient:?}"
        );
        let host = u8::try_from(index + 2).context("too many --allow recipients")?;
        anyhow::ensure!(host < 255, "at most 253 recipients are supported");
        let client_ipv4 = material.identity.client_ipv4(host).to_string();
        let secret = generate_credential_secret();
        credentials.push(managed_credential(
            format!("etcat-{index}"),
            secret.clone(),
            vec![CLIENT_GROUP.to_owned()],
            expiry,
        ));
        pending.push((recipient, secret, client_ipv4));
    }

    let mut token = make_token(
        &material.identity,
        CredentialEnvelope::Sealed {
            recipients: Vec::new(),
        },
        &material.relay,
        gateway_port,
        cli.full_address,
        expires_unix,
    )?;
    let aad = token.credential_aad()?;
    let recipients = pending
        .into_iter()
        .map(|(recipient, secret, client_ipv4)| {
            seal_credential(recipient, &secret, &client_ipv4, &aad)
        })
        .collect::<Result<Vec<_>>>()?;
    token.credential = CredentialEnvelope::Sealed { recipients };
    Ok((credentials, token))
}

async fn report_server_address(
    cli: &Cli,
    token: &str,
    relay: &Relay,
    saved_key_name: Option<&str>,
) -> Result<()> {
    eprintln!("# Selected shared relay {}, {}", relay.id, relay.region);
    if relay.public_key.is_none() {
        eprintln!("# WARNING: relay traffic is encrypted, but this relay has no pinned identity");
    }
    if let Some(name) = saved_key_name {
        eprintln!("# Server listening with saved key {name:?}: {token}");
    } else {
        eprintln!("# Server listening with new address: {token}");
    }
    if cli.json {
        println!("{}", serde_json::json!({ "listenAddr": token }));
    }
    if let Ok(destination) = std::env::var("ETCAT_ADDR_FILE") {
        if let Some(address) = destination.strip_prefix("tcp:") {
            let mut stream = TcpStream::connect(address).await?;
            stream.write_all(token.as_bytes()).await?;
            stream.write_all(b"\n").await?;
        } else {
            write_private_token(Path::new(&destination), token)?;
        }
    }
    Ok(())
}

fn write_private_token(path: &Path, token: &str) -> Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create token file {}", path.display()))?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

async fn handle_stream_connection(
    mut stream: TcpStream,
    network_name: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<()> {
    let (destination, ()) = server_handshake(
        &mut stream,
        network_name,
        signing_key,
        |destination| async move {
            anyhow::ensure!(
                destination == Destination::Stream,
                "server is in stream mode"
            );
            Ok(())
        },
    )
    .await?;
    debug_assert_eq!(destination, Destination::Stream);
    copy(&mut stream, &mut tokio::io::stdout()).await?;
    Ok(())
}

async fn handle_service_connection(
    mut stream: TcpStream,
    network_name: &str,
    signing_key: &ed25519_dalek::SigningKey,
    policy: &ServePolicy,
) -> Result<()> {
    enum ConnectedDestination {
        Tcp(TcpStream),
        Ssh,
    }

    let (destination, connected) = server_handshake(
        &mut stream,
        network_name,
        signing_key,
        |destination| async move {
            match &destination {
                Destination::ServerPort { port } => {
                    anyhow::ensure!(policy.allows(*port), "TCP port {port} is not served");
                    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *port);
                    connect_destination(address, address.to_string())
                        .await
                        .map(ConnectedDestination::Tcp)
                }
                Destination::ExitNode { host, port } => {
                    anyhow::ensure!(policy.exit_node, "exit-node mode is disabled");
                    anyhow::ensure!(
                        !host.is_empty() && host.len() <= 253,
                        "invalid exit hostname"
                    );
                    anyhow::ensure!(*port != 0, "exit port must be non-zero");
                    connect_destination((host.as_str(), *port), format!("{host}:{port}"))
                        .await
                        .map(ConnectedDestination::Tcp)
                }
                Destination::NoAuthSsh => policy
                    .no_auth_ssh
                    .then_some(ConnectedDestination::Ssh)
                    .context("no-auth SSH is disabled"),
                Destination::Stream => anyhow::bail!("server is not in stream mode"),
            }
        },
    )
    .await?;
    match connected {
        ConnectedDestination::Ssh => {
            debug_assert_eq!(destination, Destination::NoAuthSsh);
            #[cfg(unix)]
            {
                crate::ssh_server::serve(stream).await
            }
            #[cfg(not(unix))]
            anyhow::bail!("no-auth SSH is unavailable on this platform");
        }
        ConnectedDestination::Tcp(mut target) => {
            copy_bidirectional(&mut stream, &mut target).await?;
            Ok(())
        }
    }
}

async fn connect_destination<A>(address: A, description: String) -> Result<TcpStream>
where
    A: tokio::net::ToSocketAddrs,
{
    tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(address))
        .await
        .with_context(|| format!("timed out connecting to {description}"))?
        .with_context(|| format!("failed to connect to {description}"))
}

async fn run_client(cli: &Cli) -> Result<()> {
    let target = cli.target.as_deref().context("missing connection token")?;
    let token = resolve_target(target).await?;
    let session =
        ClientSession::start(token, cli.relay_file.as_deref(), cli.key.as_deref()).await?;
    let stream = session
        .connect(parse_destination(cli.destination.as_deref())?)
        .await?;
    copy_stdio(stream).await
}

struct ClientSession {
    _mesh: MeshInstance,
    gateway: SocketAddr,
    network_name: String,
    verifying_key: VerifyingKey,
}

impl ClientSession {
    async fn start(
        token: ConnectionToken,
        relay_file: Option<&Path>,
        key_name: Option<&str>,
    ) -> Result<Self> {
        let registry = RelayRegistry::load(relay_file)?;
        let relay = resolve_relay(&token, &registry)?;
        let (credential_secret, client_ipv4) = client_credential(&token, key_name)?;
        let gateway_port = token.server.gateway_port;
        let server_ip = token.gateway_ipv4()?;
        let network_name = token.network_name()?;
        let client_ip = client_ipv4.parse::<Ipv4Addr>()?;
        let local_port = reserve_bound_port().await?;
        let forward = tcp_forward(
            local_port,
            SocketAddr::new(IpAddr::V4(server_ip), gateway_port),
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
        let key_bytes: [u8; 32] = STANDARD
            .decode(&token.server.public_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid server identity key"))?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)?;
        wait_for_gateway_route(&mesh, server_ip, Duration::from_secs(30)).await?;
        Ok(Self {
            _mesh: mesh,
            gateway: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port),
            network_name,
            verifying_key,
        })
    }

    async fn connect(&self, destination: Destination) -> Result<TcpStream> {
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
                    &self.verifying_key,
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

#[derive(Clone)]
struct ClientOptions {
    relay_file: Option<std::path::PathBuf>,
    key_name: Option<String>,
}

async fn run_socks(args: &crate::cli::SocksArgs, cli: &Cli) -> Result<()> {
    let mut program = args.args.as_slice();
    let fixed_token = if let Some(first) = program.first()
        && (first.starts_with(crate::token::TOKEN_PREFIX) || first.contains('.'))
    {
        match resolve_target(first).await {
            Ok(token) => {
                program = &program[1..];
                Some(token)
            }
            Err(error) if first.starts_with(crate::token::TOKEN_PREFIX) => return Err(error),
            Err(_) => None,
        }
    } else {
        None
    };
    let options = ClientOptions {
        relay_file: cli.relay_file.clone(),
        key_name: cli.key.clone(),
    };
    let fixed = if let Some(token) = fixed_token {
        Some(Arc::new(
            ClientSession::start(
                token,
                options.relay_file.as_deref(),
                options.key_name.as_deref(),
            )
            .await?,
        ))
    } else {
        None
    };
    let listener = TcpListener::bind(normalize_listen_address(&args.listen)?).await?;
    let address = listener.local_addr()?;
    let proxy_url = format!("socks5h://{address}");

    if let Some((program_name, program_args)) = program.split_first() {
        eprintln!("# SOCKS5 proxy listening at {proxy_url}");
        let server = tokio::spawn(serve_socks(listener, fixed, options));
        let status = ProcessCommand::new(program_name)
            .args(program_args)
            .env("all_proxy", &proxy_url)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .await
            .with_context(|| format!("failed to run {program_name:?}"))?;
        server.abort();
        anyhow::ensure!(status.success(), "command exited with {status}");
        return Ok(());
    }

    println!("SOCKS5 proxy listening at {proxy_url}");
    serve_socks(listener, fixed, options).await
}

async fn run_ssh(args: &crate::cli::SshArgs, cli: &Cli) -> Result<()> {
    use sha2::{Digest, Sha256};

    let (user, target) = args
        .target
        .split_once('@')
        .map_or((None, args.target.as_str()), |(user, target)| {
            (Some(user), target)
        });
    let destination = args.destination.as_deref().map_or_else(
        || "ssh".to_owned(),
        |value| {
            value.parse::<IpAddr>().map_or_else(
                |_| value.to_owned(),
                |ip| SocketAddr::new(ip, 22).to_string(),
            )
        },
    );
    let executable = std::env::current_exe().context("failed to locate etcat executable")?;
    let mut proxy_arguments = vec![executable.to_string_lossy().into_owned()];
    if let Some(key) = &cli.key {
        proxy_arguments.push(format!("--key={key}"));
    }
    if let Some(relay_file) = &cli.relay_file {
        proxy_arguments.push(format!("--relay-file={}", relay_file.display()));
    }
    proxy_arguments.push("--".to_owned());
    proxy_arguments.push(target.to_owned());
    proxy_arguments.push(destination);
    let proxy_command = proxy_arguments
        .iter()
        .map(|argument| quote_proxy_argument(argument))
        .collect::<Vec<_>>()
        .join(" ");

    let hash = Sha256::digest(target.as_bytes());
    let host = format!("etcat-{}", hex::encode(&hash[..8]));
    let ssh_target = user.map_or(host.clone(), |user| format!("{user}@{host}"));
    let status = ProcessCommand::new("ssh")
        .args([
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            &format!("ProxyCommand={proxy_command}"),
            &ssh_target,
        ])
        .args(&args.command)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .context("failed to run the system OpenSSH client")?;
    anyhow::ensure!(status.success(), "ssh exited with {status}");
    Ok(())
}

#[cfg(unix)]
fn quote_proxy_argument(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(windows)]
fn quote_proxy_argument(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

fn normalize_listen_address(value: &str) -> Result<SocketAddr> {
    if let Ok(port) = value.parse::<u16>() {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 0));
    }
    value
        .parse()
        .with_context(|| format!("invalid SOCKS listen address {value:?}"))
}

async fn serve_socks(
    listener: TcpListener,
    fixed: Option<Arc<ClientSession>>,
    options: ClientOptions,
) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let fixed = fixed.clone();
        let options = options.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_socks_connection(stream, fixed, &options).await {
                tracing::warn!(?error, "SOCKS5 connection failed");
            }
        });
    }
}

async fn handle_socks_connection(
    mut stream: TcpStream,
    fixed: Option<Arc<ClientSession>>,
    options: &ClientOptions,
) -> Result<()> {
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    anyhow::ensure!(greeting[0] == 5, "unsupported SOCKS version");
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await?;
        anyhow::bail!("SOCKS client does not support no-auth mode");
    }
    stream.write_all(&[5, 0]).await?;

    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    anyhow::ensure!(
        header[0] == 5 && header[1] == 1,
        "only SOCKS5 CONNECT is supported"
    );
    let host = match header[3] {
        1 => {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V4(Ipv4Addr::from(bytes)).to_string()
        }
        3 => {
            let length = stream.read_u8().await?;
            let mut bytes = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).context("SOCKS hostname is not UTF-8")?
        }
        4 => {
            let mut bytes = [0_u8; 16];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V6(std::net::Ipv6Addr::from(bytes)).to_string()
        }
        kind => anyhow::bail!("unsupported SOCKS address type {kind}"),
    };
    let port = stream.read_u16().await?;

    let dynamic;
    let (session, destination) = if host == "server.etcat" || host.is_empty() {
        (
            fixed.as_deref().context(
                "server.etcat requires a fixed connection token argument to 'etcat socks'",
            )?,
            Destination::ServerPort { port },
        )
    } else if host.starts_with(crate::token::TOKEN_PREFIX) && !host.contains('.') {
        dynamic = ClientSession::start(
            decode_token(&host)?,
            options.relay_file.as_deref(),
            options.key_name.as_deref(),
        )
        .await?;
        (&dynamic, Destination::ServerPort { port })
    } else {
        let session = fixed
            .as_deref()
            .context("exit-node destinations require a fixed connection token")?;
        (session, Destination::ExitNode { host, port })
    };

    match session.connect(destination).await {
        Ok(mut remote) => {
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            copy_bidirectional(&mut stream, &mut remote).await?;
            Ok(())
        }
        Err(error) => {
            let _ = stream.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            Err(error)
        }
    }
}

fn parse_destination(value: Option<&str>) -> Result<Destination> {
    let Some(value) = value else {
        return Ok(Destination::Stream);
    };
    if value == "ssh" {
        return Ok(Destination::NoAuthSsh);
    }
    if value.contains(':') {
        let address = value
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid IP:port destination {value:?}"))?;
        return Ok(Destination::ExitNode {
            host: address.ip().to_string(),
            port: address.port(),
        });
    }
    let port = value
        .parse::<u16>()
        .with_context(|| format!("invalid TCP port {value:?}"))?;
    anyhow::ensure!(port != 0, "TCP port must be non-zero");
    Ok(Destination::ServerPort { port })
}

fn resolve_relay(token: &ConnectionToken, registry: &RelayRegistry) -> Result<Relay> {
    let relay = match &token.relay {
        RelayLocator::Registry { id } => registry
            .get(id)
            .cloned()
            .with_context(|| format!("relay {id:?} is not in this registry")),
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
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

async fn connect_with_retry(address: SocketAddr, timeout: Duration) -> Result<TcpStream> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) if tokio::time::Instant::now() >= deadline => return Err(error.into()),
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn copy_stdio(stream: TcpStream) -> Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let input = tokio::spawn(async move {
        copy(&mut tokio::io::stdin(), &mut writer).await?;
        writer.shutdown().await
    });
    copy(&mut reader, &mut tokio::io::stdout()).await?;
    input.abort();
    Ok(())
}

async fn ping(token: &str, timeout: &str, until_direct: bool, cli: &Cli) -> Result<()> {
    let timeout = humantime::parse_duration(timeout).context("invalid --timeout")?;
    let token = resolve_target(token).await?;
    let registry = RelayRegistry::load(cli.relay_file.as_deref())?;
    let relay = resolve_relay(&token, &registry)?;
    let (credential_secret, client_ipv4) = client_credential(&token, cli.key.as_deref())?;
    let network_name = token.network_name()?;
    let config = client_config(
        &network_name,
        &credential_secret,
        client_ipv4.parse()?,
        &relay,
        Vec::new(),
        None,
    )?;
    let mesh = MeshInstance::start(config).await?;
    let server_ip = token.server_virtual_ipv4()?;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let routes = mesh.core().route_snapshots().await;
        if let Some(route) = routes.iter().find(|route| {
            route
                .ipv4_addr
                .as_ref()
                .and_then(|inet| inet.address.as_ref())
                .is_some_and(|address| Ipv4Addr::from(address.addr) == server_ip)
        }) {
            let direct = route.cost == 1;
            println!(
                "pong in {}ms via {}",
                route.path_latency.max(1),
                if direct { "direct" } else { "shared relay" }
            );
            if direct || !until_direct {
                mesh.stop().await;
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            mesh.stop().await;
            anyhow::bail!("no suitable path to the server after {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn client_credential(token: &ConnectionToken, key_name: Option<&str>) -> Result<(String, String)> {
    match &token.credential {
        CredentialEnvelope::Bearer { secret } => {
            Ok((secret.clone(), token.client_ipv4(2)?.to_string()))
        }
        CredentialEnvelope::Sealed { recipients } => {
            let key_name = key_name.unwrap_or("client-default");
            let SavedKey::Client(client) = crate::key::load(key_name)
                .with_context(|| format!("token requires client key {key_name:?}"))?
            else {
                anyhow::bail!("selected key is a server key, not a client key")
            };
            let public_key = client_public_key(&client.private_key)?;
            let sealed = recipients
                .iter()
                .find(|sealed| sealed.recipient == public_key)
                .context("selected client key is not allowed by this token")?;
            open_credential(&client.private_key, sealed, &token.credential_aad()?)
        }
    }
}

fn expiry_from_ttl(value: Option<&str>) -> Result<Option<i64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let ttl = humantime::parse_duration(value).context("invalid --ttl")?;
    anyhow::ensure!(!ttl.is_zero(), "--ttl must be positive");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expiry = now
        .checked_add(ttl.as_secs())
        .context("--ttl is too large")?;
    Ok(Some(i64::try_from(expiry).context("--ttl is too large")?))
}

fn decode_token(value: &str) -> Result<ConnectionToken> {
    let token = ConnectionToken::decode(value)?;
    if token.expires_unix.is_some_and(|expiry| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .is_ok_and(|now| i64::try_from(now.as_secs()).is_ok_and(|now| now >= expiry))
    }) {
        anyhow::bail!("connection token has expired");
    }
    Ok(token)
}

async fn resolve_target(value: &str) -> Result<ConnectionToken> {
    if value.starts_with(crate::token::TOKEN_PREFIX) {
        return decode_token(value);
    }
    anyhow::ensure!(
        value.contains('.'),
        "argument is neither an etc1 connection token nor a DNS name"
    );
    let resolver = TokioResolver::builder(TokioConnectionProvider::default())?.build();
    let records = tokio::time::timeout(Duration::from_secs(5), resolver.txt_lookup(value))
        .await
        .context("DNS TXT lookup timed out")?
        .with_context(|| format!("failed to resolve TXT records for {value:?}"))?;
    for record in records.iter() {
        let text = record
            .txt_data()
            .iter()
            .flat_map(|part| part.iter().copied())
            .collect::<Vec<_>>();
        let text = String::from_utf8(text).context("DNS TXT record is not UTF-8")?;
        if let Some(token) = text.trim().strip_prefix("etcat=") {
            return decode_token(token.trim());
        }
    }
    anyhow::bail!("no 'etcat=' TXT record found for {value:?}")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn address_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("address");
        write_private_token(&path, "etc1secret").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "etc1secret");
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
