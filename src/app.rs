use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use easytier::common::config::ManagedCredentialConfig;
use hickory_resolver::{TokioResolver, name_server::TokioConnectionProvider};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy, copy_bidirectional},
    net::{TcpListener, TcpStream},
    process::Command as ProcessCommand,
    sync::Semaphore,
};

use crate::{
    cli::{Cli, Command, GenkeyArgs, ServeArgs},
    client::{Client, ClientOptions, ConnectionPath},
    crypto::{client_public_key, generate_client_key, seal_credential, validate_public_key},
    identity::{
        ServerIdentity as PrivateServerIdentity, credential_authentication_key,
        generate_credential_secret, server_fingerprint,
    },
    key::{SavedKey, SavedServerKey},
    network::{AccessPolicy, CLIENT_GROUP, MeshInstance, managed_credential, server_config},
    protocol::{Destination, server_handshake},
    relay::{Relay, RelayRegistry},
    service::ServePolicy,
    token::{
        ConnectionToken, CredentialEnvelope, RelayLocator, ServerIdentity as TokenServerIdentity,
        has_token_prefix,
    },
};

const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) async fn run(cli: Cli) -> Result<()> {
    init_logging(cli.verbose);
    if cli.readme || matches!(cli.command, Some(Command::Readme)) {
        print!("{}", include_str!("../README.md"));
        return Ok(());
    }
    anyhow::ensure!(
        cli.serve.is_empty()
            || (cli.command.is_none() && cli.target.is_none() && cli.destination.is_none()),
        "no positional arguments are valid along with --serve"
    );
    match cli.command.as_ref() {
        Some(Command::Serve(args)) => run_server(&cli, ServerOptions::from_serve(&cli, args)).await,
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
        Some(Command::Ssh(args)) => run_ssh(args, &cli),
        Some(Command::Forward(args)) => run_forward(args, &cli).await,
        Some(Command::Recv(args)) => run_recv(args, &cli).await,
        Some(Command::Cp(args)) => run_cp(args, &cli),
        Some(Command::Ls(args)) => run_ls(args, &cli).await,
        Some(Command::Version) => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(Command::Readme) => unreachable!("handled before command dispatch"),
        None if cli.target.is_some() => run_client(&cli).await,
        None => run_server(&cli, ServerOptions::from_root(&cli)).await,
    }
}

#[derive(Debug, Clone)]
struct ServerOptions {
    services: Vec<String>,
    allow: Vec<String>,
    full_address: bool,
    json: bool,
    ttl: Option<String>,
    files: Option<String>,
}

impl ServerOptions {
    fn from_root(cli: &Cli) -> Self {
        Self {
            services: cli.serve.clone(),
            allow: cli.allow.clone(),
            full_address: cli.full_address,
            json: cli.json,
            ttl: cli.ttl.clone(),
            files: None,
        }
    }

    fn from_serve(cli: &Cli, args: &ServeArgs) -> Self {
        let mut services = args.services.clone();
        if args.files.is_some() && !services.iter().any(|service| service == "files") {
            services.push("files".to_owned());
        }
        Self {
            services,
            allow: if args.allow.is_empty() {
                cli.allow.clone()
            } else {
                args.allow.clone()
            },
            full_address: args.full_address || cli.full_address,
            json: cli.json,
            ttl: args.ttl.clone().or_else(|| cli.ttl.clone()),
            files: args.files.clone(),
        }
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
            "version": 2,
            "network_name": token.network_name()?,
            "credential": credential,
            "server": {
                "virtual_ipv4": token.server_virtual_ipv4()?,
                "gateway_ipv4": token.gateway_ipv4()?,
                "fingerprint": &token.server.fingerprint,
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
    if !args.client && args.relay.as_deref() == Some("list") {
        return list_relays(relay_file);
    }
    let name = args
        .key
        .as_deref()
        .context("genkey requires --key=<name|path>")?;
    if args.client {
        anyhow::ensure!(
            args.relay.is_none() && !args.fixed_relay && !args.full_address,
            "genkey --client does not take relay selection flags"
        );
        if args.delete {
            crate::key::delete(name)?;
            return Ok(());
        }
        let saved = crate::key::SavedClientKey {
            private_key: generate_client_key(),
        };
        let path = crate::key::save(name, &SavedKey::Client(saved.clone()), args.force)?;
        eprintln!("# wrote file to {}", path.display());
        println!("{}", client_public_key(&saved.private_key)?);
        return Ok(());
    }
    if args.delete {
        crate::key::delete(name)?;
        return Ok(());
    }

    let registry = RelayRegistry::load(relay_file)?;
    anyhow::ensure!(
        !(args.fixed_relay && args.relay.is_some()),
        "genkey --fixed-region and --region are mutually exclusive"
    );
    let requested_relay = args.relay.as_deref().filter(|relay| *relay != "auto");
    let relay = registry.select(requested_relay).await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let gateway_port = listener.local_addr()?.port();
    drop(listener);
    let saved = SavedServerKey {
        identity: PrivateServerIdentity::generate(),
        credential_secret: generate_credential_secret(),
        relay_id: relay.id.clone(),
        fixed_relay: args.fixed_relay || requested_relay.is_some(),
        gateway_port,
    };
    let path = crate::key::save(name, &SavedKey::Server(saved.clone()), args.force)?;
    eprintln!("# wrote file to {}", path.display());
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
    let saved = match name {
        Some("new") => None,
        Some(name) => Some((name, crate::key::load(name)?)),
        None if crate::key::key_path("client-default")?.exists() => {
            Some(("client-default", crate::key::load("client-default")?))
        }
        None => None,
    };
    let private_key = match saved {
        Some((_, SavedKey::Client(client))) => client.private_key,
        Some((name, SavedKey::Server(_))) => {
            anyhow::bail!("{name:?} is a server key, not a client key")
        }
        None => generate_client_key(),
    };
    println!("{}", client_public_key(&private_key)?);
    Ok(())
}

async fn run_server(cli: &Cli, options: ServerOptions) -> Result<()> {
    let policy = ServePolicy::parse(&options.services)?;
    let file_service = configured_file_service(&options, &policy)?;
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
    let expires_unix = expiry_from_ttl(options.ttl.as_deref())?;
    let initial_relay = material
        .relays
        .first()
        .expect("server relay candidates are never empty");
    let (credentials, credential_token, authentication_keys) = prepare_credentials_and_token(
        &options.allow,
        options.full_address,
        &material,
        initial_relay,
        gateway_port,
        expires_unix,
    )?;
    let access = AccessPolicy {
        destination_ip: material.identity.gateway_ipv4(),
        ports: vec![gateway_port],
    };
    let (mesh, relay) = connect_server_mesh(&material, &credentials, &access).await?;
    let token = make_token(
        &material.identity,
        credential_token.credential,
        &relay,
        gateway_port,
        options.full_address,
        expires_unix,
    )?;
    let encoded = token.encode()?;
    report_server_address(
        options.json,
        &encoded,
        &relay,
        material.saved_key_name.as_deref(),
    )
    .await?;

    let signing_key = Arc::new(material.identity.signing_key()?);
    let authentication_keys = Arc::new(authentication_keys);
    let policy = Arc::new(policy);
    let file_service = Arc::new(file_service);
    let stream_mode = options.services.is_empty() && options.files.is_none();
    GatewayRuntime {
        gateway,
        network_name: material.identity.network_name.clone(),
        signing_key,
        authentication_keys,
        expires_unix,
        policy,
        file_service,
    }
    .run(stream_mode)
    .await?;
    mesh.stop().await;
    Ok(())
}

struct GatewayRuntime {
    gateway: TcpListener,
    network_name: String,
    signing_key: Arc<ed25519_dalek::SigningKey>,
    authentication_keys: Arc<Vec<[u8; 32]>>,
    expires_unix: Option<i64>,
    policy: Arc<ServePolicy>,
    file_service: Arc<Option<crate::file_service::FileService>>,
}

impl GatewayRuntime {
    async fn run(&self, stream_mode: bool) -> Result<()> {
        let gateway_slots = Arc::new(Semaphore::new(256));
        loop {
            tokio::select! {
                accepted = self.gateway.accept() => {
                    let (stream, _) = accepted?;
                    if stream_mode {
                        match handle_stream_connection(
                            stream,
                            &self.network_name,
                            self.signing_key.as_ref(),
                            &self.authentication_keys,
                            self.expires_unix,
                        ).await {
                            Ok(true) => break,
                            Ok(false) => continue,
                            Err(error) => {
                                tracing::debug!(?error, "gateway connection closed");
                                continue;
                            }
                        }
                    }
                    let network_name = self.network_name.clone();
                    let Ok(slot) = gateway_slots.clone().try_acquire_owned() else {
                        tracing::warn!("gateway connection limit reached");
                        continue;
                    };
                    let signing_key = self.signing_key.clone();
                    let policy = self.policy.clone();
                    let file_service = self.file_service.clone();
                    let authentication_keys = self.authentication_keys.clone();
                    let expires_unix = self.expires_unix;
                    tokio::spawn(async move {
                        let _slot = slot;
                        if let Err(error) = handle_service_connection(
                            stream,
                            &network_name,
                            signing_key.as_ref(),
                            &authentication_keys,
                            expires_unix,
                            &policy,
                            file_service.as_ref().clone(),
                        ).await {
                            tracing::debug!(?error, "gateway connection closed");
                        }
                    });
                }
                _ = tokio::signal::ctrl_c() => break,
            }
        }
        Ok(())
    }
}

fn configured_file_service(
    options: &ServerOptions,
    policy: &ServePolicy,
) -> Result<Option<crate::file_service::FileService>> {
    if !policy.files {
        return Ok(None);
    }
    let (root, mode) = options.files.as_deref().map_or_else(
        || {
            Ok((
                std::env::current_dir()?,
                crate::file_service::FileMode::ReadOnly,
            ))
        },
        parse_file_spec,
    )?;
    Ok(Some(
        crate::file_service::FileService::new(&root, mode)
            .with_context(|| format!("failed to open file service root {}", root.display()))?,
    ))
}

fn parse_file_spec(value: &str) -> Result<(PathBuf, crate::file_service::FileMode)> {
    let split = value.rsplit_once(':').filter(|(path, suffix)| {
        !(path.len() == 1
            && path.as_bytes()[0].is_ascii_alphabetic()
            && (suffix.starts_with('/') || suffix.starts_with('\\')))
    });
    let (path, mode) = match split {
        Some((path, mode)) => (
            path,
            mode.parse::<crate::file_service::FileMode>()
                .with_context(|| format!("invalid --files value {value:?}"))?,
        ),
        None => (value, crate::file_service::FileMode::ReadOnly),
    };
    anyhow::ensure!(!path.is_empty(), "file service root cannot be empty");
    Ok((PathBuf::from(path), mode))
}

struct ServerMaterial {
    identity: PrivateServerIdentity,
    credential_secret: String,
    relays: Vec<Relay>,
    saved_gateway_port: Option<u16>,
    saved_key_name: Option<String>,
}

async fn connect_server_mesh(
    material: &ServerMaterial,
    credentials: &[ManagedCredentialConfig],
    access: &AccessPolicy,
) -> Result<(MeshInstance, Relay)> {
    let mut failures = Vec::with_capacity(material.relays.len());
    for relay in &material.relays {
        let config = match server_config(&material.identity, relay, credentials.to_vec(), access) {
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
        let relays = if saved.fixed_relay {
            vec![registry.get(&saved.relay_id).cloned().with_context(|| {
                format!("saved relay {:?} is not in the registry", saved.relay_id)
            })?]
        } else {
            registry.select_candidates(None).await?
        };
        return Ok(ServerMaterial {
            identity: saved.identity,
            credential_secret: saved.credential_secret,
            relays,
            saved_gateway_port: Some(saved.gateway_port),
            saved_key_name: Some(key_name),
        });
    }
    Ok(ServerMaterial {
        identity: PrivateServerIdentity::generate(),
        credential_secret: generate_credential_secret(),
        relays: registry.select_candidates(None).await?,
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
    anyhow::ensure!(
        token.server_virtual_ipv4()? == identity.server_ipv4,
        "server identity has an inconsistent virtual address"
    );
    Ok(token)
}

fn prepare_credentials_and_token(
    allow: &[String],
    full_address: bool,
    material: &ServerMaterial,
    relay: &Relay,
    gateway_port: u16,
    expires_unix: Option<i64>,
) -> Result<(Vec<ManagedCredentialConfig>, ConnectionToken, Vec<[u8; 32]>)> {
    let expiry = expires_unix.unwrap_or(i64::MAX);
    let deny_all = allow == ["none"];
    anyhow::ensure!(
        !allow.iter().any(|value| value == "none") || deny_all,
        "--allow=none cannot be combined with client public keys"
    );
    if allow.is_empty() || deny_all {
        let credentials = if deny_all {
            Vec::new()
        } else {
            vec![managed_credential(
                "etcat-default".to_owned(),
                &material.credential_secret,
                vec![CLIENT_GROUP.to_owned()],
                expiry,
            )?]
        };
        let token = make_token(
            &material.identity,
            CredentialEnvelope::Bearer {
                secret: material.credential_secret.clone(),
            },
            relay,
            gateway_port,
            full_address,
            expires_unix,
        )?;
        let authentication_keys = if deny_all {
            Vec::new()
        } else {
            vec![credential_authentication_key(&material.credential_secret)?]
        };
        return Ok((credentials, token, authentication_keys));
    }

    let mut credentials = Vec::with_capacity(allow.len());
    let mut pending = Vec::with_capacity(allow.len());
    let mut recipients = std::collections::HashSet::with_capacity(allow.len());
    for (index, recipient) in allow.iter().enumerate() {
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
            &secret,
            vec![CLIENT_GROUP.to_owned()],
            expiry,
        )?);
        pending.push((recipient, secret, client_ipv4));
    }

    let mut token = make_token(
        &material.identity,
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
    let recipients = pending
        .into_iter()
        .map(|(recipient, secret, client_ipv4)| {
            seal_credential(recipient, &secret, &client_ipv4, &aad)
        })
        .collect::<Result<Vec<_>>>()?;
    token.credential = CredentialEnvelope::Sealed { recipients };
    Ok((credentials, token, authentication_keys))
}

async fn report_server_address(
    json: bool,
    token: &str,
    relay: &Relay,
    saved_key_name: Option<&str>,
) -> Result<()> {
    eprintln!("# Selected bootstrap relay {}, {}", relay.id, relay.region);
    if relay.public_key.is_none() {
        eprintln!("# WARNING: relay traffic is encrypted, but this relay has no pinned identity");
    }
    if let Some(name) = saved_key_name {
        eprintln!("# 🐈 Server listening with saved key {name:?}: {token}");
    } else {
        eprintln!("# 🐈 Server listening with new address: {token}");
    }
    if json {
        println!("{}", serde_json::json!({ "listenAddr": token }));
    }
    if let Some(destination) = std::env::var("ETCAT_ADDR_FILE")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("TAILCAT_ADDR_FILE").ok())
        .filter(|value| !value.is_empty())
    {
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
    authentication_keys: &[[u8; 32]],
    authentication_expiry: Option<i64>,
) -> Result<bool> {
    let (destination, ()) = server_handshake(
        &mut stream,
        network_name,
        signing_key,
        authentication_keys,
        authentication_expiry,
        |destination| async move {
            anyhow::ensure!(
                matches!(
                    destination,
                    Destination::Ping | Destination::ServerPort { .. }
                ),
                "server is in stream mode"
            );
            Ok(())
        },
    )
    .await?;
    if destination == Destination::Ping {
        return Ok(false);
    }
    if destination == (Destination::ServerPort { port: 2 }) {
        receive_named_file(&mut stream).await?;
        return Ok(true);
    }
    copy(&mut stream, &mut tokio::io::stdout()).await?;
    Ok(true)
}

/// Port-2 file transfers carry a versioned metadata frame:
///
/// ```text
/// [magic: 8B "ETCATF01"]   version lives in the last two digits
/// [u32le header_len]       header length, capped at 64 KiB
/// [header: JSON]           self-describing keys; unknown keys are ignored
/// [payload]                raw bytes until EOF
/// ```
///
/// Receivers route on the magic: anything else is treated as a raw stream,
/// identical to port 1. Future protocol revisions bump the magic version
/// (`ETCATF02`, ...) and new header keys are additive, so implementations
/// never break each other.
const FILE_FRAME_MAGIC: &[u8; 8] = b"ETCATF01";

async fn receive_named_file(stream: &mut TcpStream) -> Result<()> {
    const MAX_HEADER_LEN: usize = 64 * 1024;

    // Read up to 8 magic bytes; short raw streams keep their bytes and are
    // replayed to stdout rather than erroring out.
    let mut magic = [0u8; 8];
    let mut magic_len = 0;
    while magic_len < 8 {
        let read = stream.read(&mut magic[magic_len..]).await?;
        if read == 0 {
            let mut stdout = tokio::io::stdout();
            stdout.write_all(&magic[..magic_len]).await?;
            copy(stream, &mut stdout).await?;
            return Ok(());
        }
        magic_len += read;
    }
    if &magic != FILE_FRAME_MAGIC {
        // A recognized frame-family prefix with an unknown version is a hard
        // error; anything else is a raw stream whose bytes are replayed.
        anyhow::ensure!(
            !magic.starts_with(b"ETCATF"),
            "unsupported file frame version: expected ETCATF01, got {}",
            String::from_utf8_lossy(&magic)
        );
        let mut stdout = tokio::io::stdout();
        stdout.write_all(&magic).await?;
        copy(stream, &mut stdout).await?;
        return Ok(());
    }

    let header_len = stream.read_u32_le().await? as usize;
    anyhow::ensure!(header_len <= MAX_HEADER_LEN, "file metadata header too large");
    let mut header = vec![0u8; header_len];
    stream.read_exact(&mut header).await?;
    let meta: serde_json::Value =
        serde_json::from_slice(&header).context("invalid file metadata")?;
    let name = meta
        .get("name")
        .and_then(serde_json::Value::as_str)
        .context("file metadata is missing a name")?;
    // Basename on both slash styles, then strip control characters (terminal
    // escapes included), then revalidate.
    let name: String = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    anyhow::ensure!(!name.is_empty() && name.len() <= 255, "invalid file name");
    let path = std::env::current_dir()?.join(&name);
    // create_new is atomic: it refuses existing files and final symlinks.
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
        .with_context(|| format!("{name} already exists in the working directory"))?;
    let written = copy(stream, &mut file).await?;
    eprintln!("# Received {written} bytes -> {}", path.display());
    Ok(())
}

async fn handle_service_connection(
    mut stream: TcpStream,
    network_name: &str,
    signing_key: &ed25519_dalek::SigningKey,
    authentication_keys: &[[u8; 32]],
    authentication_expiry: Option<i64>,
    policy: &ServePolicy,
    file_service: Option<crate::file_service::FileService>,
) -> Result<()> {
    enum ConnectedDestination {
        Ping,
        Tcp(TcpStream),
        Ssh,
    }

    let (destination, connected) = server_handshake(
        &mut stream,
        network_name,
        signing_key,
        authentication_keys,
        authentication_expiry,
        |destination| async move {
            match &destination {
                Destination::Ping => Ok(ConnectedDestination::Ping),
                Destination::ServerPort { port } => {
                    if *port == 22 && (policy.no_auth_ssh || policy.files) {
                        return Ok(ConnectedDestination::Ssh);
                    }
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
            }
        },
    )
    .await?;
    match connected {
        ConnectedDestination::Ping => Ok(()),
        ConnectedDestination::Ssh => {
            debug_assert_eq!(destination, Destination::ServerPort { port: 22 });
            crate::ssh_server::serve(stream, policy.no_auth_ssh, file_service).await
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
    let session = Client::connect(token, &client_options(cli)).await?;
    let stream = session
        .connect_destination(parse_destination(cli.destination.as_deref())?)
        .await?;
    copy_stdio(stream).await
}

fn client_options(cli: &Cli) -> ClientOptions {
    ClientOptions {
        relay_file: cli.relay_file.clone(),
        key: cli.key.clone(),
        private_key: None,
    }
}

async fn run_socks(args: &crate::cli::SocksArgs, cli: &Cli) -> Result<()> {
    let mut program = args.args.as_slice();
    let mut executable = program.first().and_then(resolve_executable);
    let fixed_token = if let Some(first) = program.first()
        && (has_token_prefix(first) || (first.contains('.') && executable.is_none()))
    {
        match resolve_target(first).await {
            Ok(token) => {
                program = &program[1..];
                executable = program.first().and_then(resolve_executable);
                Some(token)
            }
            Err(error) if has_token_prefix(first) => return Err(error),
            Err(_) => None,
        }
    } else {
        None
    };
    let options = ClientOptions {
        relay_file: cli.relay_file.clone(),
        key: cli.key.clone(),
        private_key: None,
    };
    let fixed = if let Some(token) = fixed_token {
        Some(Arc::new(Client::connect(token, &options).await?))
    } else {
        None
    };
    let listen_address = normalize_listen_address(&args.listen)?;
    let listener = TcpListener::bind(&listen_address)
        .await
        .with_context(|| format!("failed to listen on {listen_address:?}"))?;
    let address = listener.local_addr()?;
    let proxy_url = format!("socks5h://{address}");

    if let Some((program_name, program_args)) = program.split_first() {
        if cli.verbose > 0 {
            eprintln!("SOCKS running at {proxy_url}");
        }
        let server = tokio::spawn(serve_socks(listener, fixed, options));
        let status = ProcessCommand::new(executable.as_deref().unwrap_or(Path::new(program_name)))
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

    eprintln!("SOCKS running at {proxy_url}");
    serve_socks(listener, fixed, options).await
}

fn resolve_executable(command: &String) -> Option<PathBuf> {
    which::which(command).ok()
}

fn run_ssh(args: &crate::cli::SshArgs, cli: &Cli) -> Result<()> {
    let (user, target) = args
        .target
        .split_once('@')
        .map_or((None, args.target.as_str()), |(user, target)| {
            (Some(user), target)
        });
    let destination = crate::ssh_proxy::destination(args.destination.as_deref());
    let host = crate::ssh_proxy::host_alias(target);
    let ssh_target = user.map_or(host.clone(), |user| format!("{user}@{host}"));
    let mut command = std::process::Command::new("ssh");
    crate::ssh_proxy::configure(&mut command, cli, target, &destination)?;
    command.arg(ssh_target).args(&args.command);
    crate::ssh_proxy::launch(command, "ssh")
}

async fn run_forward(args: &crate::cli::ForwardArgs, cli: &Cli) -> Result<()> {
    let token = resolve_target(&args.target).await?;
    let session = Arc::new(Client::connect(token, &client_options(cli)).await?);
    let bind = args
        .bind
        .parse::<IpAddr>()
        .with_context(|| format!("invalid --bind IP address {:?}", args.bind))?;
    let mappings = crate::forward::parse_mappings(&args.mappings)?;
    crate::forward::run(Some(bind), mappings, move |destination| {
        let session = session.clone();
        async move { session.connect_destination(destination).await }
    })
    .await
}

async fn run_recv(args: &crate::cli::RecvArgs, cli: &Cli) -> Result<()> {
    run_server(cli, recv_server_options(args, cli)).await
}

fn recv_server_options(args: &crate::cli::RecvArgs, cli: &Cli) -> ServerOptions {
    let mode = if args.accept_dirs { "wo+" } else { "wo" };
    let files = format!("{}:{mode}", args.directory.display());
    ServerOptions {
        services: vec!["files".to_owned()],
        allow: cli.allow.clone(),
        full_address: cli.full_address,
        json: cli.json,
        ttl: cli.ttl.clone(),
        files: Some(files),
    }
}

fn run_cp(args: &crate::cli::CpArgs, cli: &Cli) -> Result<()> {
    let remotes = args
        .paths
        .iter()
        .enumerate()
        .filter_map(|(index, path)| parse_remote_path(path).map(|remote| (index, remote)))
        .collect::<Vec<_>>();
    let first = remotes
        .first()
        .map(|(_, remote)| *remote)
        .context("cp requires at least one remote path containing an etc2 token or DNS name")?;
    anyhow::ensure!(
        remotes
            .iter()
            .all(|(_, remote)| remote.target == first.target),
        "all remote paths must use the same server"
    );

    let alias = crate::ssh_proxy::host_alias(first.target);
    let mut paths = args.paths.clone();
    for (index, remote) in remotes {
        paths[index] = remote.user.map_or_else(
            || format!("{alias}:{}", remote.path),
            |user| format!("{user}@{alias}:{}", remote.path),
        );
    }

    let destination = crate::ssh_proxy::destination(args.destination.as_deref());
    let mut command = std::process::Command::new("scp");
    crate::ssh_proxy::configure(&mut command, cli, first.target, &destination)?;
    if args.recursive {
        command.arg("-r");
    }
    if args.preserve {
        command.arg("-p");
    }
    command.args(paths);
    crate::ssh_proxy::launch(command, "scp")
}

async fn run_ls(args: &crate::cli::LsArgs, cli: &Cli) -> Result<()> {
    let (target, path) = args.target.split_once(':').unwrap_or((&args.target, "."));
    let token = resolve_target(target).await?;
    let session = Client::connect(token, &client_options(cli)).await?;
    let stream = session.dial_port(22).await?;
    let client = crate::file_client::FileClient::connect(stream).await?;
    client.list(path, args.long).await?;
    client.close().await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RemotePath<'a> {
    user: Option<&'a str>,
    target: &'a str,
    path: &'a str,
}

fn parse_remote_path(value: &str) -> Option<RemotePath<'_>> {
    let (host, path) = value.split_once(':')?;
    let (user, target) = host
        .split_once('@')
        .map_or((None, host), |(user, target)| (Some(user), target));
    (has_token_prefix(target) || target.contains('.')).then_some(RemotePath { user, target, path })
}

fn normalize_listen_address(value: &str) -> Result<String> {
    if let Ok(port) = value.parse::<u16>() {
        return Ok(format!("127.0.0.1:{port}"));
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 0).to_string());
    }
    if let Some(port) = value.strip_prefix(':') {
        port.parse::<u16>()
            .with_context(|| format!("invalid SOCKS listen address {value:?}"))?;
        return Ok(format!("0.0.0.0:{port}"));
    }
    if value.is_empty() {
        return Ok("0.0.0.0:0".to_owned());
    }
    if value.rsplit_once(':').is_some() {
        return Ok(value.to_owned());
    }
    Ok(format!("{value}:0"))
}

async fn serve_socks(
    listener: TcpListener,
    fixed: Option<Arc<Client>>,
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
    fixed: Option<Arc<Client>>,
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
    let (session, destination) = if matches!(host.as_str(), "server.etcat" | "server.tailcat" | "")
    {
        (
            fixed.as_deref().context(
                "the server magic hostname requires a fixed token argument to 'etcat socks'",
            )?,
            Destination::ServerPort { port },
        )
    } else if let Ok(token) = decode_token(&host) {
        dynamic = Client::connect(token, options).await?;
        (&dynamic, Destination::ServerPort { port })
    } else {
        let session = fixed
            .as_deref()
            .context("exit-node destinations require a fixed connection token")?;
        (session, Destination::ExitNode { host, port })
    };

    match session.connect_destination(destination).await {
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
        return Ok(Destination::ServerPort { port: 1 });
    };
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
    let options = client_options(cli);
    tokio::time::timeout(timeout, async move {
        let session = Client::connect(token, &options).await?;
        loop {
            let info = session.ping().await?;
            let elapsed = info.round_trip.as_secs_f64() * 1_000.0;
            let direct = info.path == ConnectionPath::Direct;
            match info.path {
                ConnectionPath::Direct => println!("pong in {elapsed:.1}ms via direct"),
                ConnectionPath::Relay { region } => {
                    println!("pong in {elapsed:.1}ms via shared relay ({region})");
                }
            }
            if direct || !until_direct {
                session.stop().await;
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .with_context(|| format!("no suitable path to the server after {timeout:?}"))?
}

fn expiry_from_ttl(value: Option<&str>) -> Result<Option<i64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(Some(expiry_from_ttl_at(value, now)?))
}

fn expiry_from_ttl_at(value: &str, now: Duration) -> Result<i64> {
    let ttl = humantime::parse_duration(value).context("invalid --ttl")?;
    anyhow::ensure!(
        ttl >= Duration::from_secs(1),
        "--ttl must be at least one second"
    );
    let deadline = now.checked_add(ttl).context("--ttl is too large")?;
    let expiry = deadline
        .as_secs()
        .checked_add(u64::from(deadline.subsec_nanos() != 0))
        .context("--ttl is too large")?;
    i64::try_from(expiry).context("--ttl is too large")
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
    if has_token_prefix(value) {
        return decode_token(value);
    }
    validate_dns_target(value)?;
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
        let text = text.trim();
        if let Some(token) = text
            .strip_prefix("etcat=")
            .or_else(|| text.strip_prefix("tailcat="))
        {
            return decode_token(token.trim());
        }
    }
    anyhow::bail!("no 'etcat=' or 'tailcat=' TXT record found for {value:?}")
}

fn validate_dns_target(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.contains('.'),
        "argument is neither an etc2 connection token nor a DNS name"
    );
    anyhow::ensure!(
        !value.trim_end_matches('.').split('.').any(|label| {
            label
                .get(..crate::token::TOKEN_PREFIX.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(crate::token::TOKEN_PREFIX))
        }),
        "refusing DNS lookup because the name contains an etc2 connection token"
    );
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')),
        "DNS name contains unsupported characters"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[cfg(unix)]
    #[test]
    fn address_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("address");
        write_private_token(&path, "etc2secret").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "etc2secret");
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn socks_listen_addresses_match_tailcat_forms() {
        assert_eq!(normalize_listen_address("1080").unwrap(), "127.0.0.1:1080");
        assert_eq!(
            normalize_listen_address("127.0.0.1").unwrap(),
            "127.0.0.1:0"
        );
        assert_eq!(normalize_listen_address(":1080").unwrap(), "0.0.0.0:1080");
        assert_eq!(
            normalize_listen_address("localhost").unwrap(),
            "localhost:0"
        );
        assert_eq!(normalize_listen_address("").unwrap(), "0.0.0.0:0");
    }

    #[test]
    fn default_and_ssh_connections_use_server_ports() {
        assert_eq!(
            parse_destination(None).unwrap(),
            Destination::ServerPort { port: 1 }
        );
        assert_eq!(
            parse_destination(Some("22")).unwrap(),
            Destination::ServerPort { port: 22 }
        );
        assert!(parse_destination(Some("ssh")).is_err());
    }

    #[test]
    fn refuses_to_leak_multilabel_tokens_to_dns() {
        assert!(validate_dns_target("alias.example.com").is_ok());
        assert!(validate_dns_target("alias.example.com.").is_ok());
        assert!(validate_dns_target("prefix.etc2secret.part.example.com").is_err());
        assert!(validate_dns_target("prefix.etc2secret.part.example.com.").is_err());
        assert!(validate_dns_target("prefix.ETC2SECRET.part.example.com").is_err());
    }

    #[test]
    fn recognizes_only_token_or_dns_scp_paths_as_remote() {
        assert_eq!(
            parse_remote_path("user@etc2abc:path"),
            Some(RemotePath {
                user: Some("user"),
                target: "etc2abc",
                path: "path",
            })
        );
        assert_eq!(
            parse_remote_path("files.example:path").unwrap().target,
            "files.example"
        );
        assert_eq!(parse_remote_path("C:\\local\\file"), None);
    }

    #[test]
    fn parses_file_service_roots_and_modes() {
        assert_eq!(
            parse_file_spec("/srv/public:rw").unwrap(),
            (
                PathBuf::from("/srv/public"),
                crate::file_service::FileMode::ReadWrite
            )
        );
        assert_eq!(
            parse_file_spec(".").unwrap(),
            (PathBuf::from("."), crate::file_service::FileMode::ReadOnly)
        );
        assert_eq!(
            parse_file_spec("C:\\drop").unwrap(),
            (
                PathBuf::from("C:\\drop"),
                crate::file_service::FileMode::ReadOnly
            )
        );
        assert_eq!(
            parse_file_spec("a:rw").unwrap(),
            (PathBuf::from("a"), crate::file_service::FileMode::ReadWrite)
        );
        assert!(parse_file_spec("/srv/public:invalid").is_err());
    }

    #[test]
    fn recv_preserves_root_security_options() {
        let cli = Cli::try_parse_from([
            "etcat",
            "--allow=etcp1client",
            "--full-address",
            "--ttl=15m",
            "recv",
            "--accept-dirs",
            "incoming",
        ])
        .unwrap();
        let Some(Command::Recv(args)) = cli.command.as_ref() else {
            panic!("expected recv command")
        };
        let options = recv_server_options(args, &cli);
        assert_eq!(options.allow, ["etcp1client"]);
        assert!(options.full_address);
        assert_eq!(options.ttl.as_deref(), Some("15m"));
        assert_eq!(options.files.as_deref(), Some("incoming:wo+"));
    }

    #[test]
    fn explicit_commands_with_dots_are_executable_targets() {
        let executable = std::env::current_exe().unwrap();
        assert_eq!(
            resolve_executable(&executable.display().to_string()),
            Some(executable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_lookup_requires_execute_permission() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("tool.with-dot");
        std::fs::write(&executable, "#!/bin/sh\n").unwrap();

        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&executable, permissions.clone()).unwrap();
        assert_eq!(resolve_executable(&executable.display().to_string()), None);

        permissions.set_mode(0o700);
        std::fs::set_permissions(&executable, permissions).unwrap();
        assert_eq!(
            resolve_executable(&executable.display().to_string()),
            Some(executable)
        );
    }

    #[test]
    fn subsecond_ttl_is_rejected() {
        assert!(expiry_from_ttl(Some("500ms")).is_err());
        assert!(expiry_from_ttl(Some("1s")).unwrap().is_some());
    }

    #[test]
    fn ttl_deadline_is_rounded_up() {
        assert_eq!(
            expiry_from_ttl_at("1s", Duration::new(100, 999_000_000)).unwrap(),
            102
        );
        assert_eq!(
            expiry_from_ttl_at("1s", Duration::from_secs(100)).unwrap(),
            101
        );
    }

    #[test]
    fn allow_none_issues_no_usable_credentials() {
        let cli = Cli::try_parse_from(["etcat", "--allow=none"]).unwrap();
        let material = ServerMaterial {
            identity: PrivateServerIdentity::generate(),
            credential_secret: generate_credential_secret(),
            relays: vec![Relay {
                id: "test".to_owned(),
                region: "test".to_owned(),
                endpoints: vec!["tcp://127.0.0.1:11010".parse().unwrap()],
                probe: "127.0.0.1:11010".to_owned(),
                public_key: None,
                priority: 0,
                token_id: None,
            }],
            saved_gateway_port: None,
            saved_key_name: None,
        };

        let (credentials, _, authentication_keys) = prepare_credentials_and_token(
            &cli.allow,
            cli.full_address,
            &material,
            &material.relays[0],
            49_152,
            None,
        )
        .unwrap();
        assert!(credentials.is_empty());
        assert!(authentication_keys.is_empty());
    }

    #[test]
    fn resolved_sealed_tokens_remain_decryptable() {
        let private_key = generate_client_key();
        let public_key = client_public_key(&private_key).unwrap();
        let cli = Cli::try_parse_from(["etcat", &format!("--allow={public_key}")]).unwrap();
        let registry = RelayRegistry::load(None).unwrap();
        let relay = Relay {
            id: "test".to_owned(),
            region: "test".to_owned(),
            endpoints: vec!["tcp://127.0.0.1:11010".parse().unwrap()],
            probe: "127.0.0.1:11010".to_owned(),
            public_key: None,
            priority: 0,
            token_id: Some(1),
        };
        let material = ServerMaterial {
            identity: PrivateServerIdentity::generate(),
            credential_secret: generate_credential_secret(),
            relays: vec![relay],
            saved_gateway_port: None,
            saved_key_name: None,
        };
        let (_, token, _) = prepare_credentials_and_token(
            &cli.allow,
            cli.full_address,
            &material,
            &material.relays[0],
            49_152,
            None,
        )
        .unwrap();
        let encoded = token.encode().unwrap();
        assert!(
            encoded.len() <= 160,
            "sealed token is {} characters",
            encoded.len()
        );
        let resolved = ConnectionToken::decode(&encoded)
            .unwrap()
            .resolve(&registry)
            .unwrap();
        let CredentialEnvelope::Sealed { recipients } = &resolved.credential else {
            panic!("expected sealed credential")
        };

        crate::crypto::open_credential(
            &private_key,
            &recipients[0],
            &resolved.credential_aad().unwrap(),
        )
        .unwrap();
    }
}
