use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use easytier::{
    common::config::{
        ConfigLoader, ManagedCredentialConfig, NetworkIdentity, PeerConfig, PortForwardConfig,
        TomlConfig,
    },
    instance::factory::{NativeCoreInstance, create_native_instance},
};
use sha2::{Digest, Sha256};

use crate::{
    identity::{ServerIdentity, easytier_credential_secret, secure_mode},
    relay::Relay,
};

pub const CLIENT_GROUP: &str = "etcat-client";

#[derive(Debug, Clone)]
pub struct AccessPolicy {
    pub destination_ip: Ipv4Addr,
    pub ports: Vec<u16>,
}

pub struct MeshInstance {
    core: Arc<NativeCoreInstance>,
}

impl MeshInstance {
    pub async fn start(config: TomlConfig) -> Result<Self> {
        let core = create_native_instance(config).context("failed to create EasyTier instance")?;
        core.start()
            .await
            .context("failed to start EasyTier instance")?;
        Ok(Self { core })
    }

    pub fn core(&self) -> &Arc<NativeCoreInstance> {
        &self.core
    }

    pub async fn wait_for_relay_connection(&self, relay: &Relay, timeout: Duration) -> Result<()> {
        tokio::time::timeout(timeout, async {
            loop {
                if self
                    .core
                    .peer_snapshots()
                    .await
                    .iter()
                    .flat_map(|peer| &peer.conns)
                    .any(|conn| {
                        is_live_relay_connection(
                            conn.is_closed,
                            conn.is_client,
                            conn.tunnel
                                .as_ref()
                                .and_then(|tunnel| tunnel.remote_addr.as_ref())
                                .map(|remote| remote.url.as_str()),
                            relay,
                        )
                    })
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .with_context(|| {
            format!(
                "no EasyTier connection to relay {} established within {timeout:?}",
                relay.id
            )
        })
    }

    pub async fn stop(&self) {
        self.core.stop().await;
    }
}

fn is_live_relay_connection(
    is_closed: bool,
    is_client: bool,
    remote_addr: Option<&str>,
    relay: &Relay,
) -> bool {
    !is_closed
        && is_client
        && remote_addr.is_some_and(|remote| {
            relay
                .endpoints
                .iter()
                .any(|endpoint| endpoint.as_str() == remote)
        })
}

impl Drop for MeshInstance {
    fn drop(&mut self) {
        // CoreInstance also owns a cancellation token, so dropping is safe. Callers
        // that need deterministic cleanup use stop().
    }
}

pub fn server_config(
    identity: &ServerIdentity,
    relay: &Relay,
    credentials: Vec<ManagedCredentialConfig>,
    access: &AccessPolicy,
) -> Result<TomlConfig> {
    let config = base_config(
        &identity.network_name,
        identity.server_ipv4,
        &identity.hostname,
        relay,
    )?;
    config.set_network_identity(NetworkIdentity::new(
        identity.network_name.clone(),
        identity.network_secret.clone(),
    ));
    config.set_secure_mode(Some(secure_mode(&identity.private_key)?));
    config.set_managed_credentials(credentials);
    config.set_acl(Some(build_acl(access)));
    config.add_proxy_cidr(
        "127.0.0.1/32".parse()?,
        Some(format!("{}/32", identity.gateway_ipv4()).parse()?),
    )?;
    Ok(config)
}

pub fn client_config(
    network_name: &str,
    credential_secret: &str,
    client_ipv4: Ipv4Addr,
    relay: &Relay,
    forwards: Vec<PortForwardConfig>,
    socks5: Option<SocketAddr>,
) -> Result<TomlConfig> {
    let config = base_config(network_name, client_ipv4, "etcat-client", relay)?;
    let credential_secret = easytier_credential_secret(credential_secret)?;
    let digest = Sha256::digest(credential_secret.as_bytes());
    let mut instance_id = [0_u8; 16];
    instance_id.copy_from_slice(&digest[..16]);
    config.set_id(uuid::Uuid::from_bytes(instance_id));
    config.set_network_identity(NetworkIdentity::new_credential(network_name.to_owned()));
    config.set_secure_mode(Some(secure_mode(&credential_secret)?));
    config.set_acl(Some(build_client_acl()));
    config.set_port_forwards(forwards);
    if let Some(bind) = socks5 {
        config.set_socks5_portal(Some(format!("socks5://{bind}").parse()?));
    }
    Ok(config)
}

fn base_config(
    network_name: &str,
    ipv4: Ipv4Addr,
    hostname: &str,
    relay: &Relay,
) -> Result<TomlConfig> {
    let config = TomlConfig::default();
    config.set_inst_name(network_name.to_owned());
    config.set_hostname(Some(hostname.to_owned()));
    config.set_ipv4(Some(format!("{ipv4}/24").parse()?));
    config.set_listeners(vec!["tcp://0.0.0.0:0".parse()?, "udp://0.0.0.0:0".parse()?]);
    config.set_peers(
        relay
            .endpoints
            .iter()
            .cloned()
            .map(|uri| PeerConfig {
                uri,
                peer_public_key: relay.public_key.clone(),
            })
            .collect(),
    );
    let mut flags = config.get_flags();
    flags.no_tun = true;
    flags.use_smoltcp = true;
    flags.enable_encryption = true;
    flags.need_p2p = true;
    flags.bind_device = false;
    config.set_flags(flags);
    Ok(config)
}

fn build_acl(access: &AccessPolicy) -> easytier::proto::acl::Acl {
    use easytier::proto::acl::{Acl, AclV1, Action, Chain, ChainType, GroupInfo, Protocol, Rule};

    let inbound_allow = Rule {
        name: "etcat-token-inbound".to_owned(),
        description: "Allow only services attached to the issued token".to_owned(),
        priority: 1000,
        enabled: true,
        protocol: Protocol::Tcp as i32,
        ports: access.ports.iter().map(ToString::to_string).collect(),
        destination_ips: vec![format!("{}/32", access.destination_ip)],
        source_groups: vec![CLIENT_GROUP.to_owned()],
        action: Action::Allow as i32,
        stateful: true,
        ..Default::default()
    };
    let mut chains = vec![Chain {
        name: "etcat-inbound".to_owned(),
        chain_type: ChainType::Inbound as i32,
        description: "Token-scoped service access".to_owned(),
        enabled: true,
        rules: vec![inbound_allow.clone()],
        default_action: Action::Drop as i32,
    }];
    chains.push(Chain {
        name: "etcat-forward".to_owned(),
        chain_type: ChainType::Forward as i32,
        description: "Token-scoped gateway forwarding".to_owned(),
        enabled: true,
        rules: vec![Rule {
            name: "etcat-token-forward".to_owned(),
            ..inbound_allow
        }],
        default_action: Action::Drop as i32,
    });
    Acl {
        acl_v1: Some(AclV1 {
            chains,
            group: Some(GroupInfo::default()),
        }),
    }
}

fn build_client_acl() -> easytier::proto::acl::Acl {
    use easytier::proto::acl::{Acl, AclV1, Action, Chain, ChainType, GroupInfo, Protocol, Rule};

    Acl {
        acl_v1: Some(AclV1 {
            chains: vec![Chain {
                name: "etcat-admin-only".to_owned(),
                chain_type: ChainType::Outbound as i32,
                description: "Reject routes that resolve to credential peers".to_owned(),
                enabled: true,
                rules: vec![Rule {
                    name: "etcat-reject-client-destination".to_owned(),
                    description: "The gateway must be an EasyTier admin node".to_owned(),
                    priority: 1000,
                    enabled: true,
                    protocol: Protocol::Any as i32,
                    destination_groups: vec![CLIENT_GROUP.to_owned()],
                    action: Action::Drop as i32,
                    ..Default::default()
                }],
                default_action: Action::Allow as i32,
            }],
            group: Some(GroupInfo::default()),
        }),
    }
}

pub fn managed_credential(
    id: String,
    secret: &str,
    groups: Vec<String>,
    expiry_unix: i64,
) -> Result<ManagedCredentialConfig> {
    Ok(ManagedCredentialConfig {
        credential_id: id,
        credential_secret: easytier_credential_secret(secret)?,
        groups,
        allow_relay: false,
        // Credential peers consume the admin node's gateway route, but must
        // never be allowed to publish a competing route themselves.
        allowed_proxy_cidrs: Vec::new(),
        expiry_unix,
        reusable: false,
    })
}

pub fn tcp_forward(bind_port: u16, destination: SocketAddr) -> PortForwardConfig {
    PortForwardConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bind_port),
        dst_addr: destination,
        proto: "tcp".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_credential_secret;

    fn relay() -> Relay {
        Relay {
            id: "test".to_owned(),
            region: "test".to_owned(),
            endpoints: vec!["tcp://127.0.0.1:11010".parse().unwrap()],
            probe: "127.0.0.1:11010".to_owned(),
            public_key: None,
            priority: 0,
            token_id: None,
        }
    }

    #[test]
    fn configs_are_always_no_tun_and_encrypted() {
        let identity = ServerIdentity::generate();
        let config = server_config(
            &identity,
            &relay(),
            Vec::new(),
            &AccessPolicy {
                destination_ip: identity.gateway_ipv4(),
                ports: vec![80],
            },
        )
        .unwrap();
        let flags = config.get_flags();
        assert!(flags.no_tun);
        assert!(flags.use_smoltcp);
        assert!(flags.enable_encryption);

        let client = client_config(
            &identity.network_name,
            &generate_credential_secret(),
            identity.client_ipv4(2),
            &relay(),
            Vec::new(),
            None,
        )
        .unwrap();
        assert!(client.get_flags().no_tun);
        assert!(client.get_network_identity().network_secret.is_none());
        let acl = client.get_acl().unwrap().acl_v1.unwrap();
        assert_eq!(acl.chains.len(), 1);
        assert_eq!(
            acl.chains[0].rules[0].destination_groups,
            vec![CLIENT_GROUP]
        );
        assert_eq!(
            acl.chains[0].rules[0].action,
            easytier::proto::acl::Action::Drop as i32
        );
    }

    #[test]
    fn one_client_credential_keeps_one_easytier_identity() {
        let identity = ServerIdentity::generate();
        let credential = generate_credential_secret();
        let make_config = |credential: &str| {
            client_config(
                &identity.network_name,
                credential,
                identity.client_ipv4(2),
                &relay(),
                Vec::new(),
                None,
            )
            .unwrap()
        };

        assert_eq!(
            make_config(&credential).get_id(),
            make_config(&credential).get_id()
        );
        assert_ne!(
            make_config(&credential).get_id(),
            make_config(&generate_credential_secret()).get_id()
        );
    }

    #[test]
    fn relay_readiness_requires_a_live_outgoing_connection_to_that_relay() {
        let relay = relay();
        let endpoint = Some("tcp://127.0.0.1:11010");

        assert!(is_live_relay_connection(false, true, endpoint, &relay));
        assert!(!is_live_relay_connection(
            false,
            true,
            Some("tcp://127.0.0.1:22020"),
            &relay
        ));
        assert!(!is_live_relay_connection(false, false, endpoint, &relay));
        assert!(!is_live_relay_connection(true, true, endpoint, &relay));
    }

    #[test]
    fn client_credentials_cannot_advertise_proxy_routes() {
        let credential = managed_credential(
            "client".to_owned(),
            &generate_credential_secret(),
            vec![CLIENT_GROUP.to_owned()],
            i64::MAX,
        )
        .unwrap();

        assert!(credential.allowed_proxy_cidrs.is_empty());
    }
}
