use std::{future::Future, net::IpAddr, str::FromStr};

use anyhow::{Context, Result};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
};

use crate::protocol::Destination;

const DEFAULT_BIND_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForwardMapping {
    local_port: u16,
    destination: Destination,
}

impl FromStr for ForwardMapping {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (local_port, destination) = if let Some((local, remote)) = value.split_once(':') {
            let local_port = parse_port(local, "local", value)?;
            let destination = parse_remote(remote, value)?;
            (local_port, destination)
        } else {
            let port = parse_port(value, "remote", value)?;
            (port, server_port(port, value)?)
        };
        Ok(Self {
            local_port,
            destination,
        })
    }
}

fn parse_remote(value: &str, mapping: &str) -> Result<Destination> {
    if !value.contains(':') {
        return server_port(parse_port(value, "remote", mapping)?, mapping);
    }

    let (host, port) = value
        .rsplit_once(':')
        .with_context(|| format!("invalid forward mapping {mapping:?}"))?;
    let host = if let Some(host) = host.strip_prefix('[') {
        host.strip_suffix(']').with_context(|| {
            format!("invalid bracketed IPv6 address in forward mapping {mapping:?}")
        })?
    } else {
        anyhow::ensure!(
            !host.contains(':'),
            "IPv6 addresses must be enclosed in brackets in forward mapping {mapping:?}"
        );
        host
    };
    let host = host.parse::<IpAddr>().with_context(|| {
        format!("exit-node host must be an IP address in forward mapping {mapping:?}")
    })?;
    let port = parse_port(port, "remote", mapping)?;
    anyhow::ensure!(
        port != 0,
        "remote port must be non-zero in forward mapping {mapping:?}"
    );
    Ok(Destination::ExitNode {
        host: host.to_string(),
        port,
    })
}

fn parse_port(value: &str, description: &str, mapping: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .with_context(|| format!("invalid {description} port in forward mapping {mapping:?}"))
}

fn server_port(port: u16, mapping: &str) -> Result<Destination> {
    anyhow::ensure!(
        port != 0,
        "remote port must be non-zero in forward mapping {mapping:?}"
    );
    Ok(Destination::ServerPort { port })
}

pub(crate) fn parse_mappings(values: &[String]) -> Result<Vec<ForwardMapping>> {
    anyhow::ensure!(
        !values.is_empty(),
        "at least one forward mapping is required"
    );
    values.iter().map(|value| value.parse()).collect()
}

pub(crate) async fn run<F, Fut>(
    bind_ip: Option<IpAddr>,
    mappings: Vec<ForwardMapping>,
    dial: F,
) -> Result<()>
where
    F: Fn(Destination) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<TcpStream>> + Send + 'static,
{
    anyhow::ensure!(
        !mappings.is_empty(),
        "at least one forward mapping is required"
    );
    let bind_ip = bind_ip.unwrap_or(DEFAULT_BIND_IP);
    let listeners = bind_listeners(bind_ip, mappings).await?;
    let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel();
    let mut listener_tasks = JoinSet::new();
    for (listener, destination) in listeners {
        listener_tasks.spawn(accept_connections(
            listener,
            destination,
            accepted_tx.clone(),
        ));
    }
    drop(accepted_tx);

    let mut connection_tasks = JoinSet::new();
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    let outcome = loop {
        tokio::select! {
            signal = &mut shutdown => break signal.context("failed to listen for Ctrl-C"),
            accepted = accepted_rx.recv() => {
                let Some((local, destination)) = accepted else {
                    break Err(anyhow::anyhow!("all forward listeners stopped"));
                };
                let dial = dial.clone();
                connection_tasks.spawn(proxy_connection(local, destination, dial));
            }
            result = listener_tasks.join_next() => {
                break listener_result(result);
            }
            result = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                if let Some(Ok(Err(error))) = result {
                    tracing::warn!(%error, "forwarded connection failed");
                } else if let Some(Err(error)) = result {
                    tracing::warn!(%error, "forwarded connection task failed");
                }
            }
        }
    };

    listener_tasks.abort_all();
    connection_tasks.abort_all();
    outcome
}

async fn bind_listeners(
    bind_ip: IpAddr,
    mappings: Vec<ForwardMapping>,
) -> Result<Vec<(TcpListener, Destination)>> {
    let mut listeners = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        let listener = TcpListener::bind((bind_ip, mapping.local_port))
            .await
            .with_context(|| format!("failed to bind {bind_ip}:{}", mapping.local_port))?;
        if mapping.local_port == 0 {
            println!("{}", listener.local_addr()?);
        }
        listeners.push((listener, mapping.destination));
    }
    Ok(listeners)
}

async fn accept_connections(
    listener: TcpListener,
    destination: Destination,
    accepted: mpsc::UnboundedSender<(TcpStream, Destination)>,
) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        if accepted.send((stream, destination.clone())).is_err() {
            return Ok(());
        }
    }
}

fn listener_result(result: Option<Result<Result<()>, tokio::task::JoinError>>) -> Result<()> {
    match result {
        Some(Ok(Ok(()))) | None => Err(anyhow::anyhow!("a forward listener stopped unexpectedly")),
        Some(Ok(Err(error))) => Err(error).context("forward listener failed"),
        Some(Err(error)) => Err(error).context("forward listener task failed"),
    }
}

async fn proxy_connection<F, Fut>(
    mut local: TcpStream,
    destination: Destination,
    dial: F,
) -> Result<()>
where
    F: FnOnce(Destination) -> Fut,
    Fut: Future<Output = Result<TcpStream>>,
{
    let mut remote = dial(destination).await?;
    copy_bidirectional(&mut local, &mut remote).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn parses_server_port_mappings() {
        assert_eq!(
            "8080".parse::<ForwardMapping>().unwrap(),
            ForwardMapping {
                local_port: 8080,
                destination: Destination::ServerPort { port: 8080 },
            }
        );
        assert_eq!(
            "18080:8080".parse::<ForwardMapping>().unwrap(),
            ForwardMapping {
                local_port: 18080,
                destination: Destination::ServerPort { port: 8080 },
            }
        );
        assert_eq!(
            "0:8080".parse::<ForwardMapping>().unwrap(),
            ForwardMapping {
                local_port: 0,
                destination: Destination::ServerPort { port: 8080 },
            }
        );
    }

    #[test]
    fn parses_exit_node_mappings() {
        assert_eq!(
            "13306:192.0.2.1:3306".parse::<ForwardMapping>().unwrap(),
            ForwardMapping {
                local_port: 13306,
                destination: Destination::ExitNode {
                    host: Ipv4Addr::new(192, 0, 2, 1).to_string(),
                    port: 3306,
                },
            }
        );
        assert_eq!(
            "13306:[2001:db8::1]:3306"
                .parse::<ForwardMapping>()
                .unwrap(),
            ForwardMapping {
                local_port: 13306,
                destination: Destination::ExitNode {
                    host: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).to_string(),
                    port: 3306,
                },
            }
        );
    }

    #[test]
    fn rejects_invalid_mappings() {
        for mapping in [
            "0",
            "8080:0",
            "8080:192.0.2.1:0",
            "8080:example.com:80",
            "8080:2001:db8::1:80",
            "invalid",
        ] {
            assert!(
                mapping.parse::<ForwardMapping>().is_err(),
                "{mapping:?} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn binds_an_ephemeral_listener() {
        let listeners = bind_listeners(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            vec![ForwardMapping {
                local_port: 0,
                destination: Destination::ServerPort { port: 80 },
            }],
        )
        .await
        .unwrap();
        assert_ne!(listeners[0].0.local_addr().unwrap().port(), 0);
    }

    #[tokio::test]
    async fn proxies_bytes_in_both_directions() {
        let remote_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let remote_address = remote_listener.local_addr().unwrap();
        let local_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local_address = local_listener.local_addr().unwrap();

        let proxy = tokio::spawn(async move {
            let (local, _) = local_listener.accept().await.unwrap();
            proxy_connection(
                local,
                Destination::ServerPort { port: 80 },
                move |_| async move { Ok(TcpStream::connect(remote_address).await?) },
            )
            .await
        });
        let remote = tokio::spawn(async move {
            let (mut stream, _) = remote_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let mut local = TcpStream::connect(local_address).await.unwrap();
        local.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        local.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        drop(local);

        remote.await.unwrap();
        proxy.await.unwrap().unwrap();
    }
}
