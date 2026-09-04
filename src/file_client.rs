use std::{sync::Arc, time::UNIX_EPOCH};

use anyhow::{Context, Result};
use russh::{client, keys::PublicKeyOrCertificate};
use russh_sftp::client::SftpSession;
use tokio::net::TcpStream;

pub(crate) struct FileClient {
    ssh: client::Handle<TrustTunnelIdentity>,
    sftp: SftpSession,
}

impl FileClient {
    pub(crate) async fn connect(stream: TcpStream) -> Result<Self> {
        let mut ssh = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            TrustTunnelIdentity,
        )
        .await
        .context("failed to start SSH over the etcat tunnel")?;
        anyhow::ensure!(
            ssh.authenticate_none("etcat").await?.success(),
            "file service rejected SSH authentication"
        );
        let channel = ssh.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .context("failed to start the SFTP subsystem")?;
        Ok(Self { ssh, sftp })
    }

    pub(crate) async fn list(&self, path: &str, long: bool) -> Result<()> {
        let metadata = self
            .sftp
            .metadata(path)
            .await
            .with_context(|| format!("failed to stat remote path {path:?}"))?;
        if !metadata.is_dir() {
            print_entry(path, &metadata, long);
            return Ok(());
        }

        let mut entries = self
            .sftp
            .read_dir(path)
            .await
            .with_context(|| format!("failed to list remote directory {path:?}"))?
            .collect::<Vec<_>>();
        entries.sort_by_key(russh_sftp::client::fs::DirEntry::file_name);
        for entry in entries {
            print_entry(&entry.file_name(), &entry.metadata(), long);
        }
        Ok(())
    }

    pub(crate) async fn close(self) -> Result<()> {
        self.sftp.close().await?;
        self.ssh
            .disconnect(russh::Disconnect::ByApplication, "done", "en-US")
            .await?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct TrustTunnelIdentity;

impl client::Handler for TrustTunnelIdentity {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool> {
        // The signed gateway handshake has already authenticated the endpoint.
        Ok(true)
    }
}

fn print_entry(name: &str, metadata: &russh_sftp::client::fs::Metadata, long: bool) {
    if !long {
        println!("{name}");
        return;
    }
    let kind = if metadata.is_dir() {
        'd'
    } else if metadata.is_symlink() {
        'l'
    } else {
        '-'
    };
    let permissions = metadata.permissions();
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_secs());
    println!(
        "{kind}{permissions} {:>5} {:>5} {:>10} {:>10} {name}",
        metadata.uid.unwrap_or(0),
        metadata.gid.unwrap_or(0),
        metadata.len(),
        modified,
    );
}
