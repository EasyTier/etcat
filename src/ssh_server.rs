use std::{
    collections::HashMap,
    fs,
    io::{Read as _, Write as _},
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use russh::{
    Channel, ChannelId, Sig,
    keys::{Algorithm, PrivateKey, load_secret_key, ssh_key::LineEnding},
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{ChildStdin, Command},
};

pub async fn serve(
    stream: tokio::net::TcpStream,
    shell_enabled: bool,
    file_service: Option<crate::file_service::FileService>,
) -> Result<()> {
    let host_key = load_or_create_host_key()?;
    serve_with_host_key(stream, shell_enabled, file_service, host_key).await
}

async fn serve_with_host_key(
    stream: tokio::net::TcpStream,
    shell_enabled: bool,
    file_service: Option<crate::file_service::FileService>,
    host_key: PrivateKey,
) -> Result<()> {
    let file_service = match file_service {
        Some(service) => Some(SftpService::Rooted(service)),
        None if shell_enabled => Some(SftpService::Full(
            crate::full_file_service::FullFileService::new()
                .context("failed to start unrestricted SSH file service")?,
        )),
        None => None,
    };
    let config = Arc::new(server::Config {
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(Duration::from_hours(24)),
        keys: vec![host_key],
        ..Default::default()
    });
    server::run_stream(
        config,
        stream,
        ShellHandler {
            shell_enabled,
            file_service,
            channels: HashMap::new(),
            inputs: HashMap::new(),
            environments: HashMap::new(),
            pty_sizes: HashMap::new(),
            pty_masters: HashMap::new(),
            killers: HashMap::new(),
            tasks: HashMap::new(),
        },
    )
    .await?
    .await?;
    Ok(())
}

struct ShellHandler {
    shell_enabled: bool,
    file_service: Option<SftpService>,
    channels: HashMap<ChannelId, Channel<Msg>>,
    inputs: HashMap<ChannelId, ProcessInput>,
    environments: HashMap<ChannelId, HashMap<String, String>>,
    pty_sizes: HashMap<ChannelId, PtySize>,
    pty_masters: HashMap<ChannelId, Box<dyn MasterPty>>,
    killers: HashMap<ChannelId, Box<dyn ChildKiller + Send + Sync>>,
    tasks: HashMap<ChannelId, tokio::task::AbortHandle>,
}

#[derive(Clone, Debug)]
enum SftpService {
    Rooted(crate::file_service::FileService),
    Full(crate::full_file_service::FullFileService),
}

enum ProcessInput {
    Pipe(ChildStdin),
    Pty(tokio::sync::mpsc::UnboundedSender<Vec<u8>>),
}

impl ShellHandler {
    fn start_process(
        &mut self,
        channel: ChannelId,
        command: Option<&str>,
        session: &mut Session,
    ) -> Result<()> {
        if let Some(size) = self.pty_sizes.get(&channel).copied() {
            return self.start_pty_process(channel, command, size, session);
        }

        let shell = default_shell();
        let mut process = Command::new(shell);
        configure_shell_command(&mut process, command);
        if let Some(environment) = self.environments.get(&channel) {
            process.envs(environment);
        }
        let mut child = process
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("failed to start the user's shell")?;
        let input = child.stdin.take().context("shell has no stdin")?;
        let output = child.stdout.take().context("shell has no stdout")?;
        let error = child.stderr.take().context("shell has no stderr")?;
        self.inputs.insert(channel, ProcessInput::Pipe(input));
        session.channel_success(channel)?;

        let handle = session.handle();
        let task = tokio::spawn(async move {
            let output_task = tokio::spawn(pump_output(output, handle.clone(), channel, None));
            let error_task = tokio::spawn(pump_output(error, handle.clone(), channel, Some(1)));
            let status = child.wait().await;
            let _ = output_task.await;
            let _ = error_task.await;
            let code = status
                .ok()
                .and_then(|status| status.code())
                .and_then(|code| u32::try_from(code).ok())
                .unwrap_or(255);
            let _ = handle.exit_status_request(channel, code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        self.tasks.insert(channel, task.abort_handle());
        Ok(())
    }

    fn start_pty_process(
        &mut self,
        channel: ChannelId,
        command: Option<&str>,
        size: PtySize,
        session: &mut Session,
    ) -> Result<()> {
        let pair = native_pty_system()
            .openpty(size)
            .context("failed to allocate a pseudo-terminal")?;
        let shell = default_shell();
        let mut process = CommandBuilder::new(shell);
        configure_pty_shell_command(&mut process, command);
        if let Some(environment) = self.environments.get(&channel) {
            for (name, value) in environment {
                process.env(name, value);
            }
        }
        let mut child = pair
            .slave
            .spawn_command(process)
            .context("failed to start the user's shell in a pseudo-terminal")?;
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader()?;
        let mut writer = pair.master.take_writer()?;
        let killer = child.clone_killer();
        let (input, mut input_receiver) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        self.inputs.insert(channel, ProcessInput::Pty(input));
        self.pty_masters.insert(channel, pair.master);
        self.killers.insert(channel, killer);
        session.channel_success(channel)?;

        let handle = session.handle();
        let runtime = tokio::runtime::Handle::current();
        let output_task = tokio::task::spawn_blocking(move || {
            let mut buffer = vec![0_u8; 16 * 1024];
            while let Ok(count) = reader.read(&mut buffer) {
                if count == 0
                    || runtime
                        .block_on(handle.data(channel, buffer[..count].to_vec()))
                        .is_err()
                {
                    break;
                }
            }
        });
        tokio::task::spawn_blocking(move || {
            while let Some(data) = input_receiver.blocking_recv() {
                if writer.write_all(&data).is_err() || writer.flush().is_err() {
                    break;
                }
            }
        });
        let handle = session.handle();
        let task = tokio::spawn(async move {
            let status = tokio::task::spawn_blocking(move || child.wait()).await;
            let _ = output_task.await;
            let code = status
                .ok()
                .and_then(Result::ok)
                .map_or(255, |status| status.exit_code());
            let _ = handle.exit_status_request(channel, code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        self.tasks.insert(channel, task.abort_handle());
        Ok(())
    }
}

impl server::Handler for ShellHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<()> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<()> {
        if !self.shell_enabled {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.pty_sizes.insert(
            channel,
            pty_size(col_width, row_height, pix_width, pix_height),
        );
        self.environments
            .entry(channel)
            .or_default()
            .insert("TERM".to_owned(), term.to_owned());
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<()> {
        if !self.shell_enabled {
            session.channel_failure(channel)?;
            return Ok(());
        }
        if matches!(variable_name, "TERM" | "LANG") || variable_name.starts_with("LC_") {
            self.environments
                .entry(channel)
                .or_default()
                .insert(variable_name.to_owned(), variable_value.to_owned());
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<()> {
        let size = pty_size(col_width, row_height, pix_width, pix_height);
        self.pty_sizes.insert(channel, size);
        if let Some(master) = self.pty_masters.get(&channel) {
            master.resize(size)?;
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<()> {
        if !self.shell_enabled {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.start_process(channel, None, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        if !self.shell_enabled {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let command = std::str::from_utf8(data).context("SSH command is not UTF-8")?;
        self.start_process(channel, Some(command), session)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<()> {
        let Some(file_service) = self.file_service.clone().filter(|_| name == "sftp") else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        let channel_stream = self
            .channels
            .remove(&channel)
            .context("SFTP channel is unavailable")?
            .into_stream();
        session.channel_success(channel)?;
        match file_service {
            SftpService::Rooted(service) => {
                tokio::spawn(async move {
                    russh_sftp::server::run(channel_stream, service.session()).await;
                });
            }
            SftpService::Full(service) => {
                tokio::spawn(async move {
                    russh_sftp::server::run(channel_stream, service.session()).await;
                });
            }
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<()> {
        if let Some(input) = self.inputs.get_mut(&channel) {
            match input {
                ProcessInput::Pipe(input) => input.write_all(data).await?,
                ProcessInput::Pty(input) => input
                    .send(data.to_vec())
                    .map_err(|_| anyhow::anyhow!("pseudo-terminal input is closed"))?,
            }
        }
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, _session: &mut Session) -> Result<()> {
        if let Some(ProcessInput::Pipe(mut input)) = self.inputs.remove(&channel) {
            input.shutdown().await?;
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<()> {
        if matches!(signal, Sig::INT)
            && let Some(ProcessInput::Pty(input)) = self.inputs.get(&channel)
        {
            let _ = input.send(vec![3]);
        } else if matches!(signal, Sig::KILL | Sig::TERM)
            && let Some(killer) = self.killers.get_mut(&channel)
        {
            let _ = killer.kill();
        }
        Ok(())
    }

    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> Result<()> {
        self.inputs.remove(&channel);
        self.channels.remove(&channel);
        self.pty_masters.remove(&channel);
        self.pty_sizes.remove(&channel);
        self.environments.remove(&channel);
        if let Some(mut killer) = self.killers.remove(&channel) {
            let _ = killer.kill();
        }
        if let Some(task) = self.tasks.remove(&channel) {
            task.abort();
        }
        Ok(())
    }
}

fn default_shell() -> String {
    #[cfg(unix)]
    {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned())
    }
    #[cfg(windows)]
    {
        "powershell.exe".to_owned()
    }
}

fn configure_shell_command(command: &mut Command, requested: Option<&str>) {
    #[cfg(unix)]
    if let Some(requested) = requested {
        command.args(["-c", requested]);
    } else {
        command.arg("-i");
    }

    #[cfg(windows)]
    if let Some(requested) = requested {
        command.args(["-NoLogo", "-NoProfile", "-Command", requested]);
    } else {
        command.arg("-NoLogo");
    }
}

fn configure_pty_shell_command(command: &mut CommandBuilder, requested: Option<&str>) {
    #[cfg(unix)]
    if let Some(requested) = requested {
        command.args(["-c", requested]);
    } else {
        command.arg("-i");
    }

    #[cfg(windows)]
    if let Some(requested) = requested {
        command.args(["-NoLogo", "-NoProfile", "-Command", requested]);
    } else {
        command.arg("-NoLogo");
    }
}

fn load_or_create_host_key() -> Result<PrivateKey> {
    let path = ssh_host_key_path()?;
    if path.exists() {
        return load_secret_key(&path, None)
            .with_context(|| format!("failed to load SSH host key {}", path.display()));
    }
    let parent = path.parent().context("SSH host key path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let key = PrivateKey::random(&mut rand10::rng(), Algorithm::Ed25519)
        .context("failed to generate SSH host key")?;
    let encoded = key
        .to_openssh(LineEnding::LF)
        .context("failed to encode SSH host key")?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(encoded.as_bytes())?;
            file.sync_all()?;
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            load_secret_key(&path, None)
                .with_context(|| format!("failed to load SSH host key {}", path.display()))
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to create SSH host key {}", path.display()))
        }
    }
}

fn ssh_host_key_path() -> Result<PathBuf> {
    let key_dir = crate::key::key_dir()?;
    Ok(key_dir
        .parent()
        .context("key directory has no parent")?
        .join("ssh_host_ed25519"))
}

fn pty_size(col_width: u32, row_height: u32, pix_width: u32, pix_height: u32) -> PtySize {
    PtySize {
        rows: u16::try_from(row_height).unwrap_or(u16::MAX),
        cols: u16::try_from(col_width).unwrap_or(u16::MAX),
        pixel_width: u16::try_from(pix_width).unwrap_or(u16::MAX),
        pixel_height: u16::try_from(pix_height).unwrap_or(u16::MAX),
    }
}

async fn pump_output(
    mut input: impl AsyncRead + Unpin,
    handle: server::Handle,
    channel: ChannelId,
    extended: Option<u32>,
) {
    let mut buffer = vec![0_u8; 16 * 1024];
    while let Ok(count) = input.read(&mut buffer).await {
        if count == 0 {
            break;
        }
        let data = buffer[..count].to_vec();
        let result = if let Some(code) = extended {
            handle
                .extended_data(channel, code, data)
                .await
                .map_err(drop)
        } else {
            handle.data(channel, data).await.map_err(drop)
        };
        if result.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[tokio::test]
    async fn files_only_server_runs_the_sftp_subsystem() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("visible.txt"), "visible").unwrap();
        let service = crate::file_service::FileService::new(
            directory.path(),
            crate::file_service::FileMode::ReadOnly,
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let key = PrivateKey::random(&mut rand10::rng(), Algorithm::Ed25519).unwrap();
            serve_with_host_key(stream, false, Some(service), key).await
        });

        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let client = crate::file_client::FileClient::connect(stream)
            .await
            .unwrap();
        client.list(".", false).await.unwrap();
        client.close().await.unwrap();
        server.await.unwrap().unwrap();
    }
}
