use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use russh::{
    Channel, ChannelId,
    keys::{Algorithm, PrivateKey},
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{ChildStdin, Command},
};

pub async fn serve(stream: tokio::net::TcpStream) -> Result<()> {
    let host_key = PrivateKey::random(&mut rand10::rng(), Algorithm::Ed25519)
        .context("failed to generate ephemeral SSH host key")?;
    let config = Arc::new(server::Config {
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(Duration::from_secs(24 * 60 * 60)),
        keys: vec![host_key],
        ..Default::default()
    });
    server::run_stream(
        config,
        stream,
        ShellHandler {
            inputs: HashMap::new(),
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
    inputs: HashMap<ChannelId, ProcessInput>,
    pty_sizes: HashMap<ChannelId, PtySize>,
    pty_masters: HashMap<ChannelId, Box<dyn MasterPty>>,
    killers: HashMap<ChannelId, Box<dyn ChildKiller + Send + Sync>>,
    tasks: HashMap<ChannelId, tokio::task::AbortHandle>,
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

        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned());
        let mut process = Command::new(shell);
        if let Some(command) = command {
            process.args(["-c", command]);
        } else {
            process.arg("-i");
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
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned());
        let mut process = CommandBuilder::new(shell);
        if let Some(command) = command {
            process.args(["-c", command]);
        } else {
            process.arg("-i");
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
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<()> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<()> {
        self.pty_sizes.insert(
            channel,
            pty_size(col_width, row_height, pix_width, pix_height),
        );
        session.channel_success(channel)?;
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
        self.start_process(channel, None, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        let command = std::str::from_utf8(data).context("SSH command is not UTF-8")?;
        self.start_process(channel, Some(command), session)
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

    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> Result<()> {
        self.inputs.remove(&channel);
        self.pty_masters.remove(&channel);
        self.pty_sizes.remove(&channel);
        if let Some(mut killer) = self.killers.remove(&channel) {
            let _ = killer.kill();
        }
        if let Some(task) = self.tasks.remove(&channel) {
            task.abort();
        }
        Ok(())
    }
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
