use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "etcat", version, about)]
pub struct Cli {
    /// Be verbose. Repeat for `EasyTier` diagnostics.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,

    /// Use `new`, a saved key name, or a private JSON key path.
    #[arg(long, global = true)]
    pub(crate) key: Option<String>,

    /// Override the built-in relay registry.
    #[arg(long, global = true, env = "ETCAT_RELAY_FILE")]
    pub(crate) relay_file: Option<PathBuf>,

    /// Print the etcat README and exit.
    #[arg(long, global = true)]
    pub(crate) readme: bool,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,

    /// Connection token or DNS name in client mode.
    pub(crate) target: Option<String>,

    /// Server port, or IP:port when the server is an exit node.
    pub(crate) destination: Option<String>,

    /// Ports/ranges or named services: all, no-auth-ssh, exit-node, files.
    #[arg(long, value_delimiter = ',')]
    pub(crate) serve: Vec<String>,

    /// Client public keys allowed to connect, or `none` to deny every client.
    #[arg(long, value_delimiter = ',')]
    pub(crate) allow: Vec<String>,

    /// Print a self-contained token with embedded relay metadata.
    #[arg(long, visible_alias = "embed-relay-map")]
    pub(crate) full_address: bool,

    /// Print machine-readable server startup output.
    #[arg(long, global = true)]
    pub(crate) json: bool,

    /// Credential lifetime, such as 30m or 24h. The default is process-bound.
    #[arg(long)]
    pub(crate) ttl: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Serve a one-shot stream, local TCP ports, SSH, or files.
    Serve(ServeArgs),
    /// Test connectivity and show whether the path is direct.
    Ping(PingArgs),
    /// Run a command through a local SOCKS5 proxy.
    Socks(SocksArgs),
    /// Connect with the system OpenSSH client.
    Ssh(SshArgs),
    /// Forward local TCP listeners through a server.
    Forward(ForwardArgs),
    /// Receive files into a write-only directory.
    Recv(RecvArgs),
    /// Copy files through the system OpenSSH scp client.
    Cp(CpArgs),
    /// List files exposed by a server.
    Ls(LsArgs),
    /// Parse a token without connecting.
    Parse(TokenArg),
    /// Expand a registry-relative token into a self-contained token.
    Resolve(TokenArg),
    /// Generate, list, or delete persistent identities.
    Genkey(GenkeyArgs),
    /// Print the selected client identity's public key.
    Printpub,
    /// List built-in shared relays and their trust status.
    Relays,
    /// Print the program version.
    Version,
    /// Print the embedded README.
    Readme,
}

#[derive(Debug, Args)]
pub(crate) struct ServeArgs {
    /// Ports/ranges or named services: all, no-auth-ssh, exit-node, files.
    #[arg(value_delimiter = ',')]
    pub(crate) services: Vec<String>,

    /// Client public keys allowed to connect, or `none` to deny every client.
    #[arg(long, value_delimiter = ',')]
    pub(crate) allow: Vec<String>,

    /// Print a self-contained token with embedded relay metadata.
    #[arg(long, visible_alias = "embed-relay-map")]
    pub(crate) full_address: bool,

    /// Directory and access mode: DIR[:ro|rw|wo|wo+].
    #[arg(long)]
    pub(crate) files: Option<String>,

    /// Credential lifetime, such as 30m or 24h.
    #[arg(long)]
    pub(crate) ttl: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct TokenArg {
    pub(crate) token: String,
}

#[derive(Debug, Args)]
pub(crate) struct PingArgs {
    #[arg(long)]
    pub(crate) until_direct: bool,
    #[arg(long, default_value = "10s")]
    pub(crate) timeout: String,
    pub(crate) token: String,
}

#[derive(Debug, Args)]
#[command(trailing_var_arg = true)]
pub(crate) struct SocksArgs {
    #[arg(long, default_value = "127.0.0.1:0")]
    pub(crate) listen: String,
    #[arg(allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Debug, Args)]
#[command(trailing_var_arg = true)]
pub(crate) struct SshArgs {
    /// Server port, or IP/IP:port through an exit-node server.
    #[arg(short = 'p')]
    pub(crate) destination: Option<String>,
    /// Connection token or DNS name, optionally prefixed with user@.
    pub(crate) target: String,
    /// Command to run; omit it for an interactive shell.
    #[arg(allow_hyphen_values = true)]
    pub(crate) command: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ForwardArgs {
    /// Local address on which forwarded ports listen.
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) bind: String,
    /// Connection token or DNS name.
    pub(crate) target: String,
    /// PORT, LOCAL:REMOTE, or LOCAL:IP:REMOTE mappings.
    #[arg(required = true)]
    pub(crate) mappings: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RecvArgs {
    /// Accept recursive directory uploads instead of single files only.
    #[arg(long)]
    pub(crate) accept_dirs: bool,
    #[arg(default_value = ".")]
    pub(crate) directory: PathBuf,
}

#[derive(Debug, Args)]
#[command(trailing_var_arg = true)]
pub(crate) struct CpArgs {
    /// Copy directories recursively.
    #[arg(short = 'r')]
    pub(crate) recursive: bool,
    /// Preserve modification times and modes.
    #[arg(short = 'p')]
    pub(crate) preserve: bool,
    /// Server port, IP, or IP:port used by remote paths.
    #[arg(short = 'P')]
    pub(crate) destination: Option<String>,
    /// Local and TOKEN:PATH operands accepted by scp.
    #[arg(required = true, num_args = 2.., allow_hyphen_values = true)]
    pub(crate) paths: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct LsArgs {
    /// Use the long listing format.
    #[arg(short = 'l')]
    pub(crate) long: bool,
    /// Connection token or DNS name, optionally followed by `:path`.
    pub(crate) target: String,
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct GenkeyArgs {
    /// Generate or operate on a client identity instead of a server identity.
    #[arg(long)]
    pub(crate) client: bool,
    /// Replace an existing key with the same name.
    #[arg(long)]
    pub(crate) force: bool,
    /// List saved key names.
    #[arg(long)]
    pub(crate) list: bool,
    /// Delete the selected saved key.
    #[arg(long)]
    pub(crate) delete: bool,
    /// Saved key name or private JSON path. Required when generating/deleting.
    #[arg(long)]
    pub(crate) key: Option<String>,
    /// Select a relay by registry ID instead of measuring latency.
    #[arg(long, visible_alias = "region")]
    pub(crate) relay: Option<String>,
    /// Reuse the selected relay across future server restarts.
    #[arg(long, visible_alias = "fixed-region")]
    pub(crate) fixed_relay: bool,
    /// Embed relay metadata in the printed token.
    #[arg(
        long,
        visible_aliases = ["embed-relay-map", "embed-derp-map"]
    )]
    pub(crate) full_address: bool,
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        crate::app::run(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailcat_genkey_aliases_map_to_relay_options() {
        let cli =
            Cli::try_parse_from(["etcat", "genkey", "--region=auto", "--embed-derp-map"]).unwrap();
        let Some(Command::Genkey(args)) = cli.command else {
            panic!("expected genkey command")
        };
        assert_eq!(args.relay.as_deref(), Some("auto"));
        assert!(args.full_address);

        let cli = Cli::try_parse_from(["etcat", "genkey", "--fixed-region"]).unwrap();
        let Some(Command::Genkey(args)) = cli.command else {
            panic!("expected genkey command")
        };
        assert!(args.fixed_relay);
    }

    #[test]
    fn serve_accepts_multiple_and_comma_separated_services() {
        let cli = Cli::try_parse_from(["etcat", "serve", "22,8080", "9000-9010", "--files=.:ro"])
            .unwrap();
        let Some(Command::Serve(args)) = cli.command else {
            panic!("expected serve command")
        };
        assert_eq!(args.services, ["22", "8080", "9000-9010"]);
        assert_eq!(args.files.as_deref(), Some(".:ro"));
    }

    #[test]
    fn parses_forward_cp_ls_and_recv_commands() {
        let cli =
            Cli::try_parse_from(["etcat", "forward", "--bind=0.0.0.0", "etc2token", "0:8080"])
                .unwrap();
        assert!(matches!(cli.command, Some(Command::Forward(_))));

        let cli = Cli::try_parse_from(["etcat", "cp", "-rp", "local", "etc2token:path"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Cp(_))));

        let cli = Cli::try_parse_from(["etcat", "ls", "-l", "etc2token:path"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Ls(_))));

        let cli = Cli::try_parse_from(["etcat", "recv", "--accept-dirs", "."]).unwrap();
        assert!(matches!(cli.command, Some(Command::Recv(_))));
    }
}
