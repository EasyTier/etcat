use std::{net::IpAddr, process::Command};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::cli::Cli;

pub fn destination(value: Option<&str>) -> String {
    value.map_or_else(
        || "22".to_owned(),
        |value| {
            value.parse::<IpAddr>().map_or_else(
                |_| value.to_owned(),
                |ip| std::net::SocketAddr::new(ip, 22).to_string(),
            )
        },
    )
}

pub fn host_alias(target: &str) -> String {
    let hash = Sha256::digest(target.as_bytes());
    format!("etcat-{}", hex::encode(&hash[..8]))
}

pub fn configure(command: &mut Command, cli: &Cli, target: &str, destination: &str) -> Result<()> {
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
    proxy_arguments.push(destination.to_owned());
    let proxy_command = proxy_arguments
        .iter()
        .map(|argument| quote_proxy_argument(argument))
        .collect::<Result<Vec<_>>>()?
        .join(" ");

    command.args([
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
    ]);
    Ok(())
}

pub fn launch(mut command: Command, program: &str) -> Result<()> {
    command
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        let error = command.exec();
        Err(error).with_context(|| format!("failed to run the system OpenSSH {program} client"))
    }

    #[cfg(windows)]
    {
        let status = command
            .status()
            .with_context(|| format!("failed to run the system OpenSSH {program} client"))?;
        std::process::exit(status.code().unwrap_or(255));
    }
}

#[cfg(unix)]
fn quote_proxy_argument(value: &str) -> Result<String> {
    anyhow::ensure!(!value.contains('\0'), "ProxyCommand argument contains NUL");
    let value = value.replace('%', "%%");
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

#[cfg(windows)]
fn quote_proxy_argument(value: &str) -> Result<String> {
    anyhow::ensure!(
        !value
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n' | '"' | '%' | '!')),
        "ProxyCommand argument contains a character that is unsafe for Windows OpenSSH"
    );
    Ok(format!("\"{value}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_ip_destination_defaults_to_ssh_port() {
        assert_eq!(destination(Some("192.0.2.1")), "192.0.2.1:22");
        assert_eq!(destination(Some("2001:db8::1")), "[2001:db8::1]:22");
        assert_eq!(destination(Some("2222")), "2222");
        assert_eq!(destination(None), "22");
    }

    #[cfg(unix)]
    #[test]
    fn proxy_arguments_quote_shell_and_ssh_expansion() {
        assert_eq!(quote_proxy_argument("a'b%c").unwrap(), "'a'\\''b%%c'");
        assert!(quote_proxy_argument("bad\0value").is_err());
    }
}
