mod app;
mod cli;
mod crypto;
mod identity;
mod key;
mod network;
mod protocol;
mod relay;
mod service;
#[cfg(unix)]
mod ssh_server;
mod token;

use anyhow::Result;
use clap::Parser;

use crate::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.run().await
}
