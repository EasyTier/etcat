#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

mod app;
mod cli;
mod client;
mod crypto;
mod file_client;
mod file_service;
mod forward;
mod full_file_service;
mod identity;
mod key;
mod network;
mod protocol;
mod relay;
mod server;
mod service;
mod ssh_proxy;
mod ssh_server;
mod token;

use anyhow::Result;
use clap::Parser as _;

pub use client::{Client, ClientOptions, ConnectionInfo, ConnectionPath};
pub use crypto::{client_public_key, generate_client_key};
pub use file_service::{FileMode, FileService, FileServiceError, FileSession};
pub use full_file_service::{FullFileService, FullFileServiceError, FullFileSession};
pub use identity::ServerIdentity as ServerNetworkIdentity;
pub use key::{SavedClientKey as ClientKey, SavedServerKey as ServerKey};
pub use protocol::Destination;
pub use relay::{Relay, RelayRegistry};
pub use server::{IncomingConnection, Server, ServerOptions};
pub use token::{
    ConnectionToken, CredentialEnvelope, RelayLocator, SealedCredential,
    ServerIdentity as TokenServerIdentity,
};

/// Parses the process arguments and runs the etcat command-line interface.
pub async fn run_cli() -> Result<()> {
    cli::Cli::parse().run().await
}
