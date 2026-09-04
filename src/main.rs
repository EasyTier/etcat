use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    etcat::run_cli().await
}
