use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    sniper::init_tracing();
    sniper::run().await
}
