use std::net::SocketAddr;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "octra-mock-rpc")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:18080")]
    listen: SocketAddr,
    #[arg(long, default_value = "octPROGRAMaddress0000000000000000000000")]
    program_addr: String,
    /// Seed an explicit mock account with OU, enabling real ledger admission.
    #[arg(long, value_name = "ADDRESS=OU")]
    fund: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let accounts = cli
        .fund
        .iter()
        .map(|value| {
            let (address, amount) = value
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--fund expects ADDRESS=OU"))?;
            Ok((address.to_owned(), amount.parse::<u64>()?))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    octra_mock_rpc::serve_with_accounts(cli.listen, cli.program_addr, accounts).await
}
