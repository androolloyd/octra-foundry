//! Tiny CLI over the devkey set, for shell consumers (the
//! docker/octra-node compose file and its entrypoint were generated
//! from this output; regenerate with the commands below if the set
//! ever changes — which it should not).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        // Default: the file most consumers want.
        None | Some("wallets-toml") => print!("{}", octra_devkeys::wallets_toml()),
        Some("validators-env") => println!("{}", octra_devkeys::validators_env()),
        Some("wallet-json") => {
            let Some(index) = args.get(1).and_then(|s| s.parse::<usize>().ok()) else {
                eprintln!(
                    "usage: octra-devkeys wallet-json <0..{}>",
                    octra_devkeys::ACCOUNT_COUNT - 1
                );
                return ExitCode::FAILURE;
            };
            let Some(account) = octra_devkeys::DevAccount::get(index) else {
                eprintln!("no such devkey index: {index}");
                return ExitCode::FAILURE;
            };
            println!("{}", account.node_wallet_json());
        }
        Some(other) => {
            eprintln!(
                "unknown command: {other} (try wallets-toml | validators-env | wallet-json <i>)"
            );
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
