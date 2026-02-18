use simulator::{basic_sim, fallback_sim};

pub mod cli;
use cli::cli_app;

fn main() {
    let matches = cli_app().get_matches();
    match matches.subcommand_name() {
        Some("basic-sim") => match basic_sim::run_basic_sim(&matches) {
            Ok(()) => println!("Simulation exited successfully"),
            Err(e) => {
                eprintln!("Simulation exited with error: {}", e);
                std::process::exit(1)
            }
        },
        Some("fallback-sim") => match fallback_sim::run_fallback_sim(&matches) {
            Ok(()) => println!("Simulation exited successfully"),
            Err(e) => {
                eprintln!("Simulation exited with error: {}", e);
                std::process::exit(1)
            }
        },
        _ => {
            eprintln!("Invalid subcommand. Use --help to see available options");
            std::process::exit(1)
        }
    }
}
