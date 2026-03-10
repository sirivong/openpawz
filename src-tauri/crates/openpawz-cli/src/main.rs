// OpenPawz CLI — Command-line interface to the OpenPawz AI engine.
//
// Talks directly to the openpawz-core library (same Rust code as the desktop app)
// with zero network overhead. Shares the same SQLite database and config.

mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "openpawz",
    about = "OpenPawz CLI — Multi-agent AI from the terminal",
    version,
    arg_required_else_help = true
)]
struct Cli {
    /// Output format
    #[arg(long, global = true, default_value = "human")]
    output: OutputFormat,

    /// Enable verbose logging
    #[arg(long, short, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Quiet,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage agents (list, create, delete)
    Agent {
        #[command(subcommand)]
        action: commands::agent::AgentAction,
    },
    /// Manage chat sessions (list, delete, history)
    Session {
        #[command(subcommand)]
        action: commands::session::SessionAction,
    },
    /// Engine configuration (get, set)
    Config {
        #[command(subcommand)]
        action: commands::config::ConfigAction,
    },
    /// Memory operations (store, search, list)
    Memory {
        #[command(subcommand)]
        action: commands::memory::MemoryAction,
    },
    /// Engine status and diagnostics
    Status,
    /// Initial setup wizard
    Setup,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }

    // Initialize the core engine (loads DB, paths, key vault)
    openpawz_core::engine::paths::load_data_root_from_conf();

    let store = match openpawz_core::engine::sessions::SessionStore::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: Failed to open database: {}", e);
            std::process::exit(1);
        }
    };

    let result = match cli.command {
        Commands::Agent { action } => commands::agent::run(&store, action, &cli.output),
        Commands::Session { action } => commands::session::run(&store, action, &cli.output),
        Commands::Config { action } => commands::config::run(&store, action, &cli.output),
        Commands::Memory { action } => commands::memory::run(&store, action, &cli.output).await,
        Commands::Status => commands::status::run(&store, &cli.output),
        Commands::Setup => commands::setup::run(&store),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
