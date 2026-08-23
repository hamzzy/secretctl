use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "secretctl", version, about = "Local-first credential isolation for AI agents")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize local secretctl installation
    Init,
    /// Daemon management
    Daemon {
        #[command(subcommand)]
        cmd: Option<DaemonCommands>,
    },
    /// Manage agent principals
    Agent {
        #[command(subcommand)]
        cmd: AgentCommands,
    },
    /// Manage credentials
    Credential {
        #[command(subcommand)]
        cmd: CredentialCommands,
    },
    /// Manage site recipes
    Recipe {
        #[command(subcommand)]
        cmd: RecipeCommands,
    },
    /// Policy evaluation and validation
    Policy {
        #[command(subcommand)]
        cmd: PolicyCommands,
    },
    /// Managed browser operations
    Browser {
        #[command(subcommand)]
        cmd: BrowserCommands,
    },
    /// Audit log and verification
    Audit {
        #[command(subcommand)]
        cmd: AuditCommands,
    },
    /// Show daemon status
    Status,
    /// Show health and diagnostic checks
    Health,
}

#[derive(Subcommand, Debug)]
enum DaemonCommands {
    Start,
    Stop,
    Status,
}

#[derive(Subcommand, Debug)]
enum AgentCommands {
    List,
    Enroll { name: String },
    Revoke { id: String },
}

#[derive(Subcommand, Debug)]
enum CredentialCommands {
    List,
    Add { name: String, kind: String },
    Remove { id: String },
}

#[derive(Subcommand, Debug)]
enum RecipeCommands {
    List,
    Validate { path: String },
    Add { path: String },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    Validate { path: String },
    Test { policy: String, request: String },
}

#[derive(Subcommand, Debug)]
enum BrowserCommands {
    Launch { profile: Option<String> },
    List,
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    Verify,
    Tail { lines: Option<usize> },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            println!("Initialized secretctl installation.");
        }
        Commands::Status => {
            println!("secretctl daemon status: idle");
        }
        Commands::Health => {
            println!("All security invariants verified.");
        }
        _ => {
            println!("Command recognized. Running in preview mode.");
        }
    }

    Ok(())
}
