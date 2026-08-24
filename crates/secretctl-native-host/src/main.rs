use clap::{Parser, Subcommand};
use secretctl_native_host::{run_stdio_bridge, NativeHostManifest};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "secretctl-native-host", about = "Chrome Native Messaging Host for secretctl")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Install Chrome native messaging manifest
    Install {
        #[arg(long, default_value = "secretctl-extension-id")]
        extension_id: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Install { extension_id }) => {
            let exe_path = std::env::current_exe()?;
            let manifest = NativeHostManifest::new(exe_path, &extension_id);
            let installed_at = manifest.install(None).await?;
            println!("Installed native messaging manifest to {:?}", installed_at);
        }
        None => {
            // Default: run stdio bridge when invoked by Chrome
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let socket_path = PathBuf::from(home).join(".secretctl/run/executor.sock");
            run_stdio_bridge(socket_path).await?;
        }
    }

    Ok(())
}
