use clap::{Parser, Subcommand};

#[derive(Subcommand)]
pub enum Command {
    /** Run service */
    Run { config: String },
    /** Useful tools */
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },
}

#[derive(Subcommand)]
pub enum ToolsCommand {
    /** Generate a UUID */
    Uuid,
    /** Generate a random */
    Rand {
        length: usize,
        #[arg(long)]
        base64: bool,
        #[arg(long)]
        hex: bool,
    },
}

#[derive(Parser)]
#[command(version)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}
