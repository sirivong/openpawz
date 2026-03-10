use crate::OutputFormat;
use clap::Subcommand;
use openpawz_core::engine::sessions::SessionStore;

#[derive(Subcommand)]
pub enum AgentAction {
    /// List all agents
    List,
    /// Show details of a specific agent
    Get {
        /// Agent ID
        id: String,
    },
    /// Create a new agent
    Create {
        /// Agent name
        #[arg(long)]
        name: String,
        /// Default model for this agent
        #[arg(long)]
        model: Option<String>,
    },
    /// Delete an agent
    Delete {
        /// Agent ID
        id: String,
    },
}

pub fn run(store: &SessionStore, action: AgentAction, format: &OutputFormat) -> Result<(), String> {
    match action {
        AgentAction::List => {
            let agents = store.list_all_agents().map_err(|e| e.to_string())?;
            match format {
                OutputFormat::Json => {
                    let json: Vec<_> = agents
                        .iter()
                        .map(|(pid, a)| {
                            serde_json::json!({
                                "project_id": pid,
                                "agent_id": a.agent_id,
                                "role": a.role,
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?
                    );
                }
                OutputFormat::Quiet => {
                    for (_, a) in &agents {
                        println!("{}", a.agent_id);
                    }
                }
                OutputFormat::Human => {
                    if agents.is_empty() {
                        println!("No agents found.");
                    } else {
                        println!("{:<20} {:<20} {:<20}", "AGENT ID", "PROJECT", "ROLE");
                        println!("{}", "-".repeat(60));
                        for (pid, a) in &agents {
                            println!("{:<20} {:<20} {:<20}", a.agent_id, pid, &a.role);
                        }
                    }
                }
            }
            Ok(())
        }
        AgentAction::Get { id } => {
            let files = store.list_agent_files(&id).map_err(|e| e.to_string())?;
            match format {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&files).map_err(|e| e.to_string())?
                    );
                }
                _ => {
                    println!("Agent: {}", id);
                    println!("Files: {}", files.len());
                    for f in &files {
                        println!("  - {} ({} bytes)", f.file_name, f.content.len());
                    }
                }
            }
            Ok(())
        }
        AgentAction::Create { name, model } => {
            let id = format!(
                "agent-{}",
                uuid::Uuid::new_v4()
                    .to_string()
                    .split('-')
                    .next()
                    .unwrap_or("x")
            );
            let agent_json = serde_json::json!({
                "id": id,
                "name": name,
                "default_model": model,
            });
            store
                .set_agent_file(&id, "identity.json", &agent_json.to_string())
                .map_err(|e| e.to_string())?;
            match format {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&agent_json).map_err(|e| e.to_string())?
                    );
                }
                _ => {
                    println!("Created agent '{}' ({})", name, id);
                }
            }
            Ok(())
        }
        AgentAction::Delete { id } => {
            let files = store.list_agent_files(&id).map_err(|e| e.to_string())?;
            for f in &files {
                store
                    .delete_agent_file(&id, &f.file_name)
                    .map_err(|e| e.to_string())?;
            }
            match format {
                OutputFormat::Quiet => {}
                _ => println!("Deleted agent '{}' ({} files removed)", id, files.len()),
            }
            Ok(())
        }
    }
}
