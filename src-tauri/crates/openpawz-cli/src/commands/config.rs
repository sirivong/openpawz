use crate::OutputFormat;
use clap::Subcommand;
use openpawz_core::engine::sessions::SessionStore;

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show current engine configuration
    Get,
    /// Set a configuration value
    Set {
        /// Configuration key (e.g. "default_model", "daily_budget_usd")
        key: String,
        /// New value
        value: String,
    },
}

pub fn run(
    store: &SessionStore,
    action: ConfigAction,
    format: &OutputFormat,
) -> Result<(), String> {
    match action {
        ConfigAction::Get => {
            let config_json = store
                .get_config("engine_config")
                .map_err(|e| e.to_string())?;
            match config_json {
                Some(json) => {
                    match format {
                        OutputFormat::Json | OutputFormat::Human => {
                            // Pretty-print the JSON
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json) {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&parsed)
                                        .map_err(|e| e.to_string())?
                                );
                            } else {
                                println!("{}", json);
                            }
                        }
                        OutputFormat::Quiet => println!("{}", json),
                    }
                }
                None => match format {
                    OutputFormat::Quiet => {}
                    _ => println!("No engine configuration found. Run `openpawz setup` first."),
                },
            }
            Ok(())
        }
        ConfigAction::Set { key, value } => {
            // Load existing config, patch the key, save back
            let config_json = store
                .get_config("engine_config")
                .map_err(|e| e.to_string())?
                .unwrap_or_else(|| "{}".to_string());

            let mut config: serde_json::Value =
                serde_json::from_str(&config_json).map_err(|e| e.to_string())?;

            // Try to parse value as JSON first, fall back to string
            let parsed_value: serde_json::Value =
                serde_json::from_str(&value).unwrap_or(serde_json::Value::String(value.clone()));

            config[&key] = parsed_value;

            let updated = serde_json::to_string(&config).map_err(|e| e.to_string())?;
            store
                .set_config("engine_config", &updated)
                .map_err(|e| e.to_string())?;

            match format {
                OutputFormat::Quiet => {}
                _ => println!("Set {} = {}", key, value),
            }
            Ok(())
        }
    }
}
