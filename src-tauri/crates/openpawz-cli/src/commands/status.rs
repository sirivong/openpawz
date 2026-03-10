use crate::OutputFormat;
use openpawz_core::engine::sessions::SessionStore;

pub fn run(store: &SessionStore, format: &OutputFormat) -> Result<(), String> {
    let config_json = store
        .get_config("engine_config")
        .map_err(|e| e.to_string())?;

    let has_config = config_json.is_some();
    let has_provider = config_json
        .as_ref()
        .and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok())
        .and_then(|v| v.get("providers")?.as_array().map(|a| !a.is_empty()))
        .unwrap_or(false);

    let memory_config = store
        .get_config("memory_config")
        .map_err(|e| e.to_string())?;
    let has_memory = memory_config.is_some();

    let sessions = store
        .list_sessions_filtered(1, None)
        .map_err(|e| e.to_string())?;

    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "engine": if has_config { "configured" } else { "not configured" },
                    "provider": if has_provider { "configured" } else { "missing" },
                    "memory": if has_memory { "configured" } else { "default" },
                    "sessions": sessions.len(),
                    "data_dir": openpawz_core::engine::paths::paw_data_dir().to_string_lossy(),
                }))
                .map_err(|e| e.to_string())?
            );
        }
        _ => {
            println!("OpenPawz Engine Status");
            println!("{}", "=".repeat(40));
            println!(
                "  Engine config:  {}",
                if has_config { "OK" } else { "Not configured" }
            );
            println!(
                "  AI provider:    {}",
                if has_provider {
                    "Configured"
                } else {
                    "Missing — run `openpawz setup`"
                }
            );
            println!(
                "  Memory config:  {}",
                if has_memory { "Custom" } else { "Default" }
            );
            println!(
                "  Data directory: {}",
                openpawz_core::engine::paths::paw_data_dir().to_string_lossy()
            );
            println!(
                "  Sessions:       {}",
                if sessions.is_empty() {
                    "None".to_string()
                } else {
                    format!("{}", sessions.len())
                }
            );
        }
    }
    Ok(())
}
