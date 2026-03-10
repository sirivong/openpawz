pub mod agent;
pub mod config;
pub mod memory;
pub mod session;
pub mod setup;
pub mod status;

use crate::OutputFormat;

/// Format a value as JSON or return None for other formats.
pub fn json_print<T: serde::Serialize>(value: &T, format: &OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(value).map_err(|e| e.to_string())?
            );
        }
        _ => {}
    }
    Ok(())
}
