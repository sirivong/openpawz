// ── Unified Key Vault ──────────────────────────────────────────────────────
//
// Consolidates all OS keychain entries into a SINGLE keychain item stored as
// a JSON blob.  This reduces macOS Keychain Access prompts from 6 to 1:
//
//   Before: paw-db-encryption, paw-lock-screen, paw-skill-vault,
//           paw-memory-vault, paw-n8n-encryption, paw-audit-chain
//           → 6 separate prompts on first launch / binary change
//
//   After:  ONE "openpawz" / "key-vault" entry → 1 prompt
//
// Architecture:
//   - Single keychain entry: service="openpawz", user="key-vault"
//   - In-memory HashMap<String, String> protected by RwLock (read-many)
//   - Each subsystem calls get()/set() with a purpose constant
//   - First-run migration: reads legacy per-entry items, consolidates,
//     persists the unified blob, then deletes the old entries
//
// Security:
//   - All key material passes through as String (hex or base64) — same
//     as the legacy per-entry approach.
//   - The vault blob is stored in the OS keychain (encrypted at rest by
//     macOS Keychain / GNOME Keyring / Windows Credential Manager).
//   - In-memory cache is process-scoped — cleared on exit.
//   - Write operations hold the lock across read-check + insert + persist
//     to prevent TOCTOU races between concurrent threads.

use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::RwLock;

const VAULT_SERVICE: &str = "openpawz";
const VAULT_USER: &str = "key-vault";

/// Legacy keychain entry descriptor — used only during migration.
struct LegacyEntry {
    purpose: &'static str,
    service: &'static str,
    user: &'static str,
}

/// All legacy per-entry keychain items we migrate from.
const LEGACY_ENTRIES: &[LegacyEntry] = &[
    LegacyEntry {
        purpose: PURPOSE_DB_ENCRYPTION,
        service: "paw-db-encryption",
        user: "paw-db-key",
    },
    LegacyEntry {
        purpose: PURPOSE_LOCK_SCREEN,
        service: "paw-lock-screen",
        user: "paw-lock-passphrase",
    },
    LegacyEntry {
        purpose: PURPOSE_SKILL_VAULT,
        service: "paw-skill-vault",
        user: "encryption-key",
    },
    LegacyEntry {
        purpose: PURPOSE_MEMORY_VAULT,
        service: "paw-memory-vault",
        user: "field-encryption-key",
    },
    LegacyEntry {
        purpose: PURPOSE_N8N_ENCRYPTION,
        service: "paw-n8n-encryption",
        user: "openpawz-n8n",
    },
    LegacyEntry {
        purpose: PURPOSE_AUDIT_CHAIN,
        service: "paw-audit-chain",
        user: "hmac-signing-key",
    },
    LegacyEntry {
        purpose: PURPOSE_NOSTR_KEY,
        service: "paw-nostr",
        user: "private-key",
    },
];

/// In-memory cache of the vault contents.
/// None = not yet loaded, Some = loaded (possibly empty on fresh install).
static VAULT_CACHE: RwLock<Option<HashMap<String, String>>> = RwLock::new(None);

// ── Public API ─────────────────────────────────────────────────────────────

/// Purpose constants — each subsystem uses its own key.
pub const PURPOSE_DB_ENCRYPTION: &str = "db-encryption";
pub const PURPOSE_LOCK_SCREEN: &str = "lock-screen";
pub const PURPOSE_SKILL_VAULT: &str = "skill-vault";
pub const PURPOSE_MEMORY_VAULT: &str = "memory-vault";
pub const PURPOSE_N8N_ENCRYPTION: &str = "n8n-encryption";
pub const PURPOSE_AUDIT_CHAIN: &str = "audit-chain";
pub const PURPOSE_NOSTR_KEY: &str = "nostr-key";

/// Prefetch the vault — triggers the single keychain access so that all
/// subsequent `get()` calls are pure in-memory lookups.
/// Call this early in app startup (before subsystems initialise).
pub fn prefetch() {
    ensure_loaded();
    let guard = VAULT_CACHE.read().unwrap_or_else(|e| e.into_inner());
    let count = guard.as_ref().map_or(0, |m| m.len());
    info!("[key-vault] Prefetch complete — {} keys available", count);
}

/// Check whether the vault was successfully loaded.
/// Returns `true` if `prefetch()` (or any `get()`/`set()`) has populated
/// the in-memory cache — meaning the OS keychain was reachable.
pub fn is_loaded() -> bool {
    VAULT_CACHE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
}

/// Get a value from the vault by purpose key.
/// Returns `None` if the key has never been stored.
pub fn get(purpose: &str) -> Option<String> {
    ensure_loaded();
    let guard = VAULT_CACHE.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().and_then(|map| map.get(purpose).cloned())
}

/// Store a value in the vault and persist the whole blob to the keychain.
/// Creates the vault entry if it doesn't exist yet.
///
/// Thread-safe: holds the write lock across read-check + insert + persist
/// to prevent TOCTOU races between concurrent callers.
pub fn set(purpose: &str, value: &str) {
    // Ensure vault is loaded under the write lock — avoids a
    // release-then-reacquire gap that would let another thread
    // clobber our insert.
    let mut guard = VAULT_CACHE.write().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(read_or_migrate());
    }
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(purpose.to_string(), value.to_string());
    persist_vault(map);
}

/// Remove a value from the vault and persist.
/// Used by lock_screen_remove_passphrase(), oauth revoke, etc.
pub fn remove(purpose: &str) {
    let mut guard = VAULT_CACHE.write().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(read_or_migrate());
    }
    if let Some(map) = guard.as_mut() {
        if map.remove(purpose).is_some() {
            persist_vault(map);
            info!("[key-vault] Removed '{}' from vault", purpose);
        }
    }
}

// ── Internal ───────────────────────────────────────────────────────────────

/// Ensure the vault is loaded into memory (double-checked lock pattern).
/// On first call, reads the keychain (1 OS prompt max).
/// On missing vault, migrates from legacy per-entry keychain items.
fn ensure_loaded() {
    // Fast path: already cached
    {
        let guard = VAULT_CACHE.read().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return;
        }
    }
    // Slow path: acquire write lock and double-check
    let mut guard = VAULT_CACHE.write().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        return;
    }
    *guard = Some(read_or_migrate());
}

/// Try to read the unified vault from keychain.
/// Falls back to migrating legacy entries if the vault doesn't exist.
fn read_or_migrate() -> HashMap<String, String> {
    match keyring::Entry::new(VAULT_SERVICE, VAULT_USER) {
        Ok(entry) => match entry.get_password() {
            Ok(json_str) => match serde_json::from_str::<HashMap<String, String>>(&json_str) {
                Ok(map) => {
                    info!("[key-vault] Loaded unified vault ({} keys)", map.len());
                    map
                }
                Err(e) => {
                    error!(
                        "[key-vault] Corrupt vault JSON: {} — rebuilding from legacy",
                        e
                    );
                    migrate_legacy_entries()
                }
            },
            Err(keyring::Error::NoEntry) => {
                info!("[key-vault] No unified vault found — migrating from legacy entries");
                migrate_legacy_entries()
            }
            Err(e) => {
                warn!(
                    "[key-vault] Keychain read error: {} — trying legacy migration",
                    e
                );
                migrate_legacy_entries()
            }
        },
        Err(e) => {
            error!("[key-vault] Keyring init failed: {}", e);
            HashMap::new()
        }
    }
}

/// Read values from legacy individual keychain entries, consolidate them into
/// the unified vault, persist it, and delete the old entries.
fn migrate_legacy_entries() -> HashMap<String, String> {
    let mut map = HashMap::new();

    for legacy in LEGACY_ENTRIES {
        match keyring::Entry::new(legacy.service, legacy.user) {
            Ok(entry) => match entry.get_password() {
                Ok(value) if !value.is_empty() => {
                    info!(
                        "[key-vault] Migrated '{}' from legacy entry ({}/{})",
                        legacy.purpose, legacy.service, legacy.user
                    );
                    map.insert(legacy.purpose.to_string(), value);
                }
                Ok(_) => {}                        // empty value — skip
                Err(keyring::Error::NoEntry) => {} // not set — skip
                Err(e) => {
                    warn!(
                        "[key-vault] Could not read legacy entry '{}': {}",
                        legacy.purpose, e
                    );
                }
            },
            Err(e) => {
                warn!(
                    "[key-vault] Could not init legacy entry '{}': {}",
                    legacy.purpose, e
                );
            }
        }
    }

    // Persist the consolidated vault
    if !map.is_empty() {
        persist_vault(&map);
    }

    // Clean up legacy entries (best-effort — errors are non-fatal)
    cleanup_legacy_entries();

    map
}

/// Delete legacy individual keychain entries after successful migration.
/// Best-effort — failures are logged but don't block startup.
fn cleanup_legacy_entries() {
    for legacy in LEGACY_ENTRIES {
        if let Ok(entry) = keyring::Entry::new(legacy.service, legacy.user) {
            match entry.delete_credential() {
                Ok(()) => info!(
                    "[key-vault] Deleted legacy entry {}/{}",
                    legacy.service, legacy.user
                ),
                Err(keyring::Error::NoEntry) => {} // already gone
                Err(e) => warn!(
                    "[key-vault] Could not delete legacy entry {}/{}: {}",
                    legacy.service, legacy.user, e
                ),
            }
        }
    }
}

/// Serialise the vault map to JSON and write to the single keychain entry.
fn persist_vault(map: &HashMap<String, String>) {
    let json = match serde_json::to_string(map) {
        Ok(j) => j,
        Err(e) => {
            error!("[key-vault] Failed to serialise vault: {}", e);
            return;
        }
    };

    match keyring::Entry::new(VAULT_SERVICE, VAULT_USER) {
        Ok(entry) => match entry.set_password(&json) {
            Ok(()) => debug!("[key-vault] Persisted unified vault ({} keys)", map.len()),
            Err(e) => error!("[key-vault] Failed to persist vault: {}", e),
        },
        Err(e) => error!("[key-vault] Keyring init failed on persist: {}", e),
    }
}
