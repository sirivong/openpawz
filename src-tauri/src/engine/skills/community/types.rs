use serde::{Deserialize, Serialize};

// CommunitySkill is now defined in openpawz-core
pub use crate::engine::sessions::CommunitySkill;

/// A skill discovered from a GitHub repo (not yet installed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredSkill {
    /// Derived ID: "owner/repo/skill-name"
    pub id: String,
    /// Human name from SKILL.md frontmatter
    pub name: String,
    /// Description from SKILL.md frontmatter
    pub description: String,
    /// Source repo: "owner/repo"
    pub source: String,
    /// Path within the repo (e.g. "skills/my-skill/SKILL.md")
    pub path: String,
    /// Whether this skill is already installed locally
    pub installed: bool,
    /// Install count from skills.sh (0 if unknown)
    pub installs: u64,
}
