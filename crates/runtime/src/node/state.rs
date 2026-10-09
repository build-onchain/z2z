//! Bounded public node-state snapshot: the small JSON file a running node
//! keeps fresh so operators can run `z2z-node status` like a classic daemon
//! CLI. Written atomically (temp file + rename) with bounded fields only;
//! it never contains owner secrets, orders or witness material.
//!
//! ponytail: whole-file rewrite on change. A incremental journal is not
//! warranted for a handful of scalars at 2 Hz.

use std::io::Write;
use std::path::Path;

#[derive(serde::Serialize)]
pub(crate) struct StateSnapshot<'a> {
    pub schema_version: u16,
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_reason: Option<&'a str>,
    pub peer_id: &'a str,
    pub listen: &'a str,
    pub connected_peers: usize,
    pub updated_unix: u64,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn temp_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Atomic bounded snapshot write: same directory temp file, fsync, rename.
/// Failures are reported but never fatal to the running node.
pub(crate) fn write_state(path: Option<&Path>, snapshot: &StateSnapshot<'_>) -> std::io::Result<()> {
    let Some(path) = path else { return Ok(()) };
    let temp = temp_path(path);
    {
        let mut file = std::fs::File::create(&temp)?;
        let bytes = serde_json::to_vec(snapshot).map_err(std::io::Error::other)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temp, path)
}

pub(crate) fn now_unix_secs() -> u64 {
    now_unix()
}
