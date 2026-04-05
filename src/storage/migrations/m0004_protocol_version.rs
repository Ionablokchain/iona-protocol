use crate::storage::layout::DataLayout;
use crate::storage::SchemaMeta;
use std::io;

pub fn migrate(layout: &DataLayout, meta: &mut SchemaMeta) -> io::Result<()> {
    let node_meta_path = layout.node_meta_path();
    if !node_meta_path.exists() {
        let node_meta = serde_json::json!({
            "schema_version": 4,
            "protocol_version": 1,
            "node_version": env!("CARGO_PKG_VERSION"),
        });
        let json = serde_json::to_string_pretty(&node_meta)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        DataLayout::atomic_write(&node_meta_path, json.as_bytes())?;
    }
    meta.migration_log.push(format!("v3 → v4: node_meta.json created"));
    Ok(())
}
