use crate::storage::layout::DataLayout;
use crate::storage::SchemaMeta;
use std::io;

pub fn migrate(layout: &DataLayout, meta: &mut SchemaMeta) -> io::Result<()> {
    let tx_index_path = layout.tx_index_path();
    if !tx_index_path.exists() {
        let empty = serde_json::json!({});
        let json = serde_json::to_string_pretty(&empty)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        DataLayout::atomic_write(&tx_index_path, json.as_bytes())?;
    }
    meta.migration_log
        .push(format!("v4 → v5: tx_index.json created"));
    Ok(())
}
