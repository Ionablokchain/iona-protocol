pub mod m0004_protocol_version;
pub mod m0005_add_tx_index;

/// List of migrations: (from_version, to_version, description).
pub const MIGRATIONS: &[(u32, u32, &str)] = &[
    (0, 1, "schema marker"),
    (1, 2, "normalize state_full + stakes"),
    (2, 3, "segmented WAL"),
    (3, 4, "node_meta protocol_version"),
    (4, 5, "tx_index"),
];
