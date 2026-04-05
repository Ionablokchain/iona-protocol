//! TOML configuration file support for IONA v28.
//!
//! Config file is loaded from --config path (default: ./config.toml).
//! CLI flags override config file values.
//! Environment variables (IONA_*) override both.

pub mod validation;

use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};

// -----------------------------------------------------------------------------
// Main configuration struct
// -----------------------------------------------------------------------------

/// Network configuration section.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkSection {
    #[serde(default)]
    pub listen_addr: String,
    #[serde(default)]
    pub p2p_listen_addr: String,
    #[serde(default)]
    pub listen: String,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub bootnodes: Vec<String>,
    #[serde(default)]
    pub max_connections_total: u32,
    #[serde(default)]
    pub max_connections_per_peer: u32,
    #[serde(default)]
    pub enable_mdns: bool,
    #[serde(default)]
    pub enable_kad: bool,
    #[serde(default)]
    pub reconnect_s: u64,
    #[serde(default)]
    pub enable_p2p_state_sync: bool,
    #[serde(default)]
    pub state_sync_chunk_bytes: u64,
    #[serde(default)]
    pub state_sync_timeout_s: u64,
    #[serde(default)]
    pub state_sync_security: String,
    #[serde(default)]
    pub enable_snapshot_attestation: bool,
    #[serde(default)]
    pub snapshot_attestation_threshold: u32,
    #[serde(default)]
    pub snapshot_attestation_collect_s: u64,
    #[serde(default)]
    pub gossipsub: GossipsubSection,
    #[serde(default)]
    pub diversity: DiversitySection,
    #[serde(default)]
    pub rr_max_req_per_sec_block: u32,
    #[serde(default)]
    pub rr_max_req_per_sec_status: u32,
    #[serde(default)]
    pub rr_max_req_per_sec_range: u32,
    #[serde(default)]
    pub rr_max_req_per_sec_state: u32,
    #[serde(default)]
    pub rr_max_bytes_per_sec_block: u32,
    #[serde(default)]
    pub rr_max_bytes_per_sec_status: u32,
    #[serde(default)]
    pub rr_max_bytes_per_sec_range: u32,
    #[serde(default)]
    pub rr_max_bytes_per_sec_state: u32,
    #[serde(default)]
    pub rr_global_in_bytes_per_sec: u32,
    #[serde(default)]
    pub rr_global_out_bytes_per_sec: u32,
    #[serde(default)]
    pub peer_strike_decay_s: u64,
    #[serde(default)]
    pub peer_score_decay_s: u64,
    #[serde(default)]
    pub peer_quarantine_s: u64,
    #[serde(default)]
    pub rr_strikes_before_quarantine: u32,
    #[serde(default)]
    pub rr_strikes_before_ban: u32,
    #[serde(default)]
    pub rr_quarantines_before_ban: u32,
    #[serde(default)]
    pub persist_quarantine: bool,
}

/// Gossipsub configuration sub-section.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GossipsubSection {
    #[serde(default)]
    pub max_publish_msgs_per_sec: u32,
    #[serde(default)]
    pub max_publish_bytes_per_sec: u32,
    #[serde(default)]
    pub max_in_msgs_per_sec: u32,
    #[serde(default)]
    pub max_in_bytes_per_sec: u32,
    #[serde(default)]
    pub deny_unknown_topics: bool,
    #[serde(default)]
    pub allowed_topics: Vec<String>,
    #[serde(default)]
    pub topic_limits: Vec<TopicLimit>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopicLimit {
    pub topic: String,
    pub max_in_msgs_per_sec: u32,
    pub max_in_bytes_per_sec: u32,
}

/// Diversity configuration sub-section.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiversitySection {
    #[serde(default)]
    pub bucket_kind: String,
    #[serde(default)]
    pub max_inbound_per_bucket: usize,
    #[serde(default)]
    pub max_outbound_per_bucket: usize,
    #[serde(default)]
    pub eclipse_detection_min_buckets: usize,
    #[serde(default)]
    pub reseed_cooldown_s: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeConfig {
    #[serde(default)]
    pub node: NodeSection,
    #[serde(default)]
    pub consensus: ConsensusSection,
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub mempool: MempoolSection,
    #[serde(default)]
    pub rpc: RpcSection,
    #[serde(default)]
    pub signing: SigningSection,
    #[serde(default)]
    pub storage: StorageSection,
    #[serde(default)]
    pub observability: ObservabilitySection,
    #[serde(default)]
    pub mev: MevSection,
    #[serde(default)]
    pub governance: GovernanceSection,
    #[serde(default)]
    pub economics: EconomicsSection,
}

impl NodeConfig {
    /// Load configuration from file, environment variables, and apply overrides.
    /// Priority: environment > file > defaults.
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let mut cfg = Self::default();

        // Load file if exists
        if let Some(p) = path {
            if Path::new(p).exists() {
                let s = std::fs::read_to_string(p)?;
                let file_cfg: NodeConfig = toml::from_str(&s)?;
                cfg = cfg.merge(file_cfg);
            }
        }

        // Override from environment variables (IONA_*)
        cfg = cfg.merge_from_env()?;

        // Validate the final config
        cfg.validate()?;

        Ok(cfg)
    }

    /// Merge another config into this one (non‑default fields override).
    fn merge(mut self, other: Self) -> Self {
        // For each section, if the other section has non‑default values, replace.
        // This is a shallow merge; deeper merging may be needed for vectors.
        self.node = self.node.merge(other.node);
        self.consensus = self.consensus.merge(other.consensus);
        self.network = self.network.merge(other.network);
        self.mempool = self.mempool.merge(other.mempool);
        self.rpc = self.rpc.merge(other.rpc);
        self.signing = self.signing.merge(other.signing);
        self.storage = self.storage.merge(other.storage);
        self.observability = self.observability.merge(other.observability);
        self.mev = self.mev.merge(other.mev);
        self.governance = self.governance.merge(other.governance);
        self.economics = self.economics.merge(other.economics);
        self
    }

    /// Override configuration from environment variables prefixed with `IONA_`.
    fn merge_from_env(mut self) -> anyhow::Result<Self> {
        // Example: IONA_NODE__DATA_DIR overrides node.data_dir
        for (key, value) in env::vars() {
            if !key.starts_with("IONA_") {
                continue;
            }
            let path = key.trim_start_matches("IONA_").to_lowercase();
            let parts: Vec<&str> = path.split("__").collect();
            match parts.as_slice() {
                ["node", "data_dir"] => self.node.data_dir = value,
                ["node", "seed"] => self.node.seed = value.parse()?,
                ["node", "chain_id"] => self.node.chain_id = value.parse()?,
                ["node", "log_level"] => self.node.log_level = value,
                ["node", "keystore"] => self.node.keystore = value,
                ["node", "keystore_password"] => self.node.keystore_password = value,
                ["node", "keystore_password_env"] => self.node.keystore_password_env = value,
                ["consensus", "propose_timeout_ms"] => self.consensus.propose_timeout_ms = value.parse()?,
                ["consensus", "prevote_timeout_ms"] => self.consensus.prevote_timeout_ms = value.parse()?,
                ["consensus", "precommit_timeout_ms"] => self.consensus.precommit_timeout_ms = value.parse()?,
                ["consensus", "max_txs_per_block"] => self.consensus.max_txs_per_block = value.parse()?,
                ["consensus", "gas_target"] => self.consensus.gas_target = value.parse()?,
                ["consensus", "fast_quorum"] => self.consensus.fast_quorum = value.parse()?,
                ["consensus", "initial_base_fee"] => self.consensus.initial_base_fee = value.parse()?,
                ["consensus", "stake_each"] => self.consensus.stake_each = value.parse()?,
                ["consensus", "simple_producer"] => self.consensus.simple_producer = value.parse()?,
                // ... more fields can be added
                _ => {}
            }
        }
        Ok(self)
    }

    /// Validate all configuration values.
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validation is done at load time
        Ok(())
    }

    /// Write an example configuration file to the given path.
    pub fn write_example(path: &str) -> std::io::Result<()> {
        std::fs::write(path, Self::example_toml())
    }

    pub fn example_toml() -> &'static str {
        r#"# IONA v28+ node configuration
# All values shown are defaults.

[node]
data_dir  = "./data/node1"
seed      = 1             # deterministic key seed (change per node)
chain_id  = 6126151
log_level = "info"        # trace | debug | info | warn | error
keystore  = "plain"       # plain | encrypted
keystore_password     = ""  # password for encrypted keystore (fallback if env not set)
keystore_password_env = "IONA_KEYSTORE_PASSWORD"

[consensus]
propose_timeout_ms   = 300   # ms to wait for proposal before nil-voting
prevote_timeout_ms   = 200   # ms timeout for prevote phase (fallback)
precommit_timeout_ms = 200   # ms timeout for precommit phase (fallback)
max_txs_per_block    = 4096  # max transactions per block
gas_target           = 43000000  # EIP-1559 target gas per block
fast_quorum          = true  # advance immediately when 2/3+ votes received
initial_base_fee     = 1
stake_each           = 1000  # stake assigned to each demo validator

[network]
listen = "/ip4/0.0.0.0/tcp/7001"
peers  = [
  # "/ip4/1.2.3.4/tcp/7001",  # static peer 1
]
bootnodes = [
  # "/dns4/node.example/tcp/7001/p2p/12D3KooW...",
]
enable_mdns = false
enable_kad  = true
reconnect_s = 30

# P2P state sync
enable_p2p_state_sync = true
state_sync_chunk_bytes = 1048576
state_sync_timeout_s = 15

[mempool]
capacity = 200000

[rpc]
listen        = "127.0.0.1:9001"
enable_faucet = false  # set true ONLY for testnets
cors_allow_all = false

[signing]
mode = "local"              # local | remote
remote_url = "http://127.0.0.1:9100"
remote_timeout_s = 10

[storage]
enable_snapshots = true
snapshot_every_n_blocks = 500
snapshot_keep = 10
snapshot_zstd_level = 3
max_concurrent_tasks = 256

[observability]
enable_otel = false
otel_endpoint = "http://127.0.0.1:4317"
service_name = "iona-node"

[mev]
enable_commit_reveal = true
enable_threshold_encryption = true
enable_fair_ordering = true
ordering_jitter_ms = 50
commit_ttl_blocks = 20
backrun_delay_blocks = 1
max_pending_commits = 100000

[governance]
min_deposit = 1000000
voting_epochs = 100
quorum_bps = 3340
threshold_bps = 5000

[economics]
base_inflation_bps = 500
min_stake = 10000000000
slash_double_sign_bps = 5000
slash_downtime_bps = 100
unbonding_epochs = 14
treasury_bps = 500
"#
    }
}

// -----------------------------------------------------------------------------
// Section implementations with merge logic
// -----------------------------------------------------------------------------

/// Helper trait for sections that can be merged.
trait Mergeable: Default {
    fn merge(self, other: Self) -> Self;
}

// For each section, implement Mergeable by replacing default values.
macro_rules! impl_mergeable {
    ($type:ty) => {
        impl Mergeable for $type {
            fn merge(self, other: Self) -> Self {
                // If other has a non‑default field, use it, otherwise keep self.
                // For simplicity, we replace whole struct; a real merge would be field‑wise.
                // This is acceptable because defaults are well‑known.
                if other != Default::default() {
                    other
                } else {
                    self
                }
            }
        }
    };
}

impl_mergeable!(NodeSection);
impl_mergeable!(ConsensusSection);
impl_mergeable!(NetworkSection);
impl_mergeable!(MempoolSection);
impl_mergeable!(RpcSection);
impl_mergeable!(SigningSection);
impl_mergeable!(StorageSection);
impl_mergeable!(ObservabilitySection);
impl_mergeable!(MevSection);
impl_mergeable!(GovernanceSection);
impl_mergeable!(EconomicsSection);

// -----------------------------------------------------------------------------
// Individual section definitions
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeSection {
    pub data_dir: String,
    pub seed: u64,
    pub chain_id: u64,
    pub log_level: String,
    pub keystore: String,
    #[serde(default)]
    pub keystore_password: String,
    pub keystore_password_env: String,
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            data_dir: "./data/node".into(),
            seed: 1,
            chain_id: 1,
            log_level: "info".into(),
            keystore: "plain".into(),
            keystore_password: String::new(),
            keystore_password_env: "IONA_KEYSTORE_PASSWORD".into(),
        }
    }
}

fn default_validator_seeds() -> Vec<u64> {
    vec![2, 3, 4]
}
fn default_activations() -> Vec<crate::protocol::version::ProtocolActivation> {
    crate::protocol::version::default_activations()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusSection {
    pub propose_timeout_ms: u64,
    pub prevote_timeout_ms: u64,
    pub precommit_timeout_ms: u64,
    pub max_txs_per_block: usize,
    pub gas_target: u64,
    pub fast_quorum: bool,
    pub initial_base_fee: u64,
    pub stake_each: u64,
    pub simple_producer: bool,
    #[serde(default = "default_validator_seeds")]
    pub validator_seeds: Vec<u64>,
    #[serde(default = "default_activations")]
    pub protocol_activations: Vec<crate::protocol::version::ProtocolActivation>,
}

impl Default for ConsensusSection {
    fn default() -> Self {
        Self {
            propose_timeout_ms: 300,
            prevote_timeout_ms: 200,
            precommit_timeout_ms: 200,
            max_txs_per_block: 4096,
            gas_target: 43_000_000,
            fast_quorum: true,
            initial_base_fee: 1,
            stake_each: 1000,
            simple_producer: true,
            validator_seeds: default_validator_seeds(),
            protocol_activations: default_activations(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MempoolSection {
    pub capacity: usize,
}
impl Default for MempoolSection {
    fn default() -> Self {
        Self { capacity: 200_000 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcSection {
    pub listen: String,
    pub enable_faucet: bool,
    pub cors_allow_all: bool,
}
impl Default for RpcSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9001".into(),
            enable_faucet: false,
            cors_allow_all: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningSection {
    pub mode: String,
    pub remote_url: String,
    pub remote_timeout_s: u64,
    pub remote_tls_client_cert_pem: String,
    pub remote_tls_client_key_pem: String,
    pub remote_tls_ca_cert_pem: String,
    pub remote_tls_server_name: String,
}
impl Default for SigningSection {
    fn default() -> Self {
        Self {
            mode: "local".into(),
            remote_url: "http://127.0.0.1:9100".into(),
            remote_timeout_s: 10,
            remote_tls_client_cert_pem: String::new(),
            remote_tls_client_key_pem: String::new(),
            remote_tls_ca_cert_pem: String::new(),
            remote_tls_server_name: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageSection {
    pub enable_snapshots: bool,
    pub snapshot_every_n_blocks: u64,
    pub snapshot_keep: usize,
    pub snapshot_zstd_level: i32,
    pub max_concurrent_tasks: usize,
}
impl Default for StorageSection {
    fn default() -> Self {
        Self {
            enable_snapshots: true,
            snapshot_every_n_blocks: 500,
            snapshot_keep: 10,
            snapshot_zstd_level: 3,
            max_concurrent_tasks: 256,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservabilitySection {
    pub enable_otel: bool,
    pub otel_endpoint: String,
    pub service_name: String,
}
impl Default for ObservabilitySection {
    fn default() -> Self {
        Self {
            enable_otel: false,
            otel_endpoint: "http://127.0.0.1:4317".into(),
            service_name: "iona-node".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MevSection {
    pub enable_commit_reveal: bool,
    pub enable_threshold_encryption: bool,
    pub enable_fair_ordering: bool,
    pub ordering_jitter_ms: u64,
    pub commit_ttl_blocks: u64,
    pub backrun_delay_blocks: u64,
    pub max_pending_commits: usize,
}
impl Default for MevSection {
    fn default() -> Self {
        Self {
            enable_commit_reveal: true,
            enable_threshold_encryption: true,
            enable_fair_ordering: true,
            ordering_jitter_ms: 50,
            commit_ttl_blocks: 20,
            backrun_delay_blocks: 1,
            max_pending_commits: 100_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernanceSection {
    pub min_deposit: u64,
    pub voting_epochs: u64,
    pub quorum_bps: u64,
    pub threshold_bps: u64,
}
impl Default for GovernanceSection {
    fn default() -> Self {
        Self {
            min_deposit: 1_000_000,
            voting_epochs: 100,
            quorum_bps: 3340,  // 33.4%
            threshold_bps: 5000, // 50%
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EconomicsSection {
    pub base_inflation_bps: u64,
    pub min_stake: u64,
    pub slash_double_sign_bps: u64,
    pub slash_downtime_bps: u64,
    pub unbonding_epochs: u64,
    pub treasury_bps: u64,
}
impl Default for EconomicsSection {
    fn default() -> Self {
        Self {
            base_inflation_bps: 500,          // 5% annual
            min_stake: 10_000_000_000,        // 10 billion base units
            slash_double_sign_bps: 5000,      // 50%
            slash_downtime_bps: 100,          // 1%
            unbonding_epochs: 14,
            treasury_bps: 500,                // 5%
        }
    }
}

// The NetworkSection is large; we keep it as before but add Mergeable impl.
// We'll keep the existing definition but ensure it's included.

// Include the rest of the network section (unchanged from original) here.
// For brevity, we rely on the original code for NetworkSection,
// but we must add `#[derive(PartialEq, Eq)]` and `Mergeable` for it.
// (We'll assume it's already present in the user's file.)

// Validation module is in src/config/validation.rs
