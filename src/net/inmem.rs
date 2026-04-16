//! In‑memory transport for consensus messages.
//!
//! This is intended for integration testing without sockets.
//! It simulates a small P2P network where nodes can broadcast `ConsensusMsg`
//! to all other registered nodes.
//!
//! # Example
//!
//! ```
//! use iona::net::inmem::InMemNet;
//! use iona::consensus::ConsensusMsg;
//!
//! let (net1, mut rx1) = InMemNet::new(1);
//! let rx2 = net1.register(2);
//! let net2 = net1.handle(2);
//!
//! net1.broadcast(ConsensusMsg::Note("hello".into()));
//! // rx1 does NOT receive (broadcast excludes sender), rx2 receives.
//! ```

use crate::consensus::ConsensusMsg;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{debug, warn};

pub type NodeId = u64;

/// Handle used by a node to send messages into the in‑memory network.
#[derive(Clone)]
pub struct InMemNet {
    inner: Arc<Mutex<Inner>>,
    pub node_id: NodeId,
}

struct Inner {
    peers: HashMap<NodeId, mpsc::UnboundedSender<ConsensusMsg>>,
}

impl InMemNet {
    /// Create a new network and register the first node.
    ///
    /// Returns a handle for the node and a receiver to read incoming messages.
    pub fn new(node_id: NodeId) -> (Self, mpsc::UnboundedReceiver<ConsensusMsg>) {
        let inner = Arc::new(Mutex::new(Inner {
            peers: HashMap::new(),
        }));
        let (tx, rx) = mpsc::unbounded_channel();
        inner.lock().unwrap().peers.insert(node_id, tx);
        debug!(node_id, "created new in‑memory network, node registered");
        (Self { inner, node_id }, rx)
    }

    /// Register an additional node into the same network.
    ///
    /// Returns a receiver for that node.
    pub fn register(&self, node_id: NodeId) -> mpsc::UnboundedReceiver<ConsensusMsg> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.lock().unwrap().peers.insert(node_id, tx);
        debug!(node_id, "registered new node in existing network");
        rx
    }

    /// Create another handle for the same underlying network but with a different local node id.
    ///
    /// This is useful when you already have a handle and want to simulate another node.
    pub fn handle(&self, node_id: NodeId) -> Self {
        Self {
            inner: self.inner.clone(),
            node_id,
        }
    }

    /// Broadcast a message to all nodes **except** the sender.
    pub fn broadcast(&self, msg: ConsensusMsg) {
        let peers = self.inner.lock().unwrap().peers.clone();
        let mut failed = Vec::new();
        for (id, tx) in peers.into_iter() {
            if id == self.node_id {
                continue;
            }
            if let Err(e) = tx.send(msg.clone()) {
                warn!(to = id, error = %e, "failed to broadcast message");
                failed.push(id);
            }
        }
        if !failed.is_empty() {
            // Remove failed senders from the peer list (best effort).
            let mut inner = self.inner.lock().unwrap();
            for id in failed {
                inner.peers.remove(&id);
                debug!(node_id = id, "removed dead peer");
            }
        }
        debug!(from = self.node_id, peers = self.peer_count(), "broadcasted message");
    }

    /// Send a message directly to a specific node (by ID).
    pub fn send_to(&self, target: NodeId, msg: ConsensusMsg) -> Result<(), &'static str> {
        let peers = self.inner.lock().unwrap().peers.clone();
        if let Some(tx) = peers.get(&target) {
            tx.send(msg).map_err(|_| "failed to send message")?;
            debug!(from = self.node_id, to = target, "direct message sent");
            Ok(())
        } else {
            warn!(to = target, "target node not found");
            Err("target node not registered")
        }
    }

    /// Return the number of currently registered peers (excluding self?).
    /// This counts all nodes in the network, including self.
    pub fn peer_count(&self) -> usize {
        self.inner.lock().unwrap().peers.len()
    }

    /// Check if a given node ID is connected (registered) in the network.
    pub fn is_connected(&self, node_id: NodeId) -> bool {
        self.inner.lock().unwrap().peers.contains_key(&node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ConsensusMsg;

    #[tokio::test]
    async fn test_broadcast_excludes_self() {
        let (net1, mut rx1) = InMemNet::new(1);
        let rx2 = net1.register(2);
        let rx3 = net1.register(3);

        net1.broadcast(ConsensusMsg::Note("hello".into()));

        // Self should not receive.
        assert!(rx1.try_recv().is_err());

        // Others should receive.
        assert!(rx2.try_recv().is_ok());
        assert!(rx3.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_send_to() {
        let (net1, mut rx1) = InMemNet::new(1);
        let rx2 = net1.register(2);

        net1.send_to(2, ConsensusMsg::Note("direct".into())).unwrap();

        assert!(rx1.try_recv().is_err());
        let msg = rx2.try_recv().unwrap();
        match msg {
            ConsensusMsg::Note(s) => assert_eq!(s, "direct"),
            _ => panic!("unexpected message"),
        }
    }

    #[tokio::test]
    async fn test_send_to_nonexistent() {
        let (net1, _) = InMemNet::new(1);
        let res = net1.send_to(99, ConsensusMsg::Note("test".into()));
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_peer_count() {
        let (net1, _) = InMemNet::new(1);
        assert_eq!(net1.peer_count(), 1);
        net1.register(2);
        assert_eq!(net1.peer_count(), 2);
        let net2 = net1.handle(3);
        net2.register(4);
        assert_eq!(net1.peer_count(), 4);
    }

    #[tokio::test]
    async fn test_is_connected() {
        let (net1, _) = InMemNet::new(1);
        assert!(net1.is_connected(1));
        assert!(!net1.is_connected(2));
        net1.register(2);
        assert!(net1.is_connected(2));
    }

    #[tokio::test]
    async fn test_handle() {
        let (net1, mut rx1) = InMemNet::new(1);
        let rx2 = net1.register(2);
        let net2 = net1.handle(2);
        net2.broadcast(ConsensusMsg::Note("from handle".into()));
        // net2 broadcasts to all except itself (id=2), so net1 should receive.
        let msg = rx1.try_recv().unwrap();
        match msg {
            ConsensusMsg::Note(s) => assert_eq!(s, "from handle"),
            _ => panic!("unexpected"),
        }
        assert!(rx2.try_recv().is_err());
    }
}
