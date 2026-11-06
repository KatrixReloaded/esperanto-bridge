//! Bounded consistency validation for untrusted RPC batches. This is not a consensus/finality proof.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub height: u64,
    pub hash: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub block: Anchor,
    pub transaction: [u8; 32],
    pub index: u64,
    pub payload: Vec<u8>,
}
/// Reread anchors before committing a cursor; reconcile persisted signed work before polling new work.
pub fn reconcile(
    previous: &Anchor,
    end: &Anchor,
    reread_previous: &Anchor,
    reread_end: &Anchor,
    events: Vec<Event>,
) -> Result<Vec<Event>> {
    ensure!(
        previous == reread_previous && end == reread_end,
        "RPC anchor changed; halt reconciliation"
    );
    ensure!(
        end.height >= previous.height && end.height - previous.height <= 256,
        "scan range bound exceeded"
    );
    ensure!(events.len() <= 1024, "event bound exceeded");
    let mut unique = BTreeMap::new();
    let mut blocks = BTreeMap::new();
    for event in events {
        ensure!(
            event.block.height > previous.height && event.block.height <= end.height,
            "event outside scan range"
        );
        ensure!(
            event.payload.len() <= 16 * 1024,
            "event payload bound exceeded"
        );
        if event.block.height == end.height {
            ensure!(event.block == *end, "end anchor mismatch");
        }
        if let Some(hash) = blocks.insert(event.block.height, event.block.hash) {
            ensure!(hash == event.block.hash, "conflicting block hashes");
        }
        let key = (event.block.height, event.index, event.transaction);
        if let Some(existing) = unique.insert(key, event.clone()) {
            ensure!(existing == event, "conflicting duplicate event");
        }
    }
    Ok(unique.into_values().collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_and_reorg_halt() {
        let a = Anchor {
            height: 0,
            hash: [0; 32],
        };
        let b = Anchor {
            height: 1,
            hash: [1; 32],
        };
        let e = Event {
            block: b.clone(),
            transaction: [2; 32],
            index: 0,
            payload: vec![1],
        };
        assert_eq!(
            reconcile(&a, &b, &a, &b, vec![e.clone(), e.clone()])
                .unwrap()
                .len(),
            1
        );
        let mut conflict = e.clone();
        conflict.payload = vec![2];
        assert!(reconcile(&a, &b, &a, &b, vec![e.clone(), conflict]).is_err());
        assert!(reconcile(&a, &b, &a, &a, vec![e]).is_err());
    }
}
