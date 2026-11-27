//! Persistent Crosby-Wallach / RFC 6962 BLAKE3 Merkle history tree.
//!
//! Each committed workspace revision `seq` (`0, 1, 2, ...`) appends one leaf:
//! `BLAKE3(0x00 || seq_le || revision_id || manifest_digest || eligibility_generation_le)`
//! and updates at most `floor(log2(seq + 1)) + 1` complete power-of-two subtree
//! nodes in `history_tree_nodes(level, idx, digest)` inside the commit
//! transaction. Existing frozen nodes are never overwritten.

const LEAF_DOMAIN_TAG: u8 = 0x00;
const INTERIOR_DOMAIN_TAG: u8 = 0x01;
const DIGEST_LEN: usize = 32;
const LEAF_PREIMAGE_LEN: usize = 65;
const INTERIOR_PREIMAGE_LEN: usize = 65;
const MAX_TREE_LEVELS: u32 = 63;
const MAX_PROOF_NODES: usize = 65;
const HALF_DIGEST_LEN: usize = 16;

/// SQLite DDL for the persistent Crosby-Wallach history tree node table.
pub(super) const HISTORY_TREE_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS history_tree_nodes (
    level INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    digest BLOB NOT NULL,
    PRIMARY KEY (level, idx)
);
"#;

/// Unsigned summary of the committed Merkle history tree head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryTreeHead {
    /// Total number of leaves committed (`current_sequence + 1`).
    pub tree_size: u64,
    /// 32-byte BLAKE3 Merkle root over leaves `0..tree_size`.
    pub root: [u8; DIGEST_LEN],
    /// Tip workspace revision (`seq = tree_size - 1`).
    pub head_revision: mneme_core::WorkspaceRevisionId,
    /// Eligibility generation at the tip revision.
    pub eligibility_generation: u64,
}

/// Self-contained Merkle inclusion proof for one committed leaf sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    /// Zero-based leaf sequence index (`0 <= leaf_index < tree_size`).
    pub leaf_index: u64,
    /// Number of leaves in the committed tree (`tree_size >= 1`).
    pub tree_size: u64,
    /// 32-byte BLAKE3 leaf digest at `leaf_index`.
    pub leaf_digest: [u8; DIGEST_LEN],
    /// Sibling 32-byte digests along the path from leaf to root.
    pub audit_path: Vec<[u8; DIGEST_LEN]>,
}

/// Self-contained RFC 6962 / Crosby-Wallach append-only consistency proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyProof {
    /// Number of leaves in the older committed tree (`1 <= old_size <= new_size`).
    pub old_size: u64,
    /// Number of leaves in the newer committed tree.
    pub new_size: u64,
    /// Proof node digests (for non-power-of-two `old_size`, `nodes[0]` is the
    /// starting subtree digest; remaining entries are sibling hashes).
    pub nodes: Vec<[u8; DIGEST_LEN]>,
}

/// Compute the BLAKE3 leaf digest for one committed revision from raw 32-byte manifest digest.
pub fn hash_history_leaf_bytes(
    seq: u64,
    revision_id: mneme_core::WorkspaceRevisionId,
    manifest_digest_bytes: [u8; DIGEST_LEN],
    eligibility_generation: u64,
) -> [u8; DIGEST_LEN] {
    let mut preimage = [0_u8; LEAF_PREIMAGE_LEN];
    preimage[0] = LEAF_DOMAIN_TAG;
    preimage[1..9].copy_from_slice(&seq.to_le_bytes());
    preimage[9..25].copy_from_slice(revision_id.as_bytes());
    preimage[25..57].copy_from_slice(&manifest_digest_bytes);
    preimage[57..65].copy_from_slice(&eligibility_generation.to_le_bytes());
    *blake3::hash(&preimage).as_bytes()
}

/// Compute the BLAKE3 leaf digest for one committed revision:
/// `BLAKE3(0x00 || seq_le || revision_id || manifest_digest || eligibility_generation_le)`.
pub fn hash_history_leaf(
    seq: u64,
    revision_id: mneme_core::WorkspaceRevisionId,
    manifest_digest: mneme_core::ContentDigest,
    eligibility_generation: u64,
) -> [u8; DIGEST_LEN] {
    hash_history_leaf_bytes(
        seq,
        revision_id,
        *manifest_digest.as_bytes(),
        eligibility_generation,
    )
}

/// Compute the BLAKE3 interior node digest `BLAKE3(0x01 || left || right)`.
pub fn hash_history_interior(left: [u8; DIGEST_LEN], right: [u8; DIGEST_LEN]) -> [u8; DIGEST_LEN] {
    let mut preimage = [0_u8; INTERIOR_PREIMAGE_LEN];
    preimage[0] = INTERIOR_DOMAIN_TAG;
    preimage[1..33].copy_from_slice(&left);
    preimage[33..65].copy_from_slice(&right);
    *blake3::hash(&preimage).as_bytes()
}

/// Convert a 32-byte digest into the Lean-proved kernel [`mneme_kernel::hashing::Digest`].
pub fn digest_to_kernel(bytes: [u8; DIGEST_LEN]) -> mneme_kernel::hashing::Digest {
    let mut hi_bytes = [0_u8; HALF_DIGEST_LEN];
    let mut lo_bytes = [0_u8; HALF_DIGEST_LEN];
    hi_bytes.copy_from_slice(&bytes[..HALF_DIGEST_LEN]);
    lo_bytes.copy_from_slice(&bytes[HALF_DIGEST_LEN..]);
    mneme_kernel::hashing::Digest {
        hi: u128::from_be_bytes(hi_bytes),
        lo: u128::from_be_bytes(lo_bytes),
    }
}

impl InclusionProof {
    /// Verify this inclusion proof against `expected_root` via the Lean-proved kernel.
    pub fn verify(&self, expected_root: [u8; DIGEST_LEN]) -> bool {
        if self.tree_size == 0 || self.leaf_index >= self.tree_size {
            return false;
        }
        let mut fn_idx = self.leaf_index;
        let mut sn_idx = self.tree_size.saturating_sub(1);
        let mut current = self.leaf_digest;
        let mut steps = Vec::with_capacity(self.audit_path.len());
        for sibling in &self.audit_path {
            if sn_idx == 0 {
                return false;
            }
            let is_left = (fn_idx & 1) == 1 || fn_idx == sn_idx;
            let (side, left, right) = if is_left {
                (
                    mneme_kernel::history_tree::SiblingSide::Left,
                    *sibling,
                    current,
                )
            } else {
                (
                    mneme_kernel::history_tree::SiblingSide::Right,
                    current,
                    *sibling,
                )
            };
            let parent = hash_history_interior(left, right);
            steps.push(mneme_kernel::history_tree::InclusionStep {
                side,
                left: digest_to_kernel(left),
                right: digest_to_kernel(right),
                parent: digest_to_kernel(parent),
            });
            current = parent;
            if is_left {
                while fn_idx != 0 && (fn_idx & 1) == 0 {
                    fn_idx >>= 1;
                    sn_idx >>= 1;
                }
            }
            fn_idx >>= 1;
            sn_idx >>= 1;
        }
        let check = mneme_kernel::history_tree::InclusionCheck {
            leaf_index: self.leaf_index,
            tree_size: self.tree_size,
            leaf_digest: digest_to_kernel(self.leaf_digest),
            expected_root: digest_to_kernel(expected_root),
        };
        mneme_kernel::history_tree::verify_inclusion_proof(&check, &steps)
    }
}

impl ConsistencyProof {
    /// Verify that `old_root` at `old_size` is an append-only prefix of `new_root`
    /// at `new_size` via the Lean-proved kernel.
    pub fn verify(&self, old_root: [u8; DIGEST_LEN], new_root: [u8; DIGEST_LEN]) -> bool {
        if self.old_size == 0 || self.old_size > self.new_size {
            return false;
        }
        if self.old_size == self.new_size {
            let check = mneme_kernel::history_tree::ConsistencyCheck {
                old_size: self.old_size,
                new_size: self.new_size,
                old_root: digest_to_kernel(old_root),
                new_root: digest_to_kernel(new_root),
                initial_digest: digest_to_kernel(old_root),
            };
            return self.nodes.is_empty()
                && mneme_kernel::history_tree::verify_consistency_proof(&check, &[]);
        }
        let mut fn_idx = self.old_size.saturating_sub(1);
        let mut sn_idx = self.new_size.saturating_sub(1);
        while (fn_idx & 1) == 1 {
            fn_idx >>= 1;
            sn_idx >>= 1;
        }
        let (initial_digest, sibling_slice) = if fn_idx == 0 {
            (old_root, self.nodes.as_slice())
        } else {
            let Some((first, rest)) = self.nodes.split_first() else {
                return false;
            };
            (*first, rest)
        };
        let Some(steps) = build_consistency_steps(fn_idx, sn_idx, initial_digest, sibling_slice)
        else {
            return false;
        };
        let check = mneme_kernel::history_tree::ConsistencyCheck {
            old_size: self.old_size,
            new_size: self.new_size,
            old_root: digest_to_kernel(old_root),
            new_root: digest_to_kernel(new_root),
            initial_digest: digest_to_kernel(initial_digest),
        };
        mneme_kernel::history_tree::verify_consistency_proof(&check, &steps)
    }
}

fn build_consistency_steps(
    mut fn_idx: u64,
    mut sn_idx: u64,
    initial_digest: [u8; DIGEST_LEN],
    sibling_slice: &[[u8; DIGEST_LEN]],
) -> Option<Vec<mneme_kernel::history_tree::ConsistencyStep>> {
    let mut old_acc = initial_digest;
    let mut new_acc = initial_digest;
    let mut steps = Vec::with_capacity(sibling_slice.len());
    for sibling in sibling_slice {
        if sn_idx == 0 {
            return None;
        }
        let is_left = (fn_idx & 1) == 1 || fn_idx == sn_idx;
        if is_left {
            let old_parent = hash_history_interior(*sibling, old_acc);
            let new_parent = hash_history_interior(*sibling, new_acc);
            steps.push(mneme_kernel::history_tree::ConsistencyStep {
                side: mneme_kernel::history_tree::SiblingSide::Left,
                sibling: digest_to_kernel(*sibling),
                old_right: digest_to_kernel(old_acc),
                old_parent: digest_to_kernel(old_parent),
                new_child: digest_to_kernel(new_acc),
                new_parent: digest_to_kernel(new_parent),
            });
            old_acc = old_parent;
            new_acc = new_parent;
            while fn_idx != 0 && (fn_idx & 1) == 0 {
                fn_idx >>= 1;
                sn_idx >>= 1;
            }
        } else {
            let new_parent = hash_history_interior(new_acc, *sibling);
            steps.push(mneme_kernel::history_tree::ConsistencyStep {
                side: mneme_kernel::history_tree::SiblingSide::Right,
                sibling: digest_to_kernel(*sibling),
                old_right: digest_to_kernel(old_acc),
                old_parent: digest_to_kernel(old_acc),
                new_child: digest_to_kernel(new_acc),
                new_parent: digest_to_kernel(new_parent),
            });
            new_acc = new_parent;
        }
        fn_idx >>= 1;
        sn_idx >>= 1;
    }
    Some(steps)
}

/// Largest power of two strictly less than `length` (requires `length >= 2`).
const fn largest_power_of_two_less_than(length: u64) -> u64 {
    let shift = MAX_TREE_LEVELS.saturating_sub(length.saturating_sub(1).leading_zeros());
    1_u64 << shift
}

/// Append one leaf at `seq` and update all newly completed ancestor subtrees
/// in `history_tree_nodes` in `O(log N)` SQLite operations.
pub(crate) fn append_leaf(
    connection: &rusqlite::Connection,
    seq: u64,
    leaf_digest: [u8; DIGEST_LEN],
) -> crate::error::Result<()> {
    let mut level: u32 = 0;
    let mut idx = seq;
    let mut current = leaf_digest;
    insert_node(connection, level, idx, current)?;
    while (idx & 1) == 1 {
        let left = load_node(connection, level, idx.saturating_sub(1))?;
        current = hash_history_interior(left, current);
        level = level.saturating_add(1);
        idx >>= 1;
        insert_node(connection, level, idx, current)?;
    }
    Ok(())
}

/// Ensure `history_tree_nodes` exists and covers every committed revision in
/// `revisions` (backfilling legacy ledgers once on open).
pub(super) fn ensure_history_tree(
    connection: &mut rusqlite::Connection,
) -> crate::error::Result<()> {
    connection.execute_batch(HISTORY_TREE_DDL)?;
    let expected_leaves = super::meta_u64(connection, super::META_CURRENT_SEQUENCE)?
        .checked_add(1)
        .ok_or_else(|| crate::error::Failure::InvalidCommand("sequence overflow".to_owned()))?;
    let existing_leaves: i64 = connection.query_row(
        "SELECT COUNT(*) FROM history_tree_nodes WHERE level = 0",
        [],
        |row| row.get(0),
    )?;
    if super::db_u64(existing_leaves, "history tree leaf count")? == expected_leaves {
        return Ok(());
    }
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let leaves_in_tx: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM history_tree_nodes WHERE level = 0",
        [],
        |row| row.get(0),
    )?;
    if super::db_u64(leaves_in_tx, "history tree leaf count")? == expected_leaves {
        transaction.commit()?;
        return Ok(());
    }
    transaction.execute("DELETE FROM history_tree_nodes", [])?;
    let rows = read_all_revision_leaves(&transaction, expected_leaves)?;
    for (seq, leaf_digest) in rows {
        append_leaf(&transaction, seq, leaf_digest)?;
    }
    transaction.commit()?;
    Ok(())
}

fn read_all_revision_leaves(
    connection: &rusqlite::Connection,
    expected_leaves: u64,
) -> crate::error::Result<Vec<(u64, [u8; DIGEST_LEN])>> {
    let mut statement = connection.prepare(
        "SELECT sequence, revision_id, manifest_digest, eligibility_generation
         FROM revisions ORDER BY sequence ASC",
    )?;
    let mut rows = statement.query([])?;
    let capacity = usize::try_from(expected_leaves).map_err(|_| {
        crate::error::Failure::InvalidCommand("history tree leaf count exceeds usize".to_owned())
    })?;
    let mut leaves = Vec::with_capacity(capacity);
    while let Some(row) = rows.next()? {
        let seq = super::db_u64(row.get::<_, i64>(0)?, "sequence")?;
        let revision_blob: Vec<u8> = row.get(1)?;
        let manifest_blob: Vec<u8> = row.get(2)?;
        let generation = super::db_u64(row.get::<_, i64>(3)?, "generation")?;
        let revision_id = super::revision_from_blob(&revision_blob)?;
        let manifest_bytes = super::digest_32(&manifest_blob)?;
        leaves.push((
            seq,
            hash_history_leaf_bytes(seq, revision_id, manifest_bytes, generation),
        ));
    }
    Ok(leaves)
}

fn insert_node(
    connection: &rusqlite::Connection,
    level: u32,
    idx: u64,
    digest: [u8; DIGEST_LEN],
) -> crate::error::Result<()> {
    connection.execute(
        "INSERT OR REPLACE INTO history_tree_nodes (level, idx, digest) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            i64::from(level),
            super::db_i64(idx, "history tree index")?,
            digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn load_node(
    connection: &rusqlite::Connection,
    level: u32,
    idx: u64,
) -> crate::error::Result<[u8; DIGEST_LEN]> {
    let blob: Vec<u8> = connection.query_row(
        "SELECT digest FROM history_tree_nodes WHERE level = ?1 AND idx = ?2",
        rusqlite::params![i64::from(level), super::db_i64(idx, "history tree index")?],
        |row| row.get(0),
    )?;
    <[u8; DIGEST_LEN]>::try_from(blob.as_slice()).map_err(|_| {
        crate::error::Failure::InvalidCommand(format!(
            "corrupt history_tree_nodes digest at level {level} idx {idx}"
        ))
    })
}

/// Compute `MTH(start..end)` in `O(log(end - start))` primary-key lookups.
///
/// Requires `start < end` and `start` aligned to every power-of-two chunk
/// covering `end - start` (true for every prefix and RFC 6962 subproof range).
pub(crate) fn subtree_root(
    connection: &rusqlite::Connection,
    start: u64,
    end: u64,
) -> crate::error::Result<[u8; DIGEST_LEN]> {
    if start >= end {
        return Err(crate::error::Failure::InvalidCommand(
            "history tree range must be non-empty".to_owned(),
        ));
    }
    let mut rem = end.saturating_sub(start);
    let mut pos = start;
    let mut peaks = Vec::with_capacity(MAX_PROOF_NODES);
    while rem > 0 {
        let level = MAX_TREE_LEVELS.saturating_sub(rem.leading_zeros());
        let span = 1_u64 << level;
        let idx = pos >> level;
        peaks.push(load_node(connection, level, idx)?);
        pos = pos.saturating_add(span);
        rem = rem.saturating_sub(span);
    }
    let Some(mut acc) = peaks.pop() else {
        return Err(crate::error::Failure::InvalidCommand(
            "empty history tree peak list".to_owned(),
        ));
    };
    while let Some(left_peak) = peaks.pop() {
        acc = hash_history_interior(left_peak, acc);
    }
    Ok(acc)
}

/// Compute the Merkle root for a prefix of `tree_size` leaves (`1 <= tree_size`).
pub(crate) fn root_at(
    connection: &rusqlite::Connection,
    tree_size: u64,
) -> crate::error::Result<[u8; DIGEST_LEN]> {
    subtree_root(connection, 0, tree_size)
}

/// Generate a Merkle inclusion proof for `leaf_index` within `tree_size` leaves.
pub(crate) fn build_inclusion_proof(
    connection: &rusqlite::Connection,
    leaf_index: u64,
    tree_size: u64,
) -> crate::error::Result<InclusionProof> {
    if tree_size == 0 || leaf_index >= tree_size {
        return Err(crate::error::Failure::InvalidCommand(format!(
            "leaf index {leaf_index} out of bounds for tree size {tree_size}"
        )));
    }
    let leaf_digest = load_node(connection, 0, leaf_index)?;
    let mut lo = 0_u64;
    let mut hi = tree_size;
    let mut audit_path = Vec::with_capacity(MAX_PROOF_NODES);
    while hi.saturating_sub(lo) > 1 {
        let split = largest_power_of_two_less_than(hi.saturating_sub(lo));
        let mid = lo.saturating_add(split);
        if leaf_index < mid {
            audit_path.push(subtree_root(connection, mid, hi)?);
            hi = mid;
        } else {
            audit_path.push(subtree_root(connection, lo, mid)?);
            lo = mid;
        }
    }
    audit_path.reverse();
    Ok(InclusionProof {
        leaf_index,
        tree_size,
        leaf_digest,
        audit_path,
    })
}

/// Generate an append-only RFC 6962 consistency proof from `old_size` to `new_size`.
pub(crate) fn build_consistency_proof(
    connection: &rusqlite::Connection,
    old_size: u64,
    new_size: u64,
) -> crate::error::Result<ConsistencyProof> {
    if old_size == 0 || old_size > new_size {
        return Err(crate::error::Failure::InvalidCommand(format!(
            "invalid consistency proof range {old_size}..{new_size}"
        )));
    }
    if old_size == new_size {
        return Ok(ConsistencyProof {
            old_size,
            new_size,
            nodes: Vec::new(),
        });
    }
    let mut lo = 0_u64;
    let mut hi = new_size;
    let mut prefix_len = old_size;
    let mut is_complete_subtree = true;
    let mut nodes = Vec::with_capacity(MAX_PROOF_NODES);
    while prefix_len < hi.saturating_sub(lo) {
        let split = largest_power_of_two_less_than(hi.saturating_sub(lo));
        let mid = lo.saturating_add(split);
        if prefix_len <= split {
            nodes.push(subtree_root(connection, mid, hi)?);
            hi = mid;
        } else {
            nodes.push(subtree_root(connection, lo, mid)?);
            lo = mid;
            prefix_len = prefix_len.saturating_sub(split);
            is_complete_subtree = false;
        }
    }
    if !is_complete_subtree {
        nodes.push(subtree_root(connection, lo, hi)?);
    }
    nodes.reverse();
    Ok(ConsistencyProof {
        old_size,
        new_size,
        nodes,
    })
}

/// Read the current committed [`HistoryTreeHead`] for a workspace ledger.
pub(super) fn read_tree_head(
    connection: &rusqlite::Connection,
) -> crate::error::Result<HistoryTreeHead> {
    let sequence = super::meta_u64(connection, super::META_CURRENT_SEQUENCE)?;
    let tree_size = sequence
        .checked_add(1)
        .ok_or_else(|| crate::error::Failure::InvalidCommand("sequence overflow".to_owned()))?;
    let revision_blob = super::meta_blob(connection, super::META_CURRENT_REVISION)?;
    let head_revision = super::revision_from_blob(&revision_blob)?;
    let eligibility_generation = super::meta_u64(connection, super::META_GENERATION)?;
    let root = root_at(connection, tree_size)?;
    Ok(HistoryTreeHead {
        tree_size,
        root,
        head_revision,
        eligibility_generation,
    })
}

impl super::Workspace {
    /// Current committed Crosby-Wallach Merkle history tree head.
    pub fn history_tree_head(&self) -> crate::error::Result<HistoryTreeHead> {
        read_tree_head(&self.connection)
    }

    /// Merkle root hash for the prefix of `tree_size` committed revisions.
    pub fn history_tree_root_at(&self, tree_size: u64) -> crate::error::Result<[u8; DIGEST_LEN]> {
        let head = read_tree_head(&self.connection)?;
        if tree_size == 0 || tree_size > head.tree_size {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "requested tree size {tree_size} outside 1..={}",
                head.tree_size
            )));
        }
        root_at(&self.connection, tree_size)
    }

    /// Generate an `O(log N)` Merkle inclusion proof for `seq` within `tree_size`.
    pub fn history_inclusion_proof(
        &self,
        seq: u64,
        tree_size: u64,
    ) -> crate::error::Result<InclusionProof> {
        let head = read_tree_head(&self.connection)?;
        if tree_size == 0 || tree_size > head.tree_size || seq >= tree_size {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "invalid inclusion proof request seq={seq} tree_size={tree_size} (current={})",
                head.tree_size
            )));
        }
        build_inclusion_proof(&self.connection, seq, tree_size)
    }

    /// Generate an `O(log N)` RFC 6962 append-only consistency proof from `old_size` to `new_size`.
    pub fn history_consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> crate::error::Result<ConsistencyProof> {
        let head = read_tree_head(&self.connection)?;
        if old_size == 0 || old_size > new_size || new_size > head.tree_size {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "invalid consistency proof request {old_size}..{new_size} (current={})",
                head.tree_size
            )));
        }
        build_consistency_proof(&self.connection, old_size, new_size)
    }
}

/// Standalone SQLite-backed history tree handle for high-scale verification and benchmarking.
pub struct HistoryTreeDb {
    connection: rusqlite::Connection,
}

impl HistoryTreeDb {
    /// Open an in-memory SQLite database initialized with `history_tree_nodes`.
    pub fn open_in_memory() -> crate::error::Result<Self> {
        let connection = rusqlite::Connection::open_in_memory()?;
        connection.execute_batch(HISTORY_TREE_DDL)?;
        Ok(Self { connection })
    }

    /// Append a batch of sequential `(seq, leaf_digest)` leaves inside one SQLite transaction.
    pub fn append_batch(&mut self, leaves: &[(u64, [u8; DIGEST_LEN])]) -> crate::error::Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for (seq, digest) in leaves {
            append_leaf(&tx, *seq, *digest)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Append a single leaf at `seq` in `O(log N)`.
    pub fn append(&self, seq: u64, leaf_digest: [u8; DIGEST_LEN]) -> crate::error::Result<()> {
        append_leaf(&self.connection, seq, leaf_digest)
    }

    /// Compute the Merkle root for `tree_size` leaves.
    pub fn root_at(&self, tree_size: u64) -> crate::error::Result<[u8; DIGEST_LEN]> {
        root_at(&self.connection, tree_size)
    }

    /// Generate an inclusion proof for `leaf_index` in `tree_size`.
    pub fn inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> crate::error::Result<InclusionProof> {
        build_inclusion_proof(&self.connection, leaf_index, tree_size)
    }

    /// Generate a consistency proof from `old_size` to `new_size`.
    pub fn consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> crate::error::Result<ConsistencyProof> {
        build_consistency_proof(&self.connection, old_size, new_size)
    }
}
