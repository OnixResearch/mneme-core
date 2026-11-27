//! 32-depth BLAKE3 GGM puncturable symmetric key tree (`keytree/<scope>.db`)
//! and signed [`KeyPunctureBarrier`]s for cryptographic erasure.
//!
//! Based on:
//! - D. Boneh & R. J. Lipton, *A Revocable Backup System* (USENIX Security 1996);
//! - M. D. Green & I. Miers, *Forward Secure Asynchronous Messaging from
//!   Puncturable Encryption* (IEEE S&P 2015);
//! - J. Reardon et al., *SoK: Secure Data Deletion* (IEEE S&P 2013).
//!
//! Each encrypted scope holds a separate mutable SQLite key tree under
//! `keytree/<scope-hash>.db` (strictly excluded from `blobs/` and `.mneme`
//! backups), initialized with one 32-byte CSPRNG root seed covering `2^32`
//! leaf key slots. Puncturing a `key_slot` replaces its covering ancestor with
//! at most 32 sibling subtree keys (`<= 1 KiB`), zeroizes and overwrites the
//! ancestor key, and makes every ciphertext encrypted under `key_slot`
//! permanently unreadable while 100% of surviving slots continue decrypting
//! with zero re-encryption.
// Octet structural exception: domain-qualified names and trait-only imports are intentional

use rusqlite::OptionalExtension;
use zeroize::Zeroize;

/// Store-owned directory holding mutable per-scope GGM key trees.
///
/// Strictly separate from `blobs/` and never included in immutable `.mneme`
/// backups.
pub const KEYTREE_DIRECTORY: &str = "keytree";

/// Binary tree depth (`2^32` leaf key slots per scope).
pub const GGM_DEPTH: u8 = 32;

const KEY_LEN_BYTES: usize = 32;
const ZERO_KEY: [u8; KEY_LEN_BYTES] = [0_u8; KEY_LEN_BYTES];
const GGM_LEFT_DOMAIN: &[u8] = b"mneme.ggm.left.v1\0";
const GGM_RIGHT_DOMAIN: &[u8] = b"mneme.ggm.right.v1\0";
const GGM_LEAF_DEK_DOMAIN: &[u8] = b"mneme.ggm.leaf-dek.v1\0";
const GGM_CDC_CHUNK_DOMAIN: &[u8] = b"mneme.ggm.cdc-chunk.v1\0";
const PUNCTURE_BARRIER_DOMAIN: &[u8] = b"mneme.keytree.puncture-barrier.v1\0";
const PUNCTURE_BARRIER_LABEL: &str = "key-puncture-barrier";
const META_SCOPE: &str = "scope";
const META_NEXT_SLOT: &str = "next_slot";

const KEYTREE_DDL: &str = r#"
PRAGMA secure_delete = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS subtree_keys (
    depth INTEGER NOT NULL,
    prefix INTEGER NOT NULL,
    key_bytes BLOB NOT NULL,
    PRIMARY KEY (depth, prefix)
);
CREATE TABLE IF NOT EXISTS slot_bindings (
    digest BLOB PRIMARY KEY,
    key_slot INTEGER NOT NULL,
    record_id BLOB,
    revision_id BLOB
);
CREATE INDEX IF NOT EXISTS slot_bindings_record
    ON slot_bindings(record_id, revision_id);
CREATE TABLE IF NOT EXISTS punctured_slots (
    key_slot INTEGER PRIMARY KEY,
    generation INTEGER NOT NULL
);
"#;

/// Outcome of puncturing one leaf `key_slot` in a scope's GGM key tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PunctureReport {
    /// Leaf slot that was punctured.
    pub key_slot: u32,
    /// Eligibility generation at which the puncture was established.
    pub generation: u64,
    /// Number of sibling subtree keys written (`<= 32`, i.e., `<= 1 KiB`).
    pub sibling_keys_written: u8,
    /// Whether the slot had already been punctured previously.
    pub was_already_punctured: bool,
}

/// Signed cryptographic erasure barrier synchronized across peers and portable
/// retention bundles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPunctureBarrier {
    pub scope: mneme_core::ScopeId,
    pub key_slot: u32,
    pub generation: u64,
    pub digest: Option<mneme_core::ContentDigest>,
    pub signer_key_id: Option<String>,
    pub signature_hex: Option<String>,
}

impl KeyPunctureBarrier {
    /// Canonical domain-separated bytes signed by the issuing device key.
    pub fn signing_payload(&self) -> Vec<u8> {
        let unsigned = mneme_core::Value::record_named(
            PUNCTURE_BARRIER_LABEL,
            vec![
                self.scope.to_value(),
                mneme_core::Value::integer(i64::from(self.key_slot)),
                mneme_core::Value::integer(self.generation),
                match self.digest {
                    Some(digest) => digest.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
            ],
        );
        let encoded = mneme_core::binary::encode(&unsigned);
        let mut out =
            Vec::with_capacity(PUNCTURE_BARRIER_DOMAIN.len().saturating_add(encoded.len()));
        out.extend_from_slice(PUNCTURE_BARRIER_DOMAIN);
        out.extend_from_slice(&encoded);
        out
    }

    /// Encode as canonical Preserves `<key-puncture-barrier …>`.
    pub fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            PUNCTURE_BARRIER_LABEL,
            vec![
                self.scope.to_value(),
                mneme_core::Value::integer(i64::from(self.key_slot)),
                mneme_core::Value::integer(self.generation),
                match self.digest {
                    Some(digest) => digest.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
                match &self.signer_key_id {
                    Some(id) => mneme_core::Value::string(id.clone()),
                    None => mneme_core::Value::symbol("none"),
                },
                match &self.signature_hex {
                    Some(sig) => mneme_core::Value::string(sig.clone()),
                    None => mneme_core::Value::symbol("none"),
                },
            ],
        )
    }

    /// Decode a canonical Preserves `<key-puncture-barrier …>`.
    pub fn from_value(value: &mneme_core::Value) -> Result<Self, String> {
        let record = value
            .as_record()
            .ok_or_else(|| "key puncture barrier must be a record".to_owned())?;
        if record.label() != &mneme_core::Value::symbol(PUNCTURE_BARRIER_LABEL)
            || record.fields().len() != 6
        {
            return Err("expected 6-field <key-puncture-barrier …>".to_owned());
        }
        let scope = mneme_core::ScopeId::from_value(
            &record.fields()[0],
            &mneme_core::Path::root().field("scope"),
        )
        .map_err(|diagnostic| diagnostic.to_string())?;
        let slot_i64 = record.fields()[1]
            .as_integer()
            .and_then(|int| int.to_i64())
            .ok_or_else(|| "key puncture barrier key_slot must be an integer".to_owned())?;
        let key_slot = u32::try_from(slot_i64)
            .map_err(|_| "key puncture barrier key_slot out of u32 range".to_owned())?;
        let gen_i64 = record.fields()[2]
            .as_integer()
            .and_then(|int| int.to_i64())
            .ok_or_else(|| "key puncture barrier generation must be an integer".to_owned())?;
        let generation = u64::try_from(gen_i64)
            .map_err(|_| "key puncture barrier generation must be non-negative".to_owned())?;
        let digest = match &record.fields()[3] {
            mneme_core::Value::Symbol(sym) if sym.as_str() == "none" => None,
            other => Some(
                mneme_core::ContentDigest::from_value(
                    other,
                    &mneme_core::Path::root().field("digest"),
                )
                .map_err(|diagnostic| diagnostic.to_string())?,
            ),
        };
        let signer_key_id = parse_optional_string(&record.fields()[4], "signer_key_id")?;
        let signature_hex = parse_optional_string(&record.fields()[5], "signature_hex")?;
        Ok(Self {
            scope,
            key_slot,
            generation,
            digest,
            signer_key_id,
            signature_hex,
        })
    }
}

fn parse_optional_string(value: &mneme_core::Value, field: &str) -> Result<Option<String>, String> {
    match value {
        mneme_core::Value::Symbol(sym) if sym.as_str() == "none" => Ok(None),
        other => other
            .as_string()
            .map(|text| Some(text.to_owned()))
            .ok_or_else(|| format!("key puncture barrier {field} must be a string or none")),
    }
}

/// Filesystem path of the mutable SQLite key tree for `scope` under `root`.
pub fn db_path(root: &std::path::Path, scope: &mneme_core::ScopeId) -> std::path::PathBuf {
    let scope_hash = blake3::hash(scope.to_string().as_bytes());
    root.join(KEYTREE_DIRECTORY)
        .join(format!("{}.db", scope_hash.to_hex()))
}

/// Parse a canonical `"<class>:<local>"` scope string.
pub(crate) fn parse_scope_str(text: &str) -> Option<mneme_core::ScopeId> {
    let (class_str, local) = text.split_once(':')?;
    let class = mneme_core::ScopeClass::parse(class_str)?;
    mneme_core::ScopeId::new(class, local).ok()
}

/// Whether `scope` uses `MNENC01\0` GGM-encrypted blob framing in `root`.
///
/// Default-on for `confidential` scopes (local name `"confidential"` or
/// prefixed with `"confidential/"` / `"confidential:"`), and opt-in for any
/// other scope whose key tree has been initialized.
pub fn is_scope_encrypted(root: &std::path::Path, scope: &mneme_core::ScopeId) -> bool {
    let local = scope.local();
    let is_confidential = local == "confidential"
        || local.starts_with("confidential/")
        || local.starts_with("confidential:")
        || local.starts_with("confidential-")
        || local.starts_with("confidential_")
        || local.starts_with("confidential.");
    is_confidential || db_path(root, scope).exists()
}

/// Mutable per-scope 32-depth BLAKE3 GGM puncturable symmetric key tree.
pub struct PuncturableTree {
    scope: mneme_core::ScopeId,
    connection: rusqlite::Connection,
}

impl PuncturableTree {
    /// Open or initialize the GGM key tree for `scope` under `root`.
    pub fn open_or_init(
        root: &std::path::Path,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<Self> {
        let dir = root.join(KEYTREE_DIRECTORY);
        std::fs::create_dir_all(&dir).map_err(|error| crate::error::Failure::io(&dir, error))?;
        let path = db_path(root, scope);
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(KEYTREE_DDL)?;
        let tree = Self {
            scope: scope.clone(),
            connection,
        };
        tree.ensure_initialized()?;
        Ok(tree)
    }

    /// Open an existing GGM key tree for `scope` without creating a new one.
    pub fn open_existing(
        root: &std::path::Path,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<Option<Self>> {
        let path = db_path(root, scope);
        if !path.exists() {
            return Ok(None);
        }
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch("PRAGMA secure_delete = ON; PRAGMA synchronous = FULL;")?;
        Ok(Some(Self {
            scope: scope.clone(),
            connection,
        }))
    }

    /// Scope this key tree belongs to.
    pub fn scope(&self) -> &mneme_core::ScopeId {
        &self.scope
    }

    #[allow(unknown_lints, ambient_random)] // CSPRNG root seed initialization for per-scope key tree
    fn ensure_initialized(&self) -> crate::error::Result<()> {
        let existing: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                rusqlite::params![META_SCOPE],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_some() {
            return Ok(());
        }
        let mut root_seed = zeroize::Zeroizing::new([0_u8; KEY_LEN_BYTES]);
        getrandom::fill(root_seed.as_mut_slice())
            .map_err(|error| crate::error::Failure::Random(error.to_string()))?;
        let scope_str = self.scope.to_string();
        self.connection.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![META_SCOPE, scope_str.as_bytes()],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![META_NEXT_SLOT, 0_u32.to_le_bytes().as_slice()],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO subtree_keys (depth, prefix, key_bytes) VALUES (0, 0, ?1)",
            rusqlite::params![root_seed.as_slice()],
        )?;
        Ok(())
    }

    /// Allocate (or return an existing) leaf `key_slot` for `digest`, optionally
    /// recording the owning `(record_id, revision_id)` so `Forget` can locate it.
    pub fn allocate_slot(
        &mut self,
        digest: mneme_core::ContentDigest,
        record_id: Option<mneme_core::RecordId>,
        revision_id: Option<mneme_core::RevisionId>,
    ) -> crate::error::Result<u32> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(slot) = lookup_slot_in(&transaction, digest)? {
            if record_id.is_some() {
                transaction.execute(
                    "UPDATE slot_bindings
                     SET record_id = COALESCE(record_id, ?2),
                         revision_id = COALESCE(revision_id, ?3)
                     WHERE digest = ?1",
                    rusqlite::params![
                        digest.as_bytes().as_slice(),
                        record_id.map(|id| id.as_bytes().to_vec()),
                        revision_id.map(|id| id.as_bytes().to_vec()),
                    ],
                )?;
            }
            transaction.commit()?;
            return Ok(slot);
        }
        let slot = read_next_slot(&transaction)?;
        let next = slot.checked_add(1).ok_or_else(|| {
            crate::error::Failure::ValueOutOfRange("GGM keytree exhausted 2^32 slots")
        })?;
        transaction.execute(
            "UPDATE meta SET value = ?1 WHERE key = ?2",
            rusqlite::params![next.to_le_bytes().as_slice(), META_NEXT_SLOT],
        )?;
        transaction.execute(
            "INSERT INTO slot_bindings (digest, key_slot, record_id, revision_id)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                digest.as_bytes().as_slice(),
                i64::from(slot),
                record_id.map(|id| id.as_bytes().to_vec()),
                revision_id.map(|id| id.as_bytes().to_vec()),
            ],
        )?;
        transaction.commit()?;
        Ok(slot)
    }

    /// Associate a known `key_slot` with `digest` and optional `(record_id, revision_id)`.
    pub fn bind_slot(
        &mut self,
        digest: mneme_core::ContentDigest,
        key_slot: u32,
        record_id: Option<mneme_core::RecordId>,
        revision_id: Option<mneme_core::RevisionId>,
    ) -> crate::error::Result<()> {
        self.connection.execute(
            "INSERT INTO slot_bindings (digest, key_slot, record_id, revision_id)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(digest) DO UPDATE SET
               record_id = COALESCE(slot_bindings.record_id, excluded.record_id),
               revision_id = COALESCE(slot_bindings.revision_id, excluded.revision_id)",
            rusqlite::params![
                digest.as_bytes().as_slice(),
                i64::from(key_slot),
                record_id.map(|id| id.as_bytes().to_vec()),
                revision_id.map(|id| id.as_bytes().to_vec()),
            ],
        )?;
        Ok(())
    }

    /// Look up the bound `key_slot` for `digest`, if any.
    pub fn slot_for_digest(
        &self,
        digest: mneme_core::ContentDigest,
    ) -> crate::error::Result<Option<u32>> {
        lookup_slot_in(&self.connection, digest)
    }

    /// Look up all `key_slot`s bound to `record_id` (optionally filtered by `revision_id`).
    pub fn slots_for_record(
        &self,
        record_id: mneme_core::RecordId,
        revision_id: Option<mneme_core::RevisionId>,
    ) -> crate::error::Result<Vec<(u32, [u8; 32])>> {
        let rows: Vec<(i64, Vec<u8>)> = if let Some(rev) = revision_id {
            let mut stmt = self.connection.prepare(
                "SELECT key_slot, digest FROM slot_bindings
                 WHERE record_id = ?1 AND revision_id = ?2
                 ORDER BY key_slot",
            )?;
            stmt.query_map(
                rusqlite::params![record_id.as_bytes().as_slice(), rev.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?
        } else {
            let mut stmt = self.connection.prepare(
                "SELECT key_slot, digest FROM slot_bindings
                 WHERE record_id = ?1
                 ORDER BY key_slot",
            )?;
            stmt.query_map(rusqlite::params![record_id.as_bytes().as_slice()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut out = Vec::with_capacity(rows.len());
        for (slot_i64, digest_bytes) in rows {
            if let (Ok(slot), Ok(digest)) = (
                u32::try_from(slot_i64),
                <[u8; KEY_LEN_BYTES]>::try_from(digest_bytes.as_slice()),
            ) {
                out.push((slot, digest));
            }
        }
        Ok(out)
    }

    /// Derive the 32-byte XChaCha20-Poly1305 DEK for `key_slot`.
    ///
    /// Fails closed with [`crate::error::Failure::CryptographicallyErased`] if
    /// `key_slot` has been punctured.
    pub fn derive_dek(
        &self,
        key_slot: u32,
        digest_hex: &str,
    ) -> crate::error::Result<zeroize::Zeroizing<[u8; KEY_LEN_BYTES]>> {
        let leaf = self.derive_leaf_key(key_slot, digest_hex)?;
        Ok(derive_leaf_dek(&leaf, key_slot))
    }

    /// Derive a per-forget-domain FastCDC chunk DEK bound to `key_slot` and `chunk_index`.
    pub fn derive_chunk_dek(
        &self,
        key_slot: u32,
        chunk_index: u32,
        digest_hex: &str,
    ) -> crate::error::Result<zeroize::Zeroizing<[u8; KEY_LEN_BYTES]>> {
        let leaf = self.derive_leaf_key(key_slot, digest_hex)?;
        Ok(derive_cdc_chunk_dek(&leaf, key_slot, chunk_index))
    }

    fn derive_leaf_key(
        &self,
        key_slot: u32,
        digest_hex: &str,
    ) -> crate::error::Result<zeroize::Zeroizing<[u8; KEY_LEN_BYTES]>> {
        let Some((anc_depth, _anc_prefix, mut key)) =
            find_covering_ancestor(&self.connection, key_slot)?
        else {
            return Err(crate::error::Failure::CryptographicallyErased {
                scope: self.scope.to_string(),
                key_slot,
                digest: digest_hex.to_owned(),
            });
        };
        for depth in anc_depth..GGM_DEPTH {
            let bit = bit_at_depth(key_slot, depth);
            let next = derive_child(&key, bit);
            key.zeroize();
            key = next;
        }
        Ok(key)
    }

    /// Atomically puncture `key_slot` at `generation`.
    ///
    /// Replaces the covering ancestor with at most 32 sibling subtree keys
    /// (`<= 1 KiB`), zeroizes intermediate keys in RAM, overwrites the
    /// ancestor's stored bytes with zeros before deleting it, and records the
    /// puncture barrier.
    pub fn puncture_slot(
        &mut self,
        key_slot: u32,
        generation: u64,
    ) -> crate::error::Result<PunctureReport> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some((anc_depth, anc_prefix, mut current)) =
            find_covering_ancestor(&transaction, key_slot)?
        else {
            record_punctured_slot(&transaction, key_slot, generation)?;
            transaction.commit()?;
            return Ok(PunctureReport {
                key_slot,
                generation,
                sibling_keys_written: 0,
                was_already_punctured: true,
            });
        };

        let mut siblings_written = 0_u8;
        for depth in anc_depth..GGM_DEPTH {
            let target_bit = bit_at_depth(key_slot, depth);
            let sibling_bit = target_bit ^ 1;
            let sibling_key = derive_child(&current, sibling_bit);
            let sib_depth = depth.saturating_add(1);
            let sib_prefix = sibling_prefix(key_slot, depth);
            transaction.execute(
                "INSERT OR REPLACE INTO subtree_keys (depth, prefix, key_bytes)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    i64::from(sib_depth),
                    i64::from(sib_prefix),
                    sibling_key.as_slice(),
                ],
            )?;
            siblings_written = siblings_written.saturating_add(1);
            let next = derive_child(&current, target_bit);
            current.zeroize();
            current = next;
        }
        current.zeroize();

        // Overwrite ancestor key bytes with zeros before removing the row.
        transaction.execute(
            "UPDATE subtree_keys SET key_bytes = ?1 WHERE depth = ?2 AND prefix = ?3",
            rusqlite::params![
                ZERO_KEY.as_slice(),
                i64::from(anc_depth),
                i64::from(anc_prefix),
            ],
        )?;
        transaction.execute(
            "DELETE FROM subtree_keys WHERE depth = ?1 AND prefix = ?2",
            rusqlite::params![i64::from(anc_depth), i64::from(anc_prefix)],
        )?;
        record_punctured_slot(&transaction, key_slot, generation)?;
        transaction.commit()?;
        Ok(PunctureReport {
            key_slot,
            generation,
            sibling_keys_written: siblings_written,
            was_already_punctured: false,
        })
    }

    /// Whether `key_slot` has been punctured (no covering ancestor exists).
    pub fn is_punctured(&self, key_slot: u32) -> crate::error::Result<bool> {
        Ok(find_covering_ancestor(&self.connection, key_slot)?.is_none())
    }

    /// All recorded punctured `(key_slot, generation)` pairs, sorted by `key_slot`.
    pub fn punctured_slots(&self) -> crate::error::Result<Vec<(u32, u64)>> {
        let mut stmt = self
            .connection
            .prepare("SELECT key_slot, generation FROM punctured_slots ORDER BY key_slot")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (slot_i64, gen_i64) in rows {
            if let (Ok(slot), Ok(generation)) = (u32::try_from(slot_i64), u64::try_from(gen_i64)) {
                out.push((slot, generation));
            }
        }
        Ok(out)
    }

    /// Number of active subtree keys stored in this key tree.
    pub fn subtree_key_count(&self) -> crate::error::Result<u64> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM subtree_keys", [], |row| row.get(0))?;
        u64::try_from(count)
            .map_err(|_| crate::error::Failure::ValueOutOfRange("subtree_key_count"))
    }
}

type AncestorSubtreeKey = (u8, u32, zeroize::Zeroizing<[u8; KEY_LEN_BYTES]>);

fn find_covering_ancestor(
    connection: &rusqlite::Connection,
    key_slot: u32,
) -> crate::error::Result<Option<AncestorSubtreeKey>> {
    let mut stmt = connection
        .prepare_cached("SELECT key_bytes FROM subtree_keys WHERE depth = ?1 AND prefix = ?2")?;
    for depth in 0..=GGM_DEPTH {
        let prefix = prefix_at_depth(key_slot, depth);
        let found: Option<Vec<u8>> = stmt
            .query_row(
                rusqlite::params![i64::from(depth), i64::from(prefix)],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(mut raw) = found {
            let key_res = <[u8; KEY_LEN_BYTES]>::try_from(raw.as_slice());
            raw.zeroize();
            let key = key_res.map_err(|_| bad_subtree_key_error())?;
            return Ok(Some((depth, prefix, zeroize::Zeroizing::new(key))));
        }
    }
    Ok(None)
}

fn bad_subtree_key_error() -> crate::error::Failure {
    crate::error::Failure::UnsupportedLayout("keytree subtree key must be 32 bytes".to_owned())
}

fn record_punctured_slot(
    transaction: &rusqlite::Transaction<'_>,
    key_slot: u32,
    generation: u64,
) -> crate::error::Result<()> {
    let gen_i64 = i64::try_from(generation)
        .map_err(|_| crate::error::Failure::ValueOutOfRange("puncture generation"))?;
    transaction.execute(
        "INSERT INTO punctured_slots (key_slot, generation)
         VALUES (?1, ?2)
         ON CONFLICT(key_slot) DO UPDATE SET generation = MAX(generation, excluded.generation)",
        rusqlite::params![i64::from(key_slot), gen_i64],
    )?;
    Ok(())
}

fn lookup_slot_in(
    connection: &rusqlite::Connection,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<Option<u32>> {
    let found: Option<i64> = connection
        .query_row(
            "SELECT key_slot FROM slot_bindings WHERE digest = ?1",
            rusqlite::params![digest.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    found
        .map(|slot| {
            u32::try_from(slot).map_err(|_| crate::error::Failure::ValueOutOfRange("key_slot"))
        })
        .transpose()
}

fn read_next_slot(connection: &rusqlite::Connection) -> crate::error::Result<u32> {
    let bytes: Vec<u8> = connection.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        rusqlite::params![META_NEXT_SLOT],
        |row| row.get(0),
    )?;
    let raw: [u8; 4] = bytes.try_into().map_err(|_| {
        crate::error::Failure::UnsupportedLayout("keytree next_slot must be 4 bytes".to_owned())
    })?;
    Ok(u32::from_le_bytes(raw))
}

const fn prefix_at_depth(slot: u32, depth: u8) -> u32 {
    if depth == 0 {
        0
    } else if depth >= GGM_DEPTH {
        slot
    } else {
        let shift = GGM_DEPTH.saturating_sub(depth);
        slot & (!0_u32 << shift)
    }
}

const fn bit_at_depth(slot: u32, depth: u8) -> u8 {
    let shift = GGM_DEPTH.saturating_sub(1).saturating_sub(depth);
    if ((slot >> shift) & 1) == 0 { 0 } else { 1 }
}

const fn sibling_prefix(slot: u32, depth: u8) -> u32 {
    let shift = GGM_DEPTH.saturating_sub(1).saturating_sub(depth);
    prefix_at_depth(slot, depth.saturating_add(1)) ^ (1_u32 << shift)
}

fn derive_child(
    node_key: &[u8; KEY_LEN_BYTES],
    bit: u8,
) -> zeroize::Zeroizing<[u8; KEY_LEN_BYTES]> {
    let domain = if bit == 0 {
        GGM_LEFT_DOMAIN
    } else {
        GGM_RIGHT_DOMAIN
    };
    let hash = blake3::keyed_hash(node_key, domain);
    zeroize::Zeroizing::new(*hash.as_bytes())
}

fn derive_leaf_dek(
    leaf_key: &[u8; KEY_LEN_BYTES],
    slot: u32,
) -> zeroize::Zeroizing<[u8; KEY_LEN_BYTES]> {
    let mut hasher = blake3::Hasher::new_keyed(leaf_key);
    hasher.update(GGM_LEAF_DEK_DOMAIN);
    hasher.update(&slot.to_le_bytes());
    zeroize::Zeroizing::new(*hasher.finalize().as_bytes())
}

fn derive_cdc_chunk_dek(
    leaf_key: &[u8; KEY_LEN_BYTES],
    slot: u32,
    chunk_index: u32,
) -> zeroize::Zeroizing<[u8; KEY_LEN_BYTES]> {
    let mut hasher = blake3::Hasher::new_keyed(leaf_key);
    hasher.update(GGM_CDC_CHUNK_DOMAIN);
    hasher.update(&slot.to_le_bytes());
    hasher.update(&chunk_index.to_le_bytes());
    zeroize::Zeroizing::new(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ggm_puncture_erases_target_slot_and_preserves_all_surviving_slots() {
        let temp = tempfile::tempdir().expect("tempdir");
        let scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::User, "confidential-secret")
            .expect("scope");
        let mut tree = PuncturableTree::open_or_init(temp.path(), &scope).expect("init tree");

        let mut before = Vec::with_capacity(32);
        for slot in 0_u32..32 {
            let dek = tree.derive_dek(slot, "test").expect("derive before");
            before.push(*dek);
        }

        // Puncture slot 7 and slot 23.
        let report7 = tree.puncture_slot(7, 2).expect("puncture 7");
        assert!(!report7.was_already_punctured);
        assert!(report7.sibling_keys_written <= GGM_DEPTH);
        assert_eq!(report7.sibling_keys_written, 32);

        let report23 = tree.puncture_slot(23, 3).expect("puncture 23");
        assert!(!report23.was_already_punctured);
        assert!(report23.sibling_keys_written <= GGM_DEPTH);

        // Idempotent re-puncture succeeds cleanly with 0 sibling keys written.
        let repeat = tree.puncture_slot(7, 4).expect("repuncture 7");
        assert!(repeat.was_already_punctured);
        assert_eq!(repeat.sibling_keys_written, 0);

        // Punctured slots fail closed with CryptographicallyErased.
        assert!(matches!(
            tree.derive_dek(7, "d7"),
            Err(crate::error::Failure::CryptographicallyErased { key_slot: 7, .. })
        ));
        assert!(matches!(
            tree.derive_dek(23, "d23"),
            Err(crate::error::Failure::CryptographicallyErased { key_slot: 23, .. })
        ));

        // Every surviving slot derives the exact same DEK with zero re-encryption.
        for (slot, expected) in (0_u32..).zip(before.iter()) {
            if slot == 7 || slot == 23 {
                assert!(tree.is_punctured(slot).expect("punctured"));
                continue;
            }
            assert!(!tree.is_punctured(slot).expect("active"));
            let after = tree.derive_dek(slot, "surviving").expect("derive after");
            assert_eq!(*after, *expected, "surviving slot {slot} key changed");
        }
    }

    #[test]
    fn key_puncture_barrier_preserves_roundtrip() {
        let scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::User, "confidential-alpha")
            .expect("scope");
        let barrier = KeyPunctureBarrier {
            scope,
            key_slot: 42,
            generation: 9,
            digest: Some(mneme_core::ContentDigest::of_source_bytes(b"secret")),
            signer_key_id: Some("aa".repeat(32)),
            signature_hex: Some("bb".repeat(64)),
        };
        let decoded = KeyPunctureBarrier::from_value(&barrier.to_value()).expect("decode");
        assert_eq!(decoded, barrier);
    }
}
