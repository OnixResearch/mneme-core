//! Typed Preserves reproducibility receipts, oracle verdicts, signed receipt
//! envelopes, erasure compliance receipts, and BLAKE3 source-tree Merkle roots.

const LEAF_TAG: u8 = 0x00;
const INTERIOR_TAG: u8 = 0x01;
const PATH_SEPARATOR: u8 = 0x00;
const DIGEST_LEN: usize = 32;
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const HEX_NIBBLE_SHIFT: u8 = 4;
const HEX_NIBBLE_MASK: u8 = 0x0f;
const HEX_ALPHA_OFFSET: u8 = 10;
const HEX_BYTES_PER_BYTE: usize = 2;
const MAX_TREE_DEPTH: usize = 64;

const REPRODUCIBILITY_RECORD_LABEL: &str = "reproducibility-receipt";
const ORACLE_VERDICT_RECORD_LABEL: &str = "oracle-verdict";
const SIGNED_ENVELOPE_RECORD_LABEL: &str = "signed-receipt-envelope";
const ERASURE_RECEIPT_RECORD_LABEL: &str = "erasure-compliance-receipt";

/// Format identifier for signed Proof-Carrying Code kernel proof receipts (v2).
pub const KERNEL_PROOF_RECEIPT_V2_FORMAT: &str = "mneme-kernel-proof-receipt/v2";

/// Format identifier for signed retention erasure compliance receipts (v1).
pub const ERASURE_COMPLIANCE_RECEIPT_FORMAT: &str = "mneme-erasure-compliance-receipt/v1";

/// Typed Preserves reproducibility receipt binding an oracle verdict to exact
/// artifact, toolchain, command, seed, and boundary-condition digests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproducibilityReceipt {
    /// BLAKE3 digest of the verified subject (file, module, or source-tree Merkle root).
    pub subject_digest: String,
    /// Git commit SHA (or `"unpinned"`) evaluated by the oracle.
    pub git_rev: String,
    /// Digest of `flake.lock` or pinned toolchain lockfile.
    pub flake_lock_digest: String,
    /// Digest of the normalized oracle command specification.
    pub command_spec_digest: String,
    /// Deterministic seed / nondeterminism class (e.g. `"deterministic"`, `"fixed-clock"`).
    pub seed_class: String,
    /// Explicit boundary conditions under which the verdict was established.
    pub boundary_conditions: Vec<String>,
    /// Normalized verdict outcome (`"verified"`, `"passed"`, `"failed"`, `"skipped"`,
    /// `"warning"`, or `"unverified-claim"`).
    pub outcome: String,
    /// Digest of structured metrics (counts, timings, waiver budgets).
    pub metrics_digest: String,
}

impl ReproducibilityReceipt {
    /// Encode as canonical Preserves `<reproducibility-receipt { ... }>`.
    pub fn to_value(&self) -> crate::typed::Value {
        let conditions = crate::typed::Value::sequence(
            self.boundary_conditions
                .iter()
                .map(|item| crate::typed::Value::string(item.clone()))
                .collect(),
        );
        let fields = sym_dict([
            (
                "subject-digest",
                crate::typed::Value::string(self.subject_digest.clone()),
            ),
            ("git-rev", crate::typed::Value::string(self.git_rev.clone())),
            (
                "flake-lock-digest",
                crate::typed::Value::string(self.flake_lock_digest.clone()),
            ),
            (
                "command-spec-digest",
                crate::typed::Value::string(self.command_spec_digest.clone()),
            ),
            (
                "seed-class",
                crate::typed::Value::string(self.seed_class.clone()),
            ),
            ("boundary-conditions", conditions),
            ("outcome", crate::typed::Value::symbol(self.outcome.clone())),
            (
                "metrics-digest",
                crate::typed::Value::string(self.metrics_digest.clone()),
            ),
        ]);
        crate::typed::Value::record_named(REPRODUCIBILITY_RECORD_LABEL, vec![fields])
    }

    /// Decode from a Preserves `<reproducibility-receipt { ... }>` value.
    pub fn from_value(value: &crate::typed::Value) -> Result<Self, String> {
        let dict = unwrap_single_dict_record(value, REPRODUCIBILITY_RECORD_LABEL)?;
        let subject_digest = require_string_field(dict, "subject-digest")?;
        let git_rev = require_string_field(dict, "git-rev")?;
        let flake_lock_digest = require_string_field(dict, "flake-lock-digest")?;
        let command_spec_digest = require_string_field(dict, "command-spec-digest")?;
        let seed_class = require_string_field(dict, "seed-class")?;
        let boundary_conditions = require_string_list_field(dict, "boundary-conditions")?;
        let outcome = require_symbol_or_string_field(dict, "outcome")?;
        let metrics_digest = require_string_field(dict, "metrics-digest")?;
        Ok(Self {
            subject_digest,
            git_rev,
            flake_lock_digest,
            command_spec_digest,
            seed_class,
            boundary_conditions,
            outcome,
            metrics_digest,
        })
    }

    /// Canonical Preserves binary bytes for cryptographic signing and hashing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::binary::encode(&self.to_value())
    }

    /// Content digest over the canonical Preserves payload.
    pub fn digest(&self) -> crate::hashing::ContentDigest {
        crate::hashing::ContentDigest::of_payload(&self.to_value())
    }
}

/// Typed Preserves oracle verdict record projected into Datalog `verdict/6`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleVerdict {
    /// Producing oracle tool identifier (e.g. `"just-proofs"`, `"cargo-test"`, `"cargo-octet"`).
    pub tool: String,
    /// Target identifier (path, symbol, or entity hex).
    pub target: String,
    /// Outcome symbol (`"verified"`, `"passed"`, `"failed"`, `"unverified-claim"`, `"skipped"`).
    pub outcome: String,
    /// Subject / artifact content digest.
    pub artifact_digest: String,
    /// Toolchain / `flake.lock` digest.
    pub toolchain_digest: String,
    /// Evaluated Git revision.
    pub eval_rev: String,
    /// Optional embedded [`ReproducibilityReceipt`].
    pub receipt: Option<ReproducibilityReceipt>,
}

impl OracleVerdict {
    /// Encode as canonical Preserves `<oracle-verdict { ... }>`.
    pub fn to_value(&self) -> crate::typed::Value {
        let mut entries = vec![
            ("tool", crate::typed::Value::symbol(self.tool.clone())),
            ("target", crate::typed::Value::string(self.target.clone())),
            ("outcome", crate::typed::Value::symbol(self.outcome.clone())),
            (
                "artifact-digest",
                crate::typed::Value::string(self.artifact_digest.clone()),
            ),
            (
                "toolchain-digest",
                crate::typed::Value::string(self.toolchain_digest.clone()),
            ),
            (
                "eval-rev",
                crate::typed::Value::string(self.eval_rev.clone()),
            ),
        ];
        if let Some(receipt) = &self.receipt {
            entries.push(("receipt", receipt.to_value()));
        }
        let dict = sym_dict(entries);
        crate::typed::Value::record_named(ORACLE_VERDICT_RECORD_LABEL, vec![dict])
    }

    /// Decode from a Preserves `<oracle-verdict { ... }>` value.
    pub fn from_value(value: &crate::typed::Value) -> Result<Self, String> {
        let dict = unwrap_single_dict_record(value, ORACLE_VERDICT_RECORD_LABEL)?;
        let tool = require_symbol_or_string_field(dict, "tool")?;
        let target = require_string_field(dict, "target")?;
        let outcome = require_symbol_or_string_field(dict, "outcome")?;
        let artifact_digest = require_string_field(dict, "artifact-digest")?;
        let toolchain_digest = require_string_field(dict, "toolchain-digest")?;
        let eval_rev = require_string_field(dict, "eval-rev")?;
        let receipt = match dict.get(&crate::typed::Value::symbol("receipt")) {
            Some(val) => Some(ReproducibilityReceipt::from_value(val)?),
            None => None,
        };
        Ok(Self {
            tool,
            target,
            outcome,
            artifact_digest,
            toolchain_digest,
            eval_rev,
            receipt,
        })
    }
}

/// Reusable Ed25519-signed canonical Preserves envelope for proof-carrying
/// receipts and retention erasure compliance receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedReceiptEnvelope {
    /// Envelope schema identifier (e.g. [`KERNEL_PROOF_RECEIPT_V2_FORMAT`]).
    pub schema: String,
    /// Canonical Preserves binary bytes covered by `signature`.
    pub canonical_payload: Vec<u8>,
    /// 32-byte Ed25519 verifying key.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// 64-byte Ed25519 signature over `canonical_payload`.
    pub signature: [u8; SIGNATURE_LEN],
}

impl SignedReceiptEnvelope {
    /// Encode as canonical Preserves `<signed-receipt-envelope { ... }>`.
    pub fn to_value(&self) -> crate::typed::Value {
        let dict = sym_dict([
            ("schema", crate::typed::Value::string(self.schema.clone())),
            (
                "canonical-payload",
                crate::typed::Value::bytes(self.canonical_payload.clone()),
            ),
            (
                "public-key",
                crate::typed::Value::bytes(self.public_key.to_vec()),
            ),
            (
                "signature",
                crate::typed::Value::bytes(self.signature.to_vec()),
            ),
        ]);
        crate::typed::Value::record_named(SIGNED_ENVELOPE_RECORD_LABEL, vec![dict])
    }

    /// Decode from a Preserves `<signed-receipt-envelope { ... }>` value.
    pub fn from_value(value: &crate::typed::Value) -> Result<Self, String> {
        let dict = unwrap_single_dict_record(value, SIGNED_ENVELOPE_RECORD_LABEL)?;
        let schema = require_string_field(dict, "schema")?;
        let canonical_payload = require_bytes_field(dict, "canonical-payload")?;
        let pk_vec = require_bytes_field(dict, "public-key")?;
        let sig_vec = require_bytes_field(dict, "signature")?;
        let public_key = <[u8; PUBLIC_KEY_LEN]>::try_from(pk_vec.as_slice())
            .map_err(|_| "public-key must be exactly 32 bytes".to_owned())?;
        let signature = <[u8; SIGNATURE_LEN]>::try_from(sig_vec.as_slice())
            .map_err(|_| "signature must be exactly 64 bytes".to_owned())?;
        Ok(Self {
            schema,
            canonical_payload,
            public_key,
            signature,
        })
    }

    /// Decode `canonical_payload` strictly as a canonical Preserves value.
    pub fn decode_payload(&self) -> Result<crate::typed::Value, String> {
        crate::binary::decode_canonical(&self.canonical_payload)
            .map_err(|diagnostic| diagnostic.to_string())
    }
}

/// Typed Preserves retention erasure compliance receipt wrapped inside a
/// [`SignedReceiptEnvelope`] (`mneme-erasure-compliance-receipt/v1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureComplianceReceipt {
    /// Retention operation identifier.
    pub operation_id: String,
    /// Monotonic eligibility generation established by the erasure barrier.
    pub eligibility_generation: u64,
    /// Number of suppressed or purged targets attested by this receipt.
    pub erased_count: u64,
    /// BLAKE3 digest of the erasure manifest / target set.
    pub manifest_digest: String,
    /// Committed workspace revision at which erasure completed.
    pub workspace_revision: String,
}

impl ErasureComplianceReceipt {
    /// Encode as canonical Preserves `<erasure-compliance-receipt { ... }>`.
    pub fn to_value(&self) -> crate::typed::Value {
        let dict = sym_dict([
            (
                "format",
                crate::typed::Value::string(ERASURE_COMPLIANCE_RECEIPT_FORMAT),
            ),
            (
                "operation-id",
                crate::typed::Value::string(self.operation_id.clone()),
            ),
            (
                "eligibility-generation",
                crate::typed::Value::integer(self.eligibility_generation),
            ),
            (
                "erased-count",
                crate::typed::Value::integer(self.erased_count),
            ),
            (
                "manifest-digest",
                crate::typed::Value::string(self.manifest_digest.clone()),
            ),
            (
                "workspace-revision",
                crate::typed::Value::string(self.workspace_revision.clone()),
            ),
        ]);
        crate::typed::Value::record_named(ERASURE_RECEIPT_RECORD_LABEL, vec![dict])
    }

    /// Decode from a Preserves `<erasure-compliance-receipt { ... }>` value.
    pub fn from_value(value: &crate::typed::Value) -> Result<Self, String> {
        let dict = unwrap_single_dict_record(value, ERASURE_RECEIPT_RECORD_LABEL)?;
        let format = require_string_field(dict, "format")?;
        if format != ERASURE_COMPLIANCE_RECEIPT_FORMAT {
            return Err(format!("unsupported erasure receipt format {format}"));
        }
        let operation_id = require_string_field(dict, "operation-id")?;
        let eligibility_generation = require_u64_field(dict, "eligibility-generation")?;
        let erased_count = require_u64_field(dict, "erased-count")?;
        let manifest_digest = require_string_field(dict, "manifest-digest")?;
        let workspace_revision = require_string_field(dict, "workspace-revision")?;
        Ok(Self {
            operation_id,
            eligibility_generation,
            erased_count,
            manifest_digest,
            workspace_revision,
        })
    }

    /// Canonical Preserves binary bytes for signing inside [`SignedReceiptEnvelope`].
    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::binary::encode(&self.to_value())
    }
}

/// Compute the deterministic RFC 6962 / Crosby-Wallach BLAKE3 Merkle root over
/// `(relative_path, file_bytes)` pairs sorted by `relative_path`.
///
/// - Leaf digest: `BLAKE3(0x00 || relative_path_utf8 || 0x00 || file_bytes)`
/// - Interior digest: `BLAKE3(0x01 || left || right)` using the largest power of
///   two strictly less than `n` as the left subtree split.
pub fn compute_source_tree_merkle_root(entries: &[(&str, &[u8])]) -> [u8; DIGEST_LEN] {
    if entries.is_empty() {
        return *blake3::hash(&[]).as_bytes();
    }
    let mut sorted: Vec<(&str, &[u8])> = entries.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(right.0));
    let max_preimage_len = sorted
        .iter()
        .map(|(path, bytes)| path.len().saturating_add(bytes.len()).saturating_add(2))
        .max()
        .unwrap_or(0);
    let mut leaves = Vec::with_capacity(sorted.len());
    let mut preimage = Vec::with_capacity(max_preimage_len);
    for (rel_path, content) in sorted {
        preimage.clear();
        preimage.push(LEAF_TAG);
        preimage.extend_from_slice(rel_path.as_bytes());
        preimage.push(PATH_SEPARATOR);
        preimage.extend_from_slice(content);
        leaves.push(*blake3::hash(&preimage).as_bytes());
    }
    fold_merkle_slice(&leaves)
}

/// Encode bytes as lowercase hexadecimal text.
pub fn encode_hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(HEX_BYTES_PER_BYTE));
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> HEX_NIBBLE_SHIFT)]));
        out.push(char::from(HEX[usize::from(byte & HEX_NIBBLE_MASK)]));
    }
    out
}

/// Decode a 64-character lowercase hexadecimal string into 32 bytes.
pub fn decode_hex_32(hex: &str) -> Result<[u8; DIGEST_LEN], String> {
    let expected_len = DIGEST_LEN.saturating_mul(HEX_BYTES_PER_BYTE);
    if hex.len() != expected_len || !mneme_kernel::text::is_lower_hex(hex.as_bytes()) {
        return Err(format!(
            "expected {expected_len} lowercase hex characters, got {}",
            hex.len()
        ));
    }
    let mut out = [0_u8; DIGEST_LEN];
    for (slot, pair) in out
        .iter_mut()
        .zip(hex.as_bytes().as_chunks::<HEX_BYTES_PER_BYTE>().0)
    {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        *slot = (hi << HEX_NIBBLE_SHIFT) | lo;
    }
    Ok(out)
}

fn nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(byte.saturating_sub(b'a').saturating_add(HEX_ALPHA_OFFSET)),
        _ => Err("invalid lowercase hex nibble".to_owned()),
    }
}

/// Iterative RFC 6962 binary Merkle fold over a non-empty leaf slice.
fn fold_merkle_slice(leaves: &[[u8; DIGEST_LEN]]) -> [u8; DIGEST_LEN] {
    // Maintain a stack of (subtree_leaf_count, root_digest) and merge whenever
    // the top two entries have equal power-of-two size, then fold peaks right-to-left.
    let mut peaks: Vec<(u64, [u8; DIGEST_LEN])> = Vec::with_capacity(MAX_TREE_DEPTH);
    for leaf in leaves {
        let mut size = 1_u64;
        let mut cur = *leaf;
        while let Some((top_size, top_hash)) = peaks.last().copied() {
            if top_size != size {
                break;
            }
            let _ = peaks.pop();
            cur = hash_interior(top_hash, cur);
            size = size.saturating_mul(2);
        }
        peaks.push((size, cur));
    }
    let mut acc = match peaks.pop() {
        Some((_, digest)) => digest,
        None => [0_u8; DIGEST_LEN],
    };
    while let Some((_, left)) = peaks.pop() {
        acc = hash_interior(left, acc);
    }
    acc
}

fn hash_interior(left: [u8; DIGEST_LEN], right: [u8; DIGEST_LEN]) -> [u8; DIGEST_LEN] {
    let mut preimage = [0_u8; 1 + DIGEST_LEN + DIGEST_LEN];
    preimage[0] = INTERIOR_TAG;
    preimage[1..1 + DIGEST_LEN].copy_from_slice(&left);
    preimage[1 + DIGEST_LEN..].copy_from_slice(&right);
    *blake3::hash(&preimage).as_bytes()
}

fn sym_dict<I>(entries: I) -> crate::typed::Value
where
    I: IntoIterator<Item = (&'static str, crate::typed::Value)>,
{
    crate::typed::Value::symbol_dictionary(
        entries
            .into_iter()
            .map(|(k, v)| (crate::typed::Symbol::from(k), v)),
    )
}

fn unwrap_single_dict_record<'a>(
    value: &'a crate::typed::Value,
    expected_label: &str,
) -> Result<&'a std::collections::BTreeMap<crate::typed::Value, crate::typed::Value>, String> {
    let record = value
        .as_record()
        .ok_or_else(|| format!("expected <{expected_label} {{...}}> record"))?;
    if record.label() != &crate::typed::Value::symbol(expected_label) || record.fields().len() != 1
    {
        return Err(format!("expected <{expected_label} {{...}}> record"));
    }
    record.fields()[0]
        .as_dictionary()
        .ok_or_else(|| format!("<{expected_label}> body must be a dictionary"))
}

fn require_string_field(
    dict: &std::collections::BTreeMap<crate::typed::Value, crate::typed::Value>,
    key: &str,
) -> Result<String, String> {
    dict.get(&crate::typed::Value::symbol(key))
        .and_then(crate::typed::Value::as_string)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing or non-string field '{key}'"))
}

fn require_symbol_or_string_field(
    dict: &std::collections::BTreeMap<crate::typed::Value, crate::typed::Value>,
    key: &str,
) -> Result<String, String> {
    let val = dict
        .get(&crate::typed::Value::symbol(key))
        .ok_or_else(|| format!("missing field '{key}'"))?;
    if let Some(sym) = val.as_symbol() {
        Ok(sym.as_str().to_owned())
    } else if let Some(text) = val.as_string() {
        Ok(text.to_owned())
    } else {
        Err(format!("field '{key}' must be a symbol or string"))
    }
}

fn require_bytes_field(
    dict: &std::collections::BTreeMap<crate::typed::Value, crate::typed::Value>,
    key: &str,
) -> Result<Vec<u8>, String> {
    dict.get(&crate::typed::Value::symbol(key))
        .and_then(crate::typed::Value::as_bytes)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| format!("missing or non-bytestring field '{key}'"))
}

fn require_u64_field(
    dict: &std::collections::BTreeMap<crate::typed::Value, crate::typed::Value>,
    key: &str,
) -> Result<u64, String> {
    let raw = dict
        .get(&crate::typed::Value::symbol(key))
        .and_then(crate::typed::Value::as_integer)
        .and_then(crate::typed::SignedInteger::to_i64)
        .ok_or_else(|| format!("missing or non-integer field '{key}'"))?;
    u64::try_from(raw).map_err(|_| format!("field '{key}' must be non-negative"))
}

fn require_string_list_field(
    dict: &std::collections::BTreeMap<crate::typed::Value, crate::typed::Value>,
    key: &str,
) -> Result<Vec<String>, String> {
    let seq = dict
        .get(&crate::typed::Value::symbol(key))
        .and_then(crate::typed::Value::as_sequence)
        .ok_or_else(|| format!("missing or non-sequence field '{key}'"))?;
    seq.iter()
        .map(|item| {
            item.as_string()
                .map(str::to_owned)
                .ok_or_else(|| format!("element of '{key}' must be a string"))
        })
        .collect()
}
