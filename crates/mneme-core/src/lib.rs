//! Mneme's deterministic domain core.
//!
//! The crate owns the versioned Preserves record model, identity, scope, valid
//! and recorded time, canonical binary encoding, lossless tagged JSON transport,
//! validation, adapter capability checks, editor compatibility, and explicit
//! schema migration. Storage, coordination, retrieval, inference, and interfaces
//! are separate crates or adapters that consume these contracts.
//!
//! No module in this crate performs I/O, reads a clock, or mutates committed
//! state. Time, identity, authorization, and limits are supplied explicitly.

#![allow(unknown_lints, module_file_count, underscore_in_module_filename)] // public transport module path and intentional top-level layout
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod adapter;
pub mod base64;
pub mod binary;
pub mod digest;
pub mod editing;
pub mod envelope;
pub mod error;
pub mod fixtures;
pub mod ids;
pub mod migration;
pub mod payload;
pub mod reference;
pub mod schema;
pub mod scope;
#[allow(unknown_lints, underscore_in_module_filename)] // public transport module path
pub mod tagged_json;
pub mod text;
pub mod time;
pub mod value;

pub use adapter::{AdapterCapabilities, ValueKind, project_value};
pub use binary::{decode, decode_canonical, encode};
pub use digest::{ContentDigest, EncodingProfile, HashAlgorithm, ValueBoundary};
pub use envelope::{
    Payload, RECORD_LABEL, RecordContext, RecordEnvelope, ValidatedBatch, validate_batch,
    validate_record, validate_record_value,
};
pub use error::{Diagnostic, ErrorCode, Path, Stage, render_diagnostics};
pub use ids::{RecordId, RevisionId, WorkspaceRevisionId};
pub use payload::{RetainedSource, SourceContent, SourceSpan};
pub use reference::{Reference, RevisionEntry, SnapshotIndex};
pub use schema::{
    ExtensionPolicy, FieldSpec, FieldType, KindSchema, Lifecycle, Origin, RecordKind, RecordSchema,
    SchemaRegistry,
};
pub use scope::{ScopeClass, ScopeId};
pub use tagged_json::{
    decode_document, decode_document_value, decode_value, encode_document, encode_document_string,
    encode_value,
};
pub use time::{RecordedTime, Timestamp, ValidTime};
pub use value::{ByteString, Double, Record, SignedInteger, Symbol, Value};
