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

#![allow(unknown_lints, module_file_count)] // public transport module path and intentional top-level layout
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod base64;
pub mod binary;
pub mod clock;
pub mod editing;
pub mod fields;
pub mod fixtures;
pub mod hashing;
pub mod ids;
pub mod layout;
pub mod lineage;
pub mod miner;
pub mod payload;
pub mod pointer;
pub mod problem;
pub mod projection;
pub mod raster;
pub mod tenancy;
pub mod text;
#[allow(unknown_lints)] // public transport module path
pub mod transport;
pub mod typed;
pub mod upgrade;
pub mod wire;

pub use binary::MAX_INTEGER_BYTES;
pub use binary::{decode, decode_canonical, encode};
pub use clock::{RecordedTime, Timestamp, ValidTime};
pub use fields::{
    ExtensionPolicy, FieldSpec, FieldType, KindSchema, Lifecycle, Origin, RecordKind, RecordSchema,
    SchemaRegistry,
};
pub use hashing::{ContentDigest, EncodingProfile, HashAlgorithm, ValueBoundary};
pub use hashing::{kernel_digest, request_fingerprint};
pub use ids::{RecordId, RevisionId, WorkspaceRevisionId};
pub use layout::{RecognitionBlock, RecognitionReading};
pub use lineage::{
    ACQUISITION_SCHEMA_VERSION, Acquisition, AlignmentDisposition, CapturePart, CoordinateFrame,
    CorrectionProvenance, DERIVED_ACQUISITION_SCHEMA_VERSION, DerivedAcquisition, InkInventory,
    MAX_INK_LAYERS, MAX_INK_STROKES, MAX_RECOGNITION_SEGMENTS, MediaExtent, MediaLocation,
    MediaTransform, RecognitionAlternative, RecognitionCoverage, RecognitionScore,
    RecognitionStatus, SourcePin, TimeBase,
};
pub use payload::{RetainedSource, SourceContent, SourceSpan};
pub use pointer::{Reference, RevisionEntry, SnapshotIndex};
pub use problem::{Diagnostic, ErrorCode, Path, Stage, render_diagnostics};
pub use projection::{AdapterCapabilities, ValueKind, project_value};
pub use raster::{RecognitionPage, RecognitionPageReport, RecognitionRegion};
pub use tenancy::{ScopeClass, ScopeId};
pub use transport::{
    decode_document, decode_document_value, decode_nested_value, decode_value, encode_document,
    encode_document_string, encode_value,
};
pub use typed::{ByteString, Double, Record, SignedInteger, Symbol, Value};
pub use wire::{
    Payload, RECORD_LABEL, RecordContext, RecordEnvelope, ValidatedBatch, validate_batch,
    validate_record, validate_record_value,
};
