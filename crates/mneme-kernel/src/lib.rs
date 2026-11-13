//! Mneme's pure decision kernel.
//!
//! Every function here is a total decision over facts that an imperative shell
//! has already read: no I/O, no allocation, no clock, no panics. The shells in
//! `mneme-store`, `mneme-memory`, `mneme-retention`, `mneme-doc`,
//! `mneme-datalog`, `mneme-recall`, `mneme-prolog`, and `mneme-eval` gather the
//! facts and act on the returned decision.
//!
//! The crate is written in the Rust subset that Charon and Aeneas translate to
//! Lean. `proofs/kernel` holds the generated translation and the theorems
//! proved over it; `scripts/verify-kernel-proofs.mjs` regenerates the
//! translation, compares it with the checked-in copy, and audits the proofs.
//!
//! Rules for code in this crate, so that extraction keeps working:
//!
//! - no `for` loops, iterators, closures, trait objects, or formatting;
//! - no `return`, `break`, `continue`, or `?` inside a loop body;
//! - loops are `while` loops over an index with an accumulated flag or value;
//! - no field or binding named after a Lean keyword (`end`, `at`, `from`, ...);
//! - no parameter or local binding named like a kernel module (`verdict`,
//!   `claim`, `text`, ...): the generated Lean would resolve qualified
//!   names against the binding;
//! - `Debug` is derived only under the `debug` feature.

#![no_std]
#![forbid(unsafe_code)]
// One module per decision family keeps each proof file beside one source file.
#![allow(unknown_lints, module_file_count)]
// The extraction subset has no closures, range methods or saturating helpers,
// so these idioms are spelled out by hand.
#![allow(
    clippy::manual_range_contains,
    clippy::manual_filter,
    clippy::implicit_saturating_sub
)]

pub mod admission;
pub mod budget;
pub mod claim;
pub mod cleanup;
pub mod completeness;
pub mod extent;
pub mod hashing;
pub mod isolation;
pub mod publish;
pub mod purge;
pub mod restore;
pub mod text;
pub mod verdict;
