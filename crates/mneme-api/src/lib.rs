//! Transport-neutral local agent memory API.
//!
//! Commands and results are versioned tagged JSON documents. The CLI and local
//! stdio MCP adapters call this crate; they do not own storage or inference.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![allow(unknown_lints)] // Octet custom lint names are unknown to rustc

pub mod command;
pub mod error;
pub mod service;

pub use command::{
    ApiCommand, COMMAND_FORMAT, COMMAND_VERSION, LocalSession, RESULT_FORMAT, RESULT_VERSION,
    ReviseAction, SessionConfig, decode,
};
pub use error::{ApiError, ApiErrorCode, ApiResult};
pub use service::{ApiResponse, ApiService, error_document};
