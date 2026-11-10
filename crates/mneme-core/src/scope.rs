//! Context and scope identifiers.
//!
//! Scope is ordinary record data describing the context a record belongs to.
//! It is never an authorization grant: a caller must still be authorized for
//! the scope by an explicit access decision. Keeping the distinction in the
//! type system's vocabulary, rather than treating a matching scope string as
//! permission, prevents disclosure by coincidence.

use std::fmt;

use crate::error::{Diagnostic, ErrorCode, Path, Stage};
use crate::value::Value;

/// The declared class of a scope identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScopeClass {
    User,
    Workspace,
    Project,
    Agent,
    Task,
    Hypothesis,
}

impl ScopeClass {
    /// The schema symbol for this class.
    pub const fn symbol(self) -> &'static str {
        match self {
            ScopeClass::User => "user",
            ScopeClass::Workspace => "workspace",
            ScopeClass::Project => "project",
            ScopeClass::Agent => "agent",
            ScopeClass::Task => "task",
            ScopeClass::Hypothesis => "hypothesis",
        }
    }

    /// Parse a declared scope class.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "user" => Some(ScopeClass::User),
            "workspace" => Some(ScopeClass::Workspace),
            "project" => Some(ScopeClass::Project),
            "agent" => Some(ScopeClass::Agent),
            "task" => Some(ScopeClass::Task),
            "hypothesis" => Some(ScopeClass::Hypothesis),
            _ => None,
        }
    }
}

impl fmt::Display for ScopeClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.symbol())
    }
}

/// A stable context identifier: a class plus a local opaque name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeId {
    class: ScopeClass,
    local: String,
}

impl ScopeId {
    /// Construct a scope with a validated local name.
    pub fn new(class: ScopeClass, local: impl Into<String>) -> Result<Self, &'static str> {
        let local = local.into();
        validate_local(&local)?;
        Ok(ScopeId { class, local })
    }

    /// The scope class.
    pub const fn class(&self) -> ScopeClass {
        self.class
    }

    /// The local scope name.
    pub fn local(&self) -> &str {
        &self.local
    }

    /// Encode as `<scope class "local">`.
    pub fn to_value(&self) -> Value {
        Value::record_named(
            "scope",
            vec![
                Value::symbol(self.class.symbol()),
                Value::string(self.local.clone()),
            ],
        )
    }

    /// Decode `<scope class "local">`.
    pub fn from_value(value: &Value, path: &Path) -> Result<Self, Diagnostic> {
        let type_error = || {
            Diagnostic::new(
                Stage::Envelope,
                ErrorCode::TypeMismatch,
                path.clone(),
                "expected <scope class \"local\">",
            )
        };
        let record = value.as_record().ok_or_else(type_error)?;
        if record.label() != &Value::symbol("scope") || record.fields().len() != 2 {
            return Err(type_error());
        }
        let class = record.fields()[0]
            .as_symbol()
            .and_then(|symbol| ScopeClass::parse(symbol.as_str()))
            .ok_or_else(|| {
                Diagnostic::new(
                    Stage::Envelope,
                    ErrorCode::InvalidScope,
                    path.clone(),
                    "scope class must be user, workspace, project, agent, task, or hypothesis",
                )
            })?;
        let local = record.fields()[1].as_string().ok_or_else(|| {
            Diagnostic::new(
                Stage::Envelope,
                ErrorCode::InvalidScope,
                path.clone(),
                "scope local name must be a string",
            )
        })?;
        Self::new(class, local.to_owned()).map_err(|message| {
            Diagnostic::new(
                Stage::Envelope,
                ErrorCode::InvalidScope,
                path.clone(),
                message,
            )
        })
    }
}

impl fmt::Display for ScopeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.class, self.local)
    }
}

fn validate_local(local: &str) -> Result<(), &'static str> {
    if local.is_empty() {
        return Err("scope local name must not be empty");
    }
    if local.len() > 128 {
        return Err("scope local name exceeds 128 bytes");
    }
    let mut characters = local.chars();
    match characters.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return Err("scope local name must start with an ASCII alphanumeric character"),
    }
    if !characters.all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
    }) {
        return Err("scope local name contains an unsupported character");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_roundtrips_and_display_is_explicit() {
        let scope = ScopeId::new(ScopeClass::Project, "cedar-notes").expect("valid scope");
        assert_eq!(scope.to_string(), "project:cedar-notes");
        assert_eq!(
            ScopeId::from_value(&scope.to_value(), &Path::root()).expect("decode"),
            scope
        );
    }

    #[test]
    fn distinct_classes_with_equal_names_are_distinct_scopes() {
        let project = ScopeId::new(ScopeClass::Project, "cedar").expect("valid");
        let agent = ScopeId::new(ScopeClass::Agent, "cedar").expect("valid");
        assert_ne!(project, agent);
        assert_ne!(project.to_value(), agent.to_value());
    }

    #[test]
    fn rejects_malformed_local_names() {
        for local in ["", "-leading", "has space", "slash/name", "ümlaut"] {
            assert!(ScopeId::new(ScopeClass::Task, local).is_err(), "{local:?}");
        }
    }

    #[test]
    fn unknown_scope_class_is_refused() {
        let value = Value::record_named(
            "scope",
            vec![Value::symbol("tenant"), Value::string("cedar")],
        );
        let error = ScopeId::from_value(&value, &Path::root()).expect_err("unknown class");
        assert_eq!(error.code, ErrorCode::InvalidScope);
    }
}
