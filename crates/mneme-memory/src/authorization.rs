//! Caller authorization over record scopes.
//!
//! A caller is either the local operator, authorized for every scope, or a
//! session limited to an explicit set of scopes. The set is the only source of
//! cross-scope authorization: a scope label carried by a record never grants
//! access to it.

/// The scopes a caller is authorized for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Access {
    /// The local operator, authorized for every scope.
    Operator,
    /// A caller limited to an explicit set of scopes.
    Scopes(std::collections::BTreeSet<mneme_core::ScopeId>),
}

impl Access {
    /// Whether this access authorizes the given scope.
    pub fn allows(&self, scope: &mneme_core::ScopeId) -> bool {
        match self {
            Access::Operator => true,
            Access::Scopes(scopes) => scopes.contains(scope),
        }
    }

    /// A caller limited to the given scopes.
    pub fn scopes(scopes: impl IntoIterator<Item = mneme_core::ScopeId>) -> Self {
        Access::Scopes(scopes.into_iter().collect())
    }
}
