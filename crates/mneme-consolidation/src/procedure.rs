//! Procedural proposal validation boundary.
//!
//! Procedures are data until a dedicated validator and authorized command path
//! accept them. Validation must never execute embedded instructions, rules, or
//! tools, and it cannot mutate worker privileges in this module.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Worker capabilities available while reviewing a procedural suggestion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerPrivileges {
    pub allowed_tools: std::collections::BTreeSet<String>,
    pub may_install_procedures: bool,
}

/// One validator result. `executed` must remain false; a validator that claims
/// it ran content is refused by `validate_procedure`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureValidation {
    pub validator: String,
    pub approved: bool,
    pub rationale: String,
    pub embedded_instructions_are_data: bool,
    pub executed: bool,
}

/// A separate procedural validator. Implementations inspect content only.
pub trait ProcedureValidator {
    fn identity(&self) -> &str;

    fn supports(&self, kind: crate::ProcedureKind) -> bool;

    fn validate(
        &self,
        procedure: &crate::ProcedureProposal,
        privileges: &WorkerPrivileges,
    ) -> Result<ProcedureValidation, String>;
}

/// Validate a procedural proposal without installing or executing it.
pub fn validate_procedure(
    proposal: &crate::ConsolidationProposal,
    validator: &dyn ProcedureValidator,
    privileges: &WorkerPrivileges,
) -> Result<ProcedureValidation, String> {
    let crate::ProposalOperation::Procedure(procedure) = &proposal.operation else {
        return Err("proposal is not procedural".to_owned());
    };
    if procedure.validator != validator.identity() {
        return Err("proposal names a different validator".to_owned());
    }
    if !validator.supports(procedure.kind) {
        return Err("validator does not support this procedure kind".to_owned());
    }
    let validation = validator.validate(procedure, privileges)?;
    if validation.validator != validator.identity() {
        return Err("validation result names a different validator".to_owned());
    }
    if validation.executed {
        return Err("procedural validation executed content".to_owned());
    }
    if !validation.embedded_instructions_are_data {
        return Err("embedded instructions were not treated as data".to_owned());
    }
    Ok(validation)
}
