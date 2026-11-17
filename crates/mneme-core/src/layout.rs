//! Typed layout provenance. Recovering structure or interpreting a picture
//! never turns generated text into a literal transcription or an assertion.

const MAX_BLOCK_IDENTITY_BYTES: usize = 128;
const MAX_BLOCK_LABEL_BYTES: usize = 128;

/// What a recognizer did to produce one block's content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecognitionReading {
    Literal,
    Structure,
    Interpretation,
}

impl RecognitionReading {
    /// Stable schema symbol, independent of a backend's block labels.
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::Structure => "structure",
            Self::Interpretation => "interpretation",
        }
    }

    /// Require an explicitly supported reading kind.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "literal" => Some(Self::Literal),
            "structure" => Some(Self::Structure),
            "interpretation" => Some(Self::Interpretation),
            _ => None,
        }
    }
}

/// Backend block identity and label, and its reported reading order. A missing
/// order remains missing; list position is not an invented backend order.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecognitionBlock {
    reading: RecognitionReading,
    identity: String,
    label: String,
    order: Option<u32>,
}

impl RecognitionBlock {
    /// Construct bounded block metadata without interpreting its label.
    pub fn new(
        reading: RecognitionReading,
        identity: String,
        label: String,
        order: Option<u32>,
    ) -> Result<Self, &'static str> {
        let block = Self {
            reading,
            identity,
            label,
            order,
        };
        block.validate()?;
        Ok(block)
    }

    pub const fn reading(&self) -> RecognitionReading {
        self.reading
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub const fn order(&self) -> Option<u32> {
        self.order
    }

    /// Refuse empty/oversized identities and non-identifier layout labels.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.identity.trim().is_empty() || self.identity.len() > MAX_BLOCK_IDENTITY_BYTES {
            return Err("recognition block identity must be non-empty and bounded");
        }
        let is_label = !self.label.is_empty()
            && self.label.len() <= MAX_BLOCK_LABEL_BYTES
            && self
                .label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
        if !is_label {
            return Err("recognition block label must be a bounded identifier");
        }
        Ok(())
    }

    /// Encode the classification with the exact provider layout metadata.
    pub fn to_value(&self) -> crate::typed::Value {
        crate::typed::Value::record_named(
            "recognition-block",
            vec![
                crate::typed::Value::symbol(self.reading.symbol()),
                crate::typed::Value::string(self.identity.clone()),
                crate::typed::Value::string(self.label.clone()),
                self.order.map_or_else(
                    || crate::typed::Value::symbol("none"),
                    crate::typed::Value::integer,
                ),
            ],
        )
    }

    /// Decode a validated block tuple. Unknown kinds are not treated as literal.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        use num_traits::ToPrimitive;
        let record = value
            .as_record()
            .filter(|record| {
                record.label() == &crate::typed::Value::symbol("recognition-block")
                    && record.fields().len() == 4
            })
            .ok_or_else(|| invalid(path, "expected a recognition block tuple"))?;
        let fields = record.fields();
        let reading = fields[0]
            .as_symbol()
            .and_then(|symbol| RecognitionReading::parse(symbol.as_str()))
            .ok_or_else(|| {
                invalid(
                    &path.index(0),
                    "expected literal, structure or interpretation",
                )
            })?;
        let identity = fields[1]
            .as_string()
            .ok_or_else(|| invalid(&path.index(1), "expected a block identity"))?;
        let label = fields[2]
            .as_string()
            .ok_or_else(|| invalid(&path.index(2), "expected a block label"))?;
        let order = if fields[3]
            .as_symbol()
            .is_some_and(|symbol| symbol.as_str() == "none")
        {
            None
        } else {
            Some(
                fields[3]
                    .as_integer()
                    .and_then(|integer| integer.as_bigint().to_u32())
                    .ok_or_else(|| {
                        invalid(&path.index(3), "expected an unsigned block order or none")
                    })?,
            )
        };
        Self::new(reading, identity.to_owned(), label.to_owned(), order)
            .map_err(|message| invalid(path, message))
    }
}

fn invalid(path: &crate::problem::Path, message: &str) -> crate::problem::Diagnostic {
    crate::problem::Diagnostic::new(
        crate::problem::Stage::Domain,
        crate::problem::ErrorCode::TypeMismatch,
        path.clone(),
        message,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn reading_kinds_and_unknown_order_remain_distinct() {
        for reading in [
            super::RecognitionReading::Literal,
            super::RecognitionReading::Structure,
            super::RecognitionReading::Interpretation,
        ] {
            let block = super::RecognitionBlock::new(
                reading,
                "page-2/block-7".to_owned(),
                "formula".to_owned(),
                None,
            )
            .expect("block");
            let decoded =
                super::RecognitionBlock::from_value(&block.to_value(), &crate::Path::root())
                    .expect("decode");
            assert_eq!(decoded.reading(), reading);
            assert_eq!(decoded.order(), None);
            assert_eq!(decoded.identity(), "page-2/block-7");
        }
    }

    #[test]
    fn malformed_or_unbounded_blocks_are_refused() {
        let path = crate::Path::root();
        for (reading, identity, label, order) in [
            (
                "confident",
                "7".to_owned(),
                "text",
                crate::Value::integer(0_u32),
            ),
            (
                "literal",
                " ".to_owned(),
                "text",
                crate::Value::integer(0_u32),
            ),
            (
                "literal",
                "x".repeat(super::MAX_BLOCK_IDENTITY_BYTES + 1),
                "text",
                crate::Value::integer(0_u32),
            ),
            (
                "literal",
                "7".to_owned(),
                "a label",
                crate::Value::integer(0_u32),
            ),
            (
                "literal",
                "7".to_owned(),
                "text",
                crate::Value::integer(-1_i32),
            ),
            (
                "literal",
                "7".to_owned(),
                "text",
                crate::Value::integer(u64::MAX),
            ),
        ] {
            let value = crate::Value::record_named(
                "recognition-block",
                vec![
                    crate::Value::symbol(reading),
                    crate::Value::string(identity),
                    crate::Value::string(label),
                    order,
                ],
            );
            assert!(super::RecognitionBlock::from_value(&value, &path).is_err());
        }
    }
}
