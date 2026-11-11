//! Stable opaque identifiers.
//!
//! Mneme identifiers are sixteen random-or-explicit bytes rendered as lowercase
//! hexadecimal. They are independent of paths, titles, and content hashes: a
//! rename or an edit keeps the identifier, and two records with equal payloads
//! keep distinct identifiers. A caller constructs identifiers explicitly; the
//! workspace coordinator will supply them from its own source of uniqueness.
macro_rules! opaque_id {
    ($(#[$doc:meta])* $name:ident, $label:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// The identifier length in bytes.
            pub const LENGTH: usize = 16;

            /// Construct from exact bytes.
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Parse the canonical hexadecimal form.
            pub fn from_hex(text: &str) -> Result<Self, &'static str> {
                parse_hex(text).map(Self)
            }

            /// Render the canonical lowercase hexadecimal form.
            pub fn to_hex(self) -> String {
                encode_hex(&self.0)
            }

            /// The raw identifier bytes.
            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Encode as the typed Preserves identifier record.
            pub fn to_value(self) -> crate::value::Value {
                crate::value::Value::record_named($label, vec![crate::value::Value::string(self.to_hex())])
            }

            /// Decode from the typed Preserves identifier record.
            pub fn from_value(value: &crate::value::Value, path: &crate::error::Path) -> Result<Self, crate::error::Diagnostic> {
                let Some(record) = value.as_record() else {
                    return Err(crate::error::Diagnostic::new(
                        crate::error::Stage::Envelope,
                        crate::error::ErrorCode::TypeMismatch,
                        path.clone(),
                        format!("expected <{} \"…\">", $label),
                    ));
                };
                if record.label() != &crate::value::Value::symbol($label) || record.fields().len() != 1 {
                    return Err(crate::error::Diagnostic::new(
                        crate::error::Stage::Envelope,
                        crate::error::ErrorCode::TypeMismatch,
                        path.clone(),
                        format!("expected <{} \"…\">", $label),
                    ));
                }
                let Some(text) = record.fields()[0].as_string() else {
                    return Err(crate::error::Diagnostic::new(
                        crate::error::Stage::Envelope,
                        crate::error::ErrorCode::TypeMismatch,
                        path.clone(),
                        format!("{} must carry a hexadecimal string", $label),
                    ));
                };
                Self::from_hex(text).map_err(|message| {
                    crate::error::Diagnostic::new(
                        crate::error::Stage::Envelope,
                        crate::error::ErrorCode::InvalidIdentifier,
                        path.clone(),
                        format!("invalid {}: {message}", $label),
                    )
                })
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, concat!($label, "({})"), self.to_hex())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.to_hex())
            }
        }
    };
}

opaque_id!(
    /// A stable identity for one record, independent of its revision.
    RecordId,
    "record-id"
);
opaque_id!(
    /// An immutable revision identity for one record.
    RevisionId,
    "revision-id"
);
opaque_id!(
    /// A committed workspace snapshot identity.
    WorkspaceRevisionId,
    "workspace-revision"
);

fn parse_hex(text: &str) -> Result<[u8; 16], &'static str> {
    if text.len() != 32 {
        return Err("identifier must contain exactly 32 hexadecimal digits");
    }
    let mut bytes = [0_u8; 16];
    for (index, chunk) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = nibble(chunk[0])?;
        let low = nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("identifier contains a non-hexadecimal character"),
    }
}

fn encode_hex(bytes: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_roundtrips_through_preserves() {
        let id = RecordId::from_hex("00112233445566778899aabbccddeeff").expect("valid hex");
        let value = id.to_value();
        assert_eq!(
            RecordId::from_value(&value, &crate::error::Path::root()).expect("valid id record"),
            id
        );
    }

    #[test]
    fn identifier_distinguishes_revision_domains() {
        let text = "00112233445566778899aabbccddeeff";
        let record = RecordId::from_hex(text).expect("valid");
        let revision = RevisionId::from_hex(text).expect("valid");
        // Equal bytes in different identifier domains are different typed
        // records and cannot be substituted for one another.
        assert_ne!(record.to_value(), revision.to_value());
    }

    #[test]
    fn rejects_malformed_identifiers() {
        for text in [
            "",
            "00",
            &"0".repeat(31),
            &"0".repeat(33),
            &format!("{}g", "0".repeat(31)),
        ] {
            assert!(
                RecordId::from_hex(text).is_err(),
                "{text:?} must be rejected"
            );
        }
    }
}
