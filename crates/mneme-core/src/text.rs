//! Human-readable Preserves text rendering for diagnostics and CLI output.
//!
//! This is a writer, not a parser. The lossless interchange contract is the
//! tagged JSON transport; text output is for people reading logs, errors, and
//! summaries. Symbols are quoted when they are not comfortably readable. The
//! exact textual representation is not used for hashing or persistence.

use std::fmt;

use crate::value::Value;

/// Render a value using Preserves text syntax for human consumption.
pub fn render(value: &Value) -> String {
    let mut output = String::new();
    write_value(&mut output, value);
    output
}

fn write_value(output: &mut String, value: &Value) {
    match value {
        Value::Boolean(true) => output.push_str("#t"),
        Value::Boolean(false) => output.push_str("#f"),
        Value::Double(double) => {
            let raw = double.value();
            if raw.is_finite() {
                output.push_str(&format!("{raw:?}"));
            } else {
                output.push_str(&format!("#xd\"{:016x}\"", double.bits()));
            }
        }
        Value::SignedInteger(integer) => output.push_str(&integer.to_string()),
        Value::String(text) => match serde_json::to_string(text) {
            Ok(quoted) => output.push_str(&quoted),
            Err(_) => output.push_str(&format!("{text:?}")),
        },
        Value::ByteString(bytes) => {
            output.push_str("#x\"");
            for byte in bytes.as_slice() {
                output.push_str(&format!("{byte:02x}"));
            }
            output.push('"');
        }
        Value::Symbol(symbol) => match write_symbol_string(symbol.as_str()) {
            Ok(bare) => output.push_str(&bare),
            Err(quoted) => output.push_str(&quoted),
        },
        Value::Record(record) => {
            output.push('<');
            write_value(output, record.label());
            for field in record.fields() {
                output.push(' ');
                write_value(output, field);
            }
            output.push('>');
        }
        Value::Sequence(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(' ');
                }
                write_value(output, item);
            }
            output.push(']');
        }
        Value::Set(items) => {
            output.push_str("#{");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(' ');
                }
                write_value(output, item);
            }
            output.push('}');
        }
        Value::Dictionary(entries) => {
            output.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    output.push(' ');
                }
                write_value(output, key);
                output.push_str(": ");
                write_value(output, item);
            }
            output.push('}');
        }
        Value::Embedded(inner) => {
            output.push_str("#:");
            write_value(output, inner);
        }
    }
}

/// Write a symbol using the diagnostic text syntax.
pub fn write_symbol(formatter: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
    match write_symbol_string(text) {
        Ok(bare) => formatter.write_str(&bare),
        Err(quoted) => formatter.write_str(&quoted),
    }
}

fn write_symbol_string(text: &str) -> Result<String, String> {
    if is_bare_symbol(text) {
        Ok(text.to_owned())
    } else {
        let escaped = text.replace('\\', "\\\\").replace('|', "\\|");
        Err(format!("|{escaped}|"))
    }
}

fn is_bare_symbol(text: &str) -> bool {
    let mut characters = text.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    characters.all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '/')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;

    #[test]
    fn renders_compound_values() {
        let value = Value::dictionary([
            (Value::symbol("name"), Value::string("Cedar Notes")),
            (Value::symbol("large"), Value::integer(1_i64)),
        ]);
        assert_eq!(render(&value), "{large: 1 name: \"Cedar Notes\"}");
    }

    #[test]
    fn quotes_symbols_that_need_escaping() {
        assert_eq!(render(&Value::symbol("plain-name")), "plain-name");
        assert_eq!(render(&Value::symbol("two words")), "|two words|");
        assert_eq!(render(&Value::symbol("a|b")), "|a\\|b|");
    }

    #[test]
    fn renders_bytes_and_embedded_markers() {
        assert_eq!(render(&Value::bytes([0_u8, 255])), "#x\"00ff\"");
        assert_eq!(render(&Value::embedded(Value::Boolean(true))), "#:#t");
    }
}
