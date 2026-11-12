//! Human-readable Preserves text rendering for diagnostics and CLI output.
//!
//! This is a writer, not a parser. The lossless interchange contract is the
//! tagged JSON transport; text output is for people reading logs, errors, and
//! summaries. Symbols are quoted when they are not comfortably readable. The
//! exact textual representation is not used for hashing or persistence.

/// Render a value using Preserves text syntax for human consumption.
pub fn render(value: &crate::typed::Value) -> String {
    let mut output = String::new();
    write_value(&mut output, value);
    output
}

enum RenderWork<'a> {
    Value(&'a crate::typed::Value),
    Text(&'static str),
}

fn write_value(output: &mut String, value: &crate::typed::Value) {
    let mut work = vec![RenderWork::Value(value)];
    while let Some(task) = work.pop() {
        match task {
            RenderWork::Text(text) => output.push_str(text),
            RenderWork::Value(value) => {
                if !write_scalar(output, value) {
                    write_composite(&mut work, value);
                }
            }
        }
    }
}

fn write_scalar(output: &mut String, value: &crate::typed::Value) -> bool {
    match value {
        crate::typed::Value::Boolean(true) => output.push_str("#t"),
        crate::typed::Value::Boolean(false) => output.push_str("#f"),
        crate::typed::Value::Double(double) => {
            let raw = double.value();
            if raw.is_finite() {
                output.push_str(&format!("{raw:?}"));
            } else {
                output.push_str(&format!("#xd\"{:016x}\"", double.bits()));
            }
        }
        crate::typed::Value::SignedInteger(integer) => output.push_str(&integer.to_string()),
        crate::typed::Value::String(text) => match serde_json::to_string(text) {
            Ok(quoted) => output.push_str(&quoted),
            Err(_) => output.push_str(&format!("{text:?}")),
        },
        crate::typed::Value::ByteString(bytes) => {
            output.push_str("#x\"");
            for byte in bytes.as_slice() {
                output.push_str(&format!("{byte:02x}"));
            }
            output.push('"');
        }
        crate::typed::Value::Symbol(symbol) => match write_symbol_string(symbol.as_str()) {
            Ok(bare) => output.push_str(&bare),
            Err(quoted) => output.push_str(&quoted),
        },
        _ => return false,
    }
    true
}

fn write_composite<'a>(work: &mut Vec<RenderWork<'a>>, value: &'a crate::typed::Value) {
    match value {
        crate::typed::Value::Record(record) => {
            work.push(RenderWork::Text(">"));
            for field in record.fields().iter().rev() {
                work.push(RenderWork::Value(field));
                work.push(RenderWork::Text(" "));
            }
            work.push(RenderWork::Value(record.label()));
            work.push(RenderWork::Text("<"));
        }
        crate::typed::Value::Sequence(items) => {
            work.push(RenderWork::Text("]"));
            for (index, item) in items.iter().enumerate().rev() {
                work.push(RenderWork::Value(item));
                if index > 0 {
                    work.push(RenderWork::Text(" "));
                }
            }
            work.push(RenderWork::Text("["));
        }
        crate::typed::Value::Set(items) => {
            work.push(RenderWork::Text("}"));
            for (index, item) in items.iter().enumerate().rev() {
                work.push(RenderWork::Value(item));
                if index > 0 {
                    work.push(RenderWork::Text(" "));
                }
            }
            work.push(RenderWork::Text("#{"));
        }
        crate::typed::Value::Dictionary(entries) => {
            work.push(RenderWork::Text("}"));
            for (index, (key, item)) in entries.iter().enumerate().rev() {
                work.push(RenderWork::Value(item));
                work.push(RenderWork::Text(": "));
                work.push(RenderWork::Value(key));
                if index > 0 {
                    work.push(RenderWork::Text(" "));
                }
            }
            work.push(RenderWork::Text("{"));
        }
        crate::typed::Value::Embedded(inner) => {
            work.push(RenderWork::Value(inner));
            work.push(RenderWork::Text("#:"));
        }
        _ => {}
    }
}

/// Write a symbol using the diagnostic text syntax.
pub fn write_symbol(formatter: &mut std::fmt::Formatter<'_>, text: &str) -> std::fmt::Result {
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

    #[test]
    fn renders_compound_values() {
        let value = crate::typed::Value::dictionary([
            (
                crate::typed::Value::symbol("name"),
                crate::typed::Value::string("Cedar Notes"),
            ),
            (
                crate::typed::Value::symbol("large"),
                crate::typed::Value::integer(1_i64),
            ),
        ]);
        assert_eq!(render(&value), "{large: 1 name: \"Cedar Notes\"}");
    }

    #[test]
    fn quotes_symbols_that_need_escaping() {
        assert_eq!(
            render(&crate::typed::Value::symbol("plain-name")),
            "plain-name"
        );
        assert_eq!(
            render(&crate::typed::Value::symbol("two words")),
            "|two words|"
        );
        assert_eq!(render(&crate::typed::Value::symbol("a|b")), "|a\\|b|");
    }

    #[test]
    fn renders_bytes_and_embedded_markers() {
        assert_eq!(
            render(&crate::typed::Value::bytes([0_u8, 255])),
            "#x\"00ff\""
        );
        assert_eq!(
            render(&crate::typed::Value::embedded(
                crate::typed::Value::Boolean(true)
            )),
            "#:#t"
        );
    }
}
