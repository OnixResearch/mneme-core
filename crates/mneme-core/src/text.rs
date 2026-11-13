//! Human-readable Preserves text rendering for diagnostics and CLI output.
//!
//! This is a writer, not a parser. The lossless interchange contract is the
//! tagged JSON transport; text output is for people reading logs, errors, and
//! summaries. Symbols are quoted when they are not comfortably readable. The
//! exact textual representation is not used for hashing or persistence.
//!
//! Control, invisible and bidirectional-control characters are always escaped,
//! because the text is read on terminals: record content must not be able to
//! clear the screen, recolour text, reorder it or forge a second output line.
//! Printable text renders unchanged, and a rendered string is a valid Preserves
//! text string that parses back to the same text.

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
        crate::typed::Value::String(text) => write_string(output, text),
        crate::typed::Value::ByteString(bytes) => {
            output.push_str("#x\"");
            for byte in bytes.as_slice() {
                output.push_str(&format!("{byte:02x}"));
            }
            output.push('"');
        }
        crate::typed::Value::Symbol(symbol) => output.push_str(&render_symbol(symbol.as_str())),
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
    formatter.write_str(&render_symbol(text))
}

/// Render a symbol: bare when it is comfortably readable, quoted otherwise.
fn render_symbol(text: &str) -> String {
    if is_bare_symbol(text) {
        return text.to_owned();
    }
    let mut rendered = String::with_capacity(text.len() + 2);
    rendered.push('|');
    for character in text.chars() {
        if character == '|' {
            rendered.push_str("\\|");
        } else {
            write_quoted_character(&mut rendered, character);
        }
    }
    rendered.push('|');
    rendered
}

/// Append a string as a quoted Preserves text string literal.
fn write_string(output: &mut String, text: &str) {
    output.push('"');
    for character in text.chars() {
        if character == '"' {
            output.push_str("\\\"");
        } else {
            write_quoted_character(output, character);
        }
    }
    output.push('"');
}

/// Append one character of a quoted text form, escaping what must be escaped.
///
/// The escapes are the Preserves text string escapes, so a rendered string
/// parses back to the same text; the quoted-symbol form uses the same set.
fn write_quoted_character(output: &mut String, character: char) {
    match character {
        '\\' => output.push_str("\\\\"),
        '\n' => output.push_str("\\n"),
        '\r' => output.push_str("\\r"),
        '\t' => output.push_str("\\t"),
        '\u{08}' => output.push_str("\\b"),
        '\u{0C}' => output.push_str("\\f"),
        other if is_nonprinting(other) => write_code_point_escape(output, other),
        other => output.push(other),
    }
}

/// Whether a character must be escaped because it is invisible or reorders text.
///
/// Covers the C0, DEL and C1 controls, the Unicode format characters that
/// render as nothing or change the direction of the text around them, and the
/// line and paragraph separators, none of which may reach a terminal.
///
/// Exposed crate-wide so diagnostic message escaping can apply the same rule to
/// text it interpolates.
pub(crate) fn is_nonprinting(character: char) -> bool {
    if character.is_control() {
        return true;
    }
    matches!(
        u32::from(character),
        0x00AD
            | 0x061C
            | 0x180E
            | 0xFEFF
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x206F
            | 0xE0000..=0xE007F
    )
}

/// Append the `\uXXXX` escape for a character.
///
/// Code points above the basic multilingual plane use a UTF-16 surrogate pair,
/// because a bare surrogate is not a valid Preserves text escape.
fn write_code_point_escape(output: &mut String, character: char) {
    let scalar = u32::from(character);
    if scalar <= 0xFFFF {
        write_escape_unit(output, scalar);
        return;
    }
    let adjusted = scalar - 0x1_0000;
    write_escape_unit(output, 0xD800 + (adjusted >> 10));
    write_escape_unit(output, 0xDC00 + (adjusted & 0x3FF));
}

/// Append `\u` and the four hexadecimal digits of one UTF-16 code unit.
fn write_escape_unit(output: &mut String, unit: u32) {
    output.push_str("\\u");
    for shift in [12_u32, 8, 4, 0] {
        // Masking keeps the digit below the radix, so a digit always results.
        if let Some(digit) = char::from_digit((unit >> shift) & 0xF, 16) {
            output.push(digit);
        }
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
