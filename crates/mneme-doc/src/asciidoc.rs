//! Bounded source scanning for the supported AsciiDoc subset.
//!
//! The scanner never treats an AST as authoritative: callers retain exact
//! source bytes and use byte spans from this module.

/// A source-local diagnostic with a stable code and display position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub message: String,
    pub line: usize,
    pub column: usize,
    pub span: Option<mneme_core::SourceSpan>,
    /// Fatal diagnostics reject an import; warnings are preview-only.
    pub fatal: bool,
}

impl Diagnostic {
    #[allow(unknown_lints, usize_in_public_api)] // line/column mirror source positions
    pub fn new(
        code: &'static str,
        message: impl Into<String>,
        line: usize,
        column: usize,
        span: Option<mneme_core::SourceSpan>,
    ) -> Self {
        Diagnostic {
            code,
            message: message.into(),
            line,
            column,
            span,
            fatal: true,
        }
    }

    /// A non-fatal diagnostic that does not reject the source bytes.
    #[allow(unknown_lints, usize_in_public_api)] // line/column mirror source positions
    pub fn warning(
        code: &'static str,
        message: impl Into<String>,
        line: usize,
        column: usize,
        span: Option<mneme_core::SourceSpan>,
    ) -> Self {
        let mut diagnostic = Diagnostic::new(code, message, line, column, span);
        diagnostic.fatal = false;
        diagnostic
    }
}

/// Parsed document header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub title: Option<String>,
    pub entity_id: Option<mneme_core::RecordId>,
}

/// One include directive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncludeDirective {
    pub target: String,
    pub optional: bool,
    pub span: mneme_core::SourceSpan,
    pub line: usize,
    pub column: usize,
}

/// One explicit source anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorSpec {
    pub anchor: String,
    pub label: Option<String>,
    pub span: mneme_core::SourceSpan,
    pub line: usize,
    pub column: usize,
}

#[derive(Clone, Debug)]
struct Line<'a> {
    text: &'a str,
    start: usize,
    end: usize,
    number: usize,
}

impl Line<'_> {
    fn span(&self) -> Option<mneme_core::SourceSpan> {
        if self.text.is_empty() {
            return None;
        }
        mneme_core::SourceSpan::new(self.start as u64, (self.end - 1) as u64).ok()
    }
}

#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn lines(text: &str) -> Vec<Line<'_>> {
    let max_lines = text.split_inclusive('\n').count();
    let mut output = Vec::with_capacity(max_lines);
    let mut offset = 0;
    for (index, chunk) in text.split_inclusive('\n').enumerate() {
        let start = offset;
        offset += chunk.len();
        let text = chunk.strip_suffix('\n').unwrap_or(chunk);
        let text = text.strip_suffix('\r').unwrap_or(text);
        let end = start + text.len();
        output.push(Line {
            text,
            start,
            end,
            number: index + 1,
        });
    }
    if offset < text.len() {
        output.push(Line {
            text: &text[offset..],
            start: offset,
            end: text.len(),
            number: output.len() + 1,
        });
    }
    output
}

/// Parse the document header and literal entity binding.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn parse_header(text: &str) -> Result<Header, Vec<Diagnostic>> {
    let source_lines = lines(text);
    let mut diagnostics = Vec::with_capacity(source_lines.len().saturating_add(1));
    let mut header = Header::default();
    let mut is_seen_entity = false;
    let mut is_conditional = false;
    for line in source_lines {
        if !parse_header_line(
            &line,
            &mut header,
            &mut is_seen_entity,
            &mut is_conditional,
            &mut diagnostics,
        ) {
            break;
        }
    }
    if is_conditional && is_seen_entity {
        diagnostics.push(Diagnostic::new(
            "binding-conditional",
            "entity-id cannot be controlled by a conditional",
            1,
            1,
            None,
        ));
    }
    if diagnostics.is_empty() {
        Ok(header)
    } else {
        Err(diagnostics)
    }
}

fn parse_header_line(
    line: &Line<'_>,
    header: &mut Header,
    is_seen_entity: &mut bool,
    is_conditional: &mut bool,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    let content = line.text.trim();
    if content.is_empty() {
        return false;
    }
    if content.starts_with("//") {
        return true;
    }
    if content.starts_with("ifdef::")
        || content.starts_with("ifndef::")
        || content.starts_with("ifeval::")
    {
        *is_conditional = true;
        return true;
    }
    if let Some(title) = content.strip_prefix("= ") {
        if header.title.is_none() {
            header.title = Some(title.trim().to_owned());
        }
        return true;
    }
    if let Some(rest) = content.strip_prefix(':') {
        parse_entity_header_attribute(rest, line, header, is_seen_entity, diagnostics);
    }
    true
}

fn parse_entity_header_attribute(
    rest: &str,
    line: &Line<'_>,
    header: &mut Header,
    is_seen_entity: &mut bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if rest.starts_with("entity-id!:") {
        diagnostics.push(Diagnostic::new(
            "binding-unset",
            "entity-id cannot be unset in a document header",
            line.number,
            1,
            line.span(),
        ));
        return;
    }
    let Some((name, value)) = rest.split_once(':') else {
        return;
    };
    if name.trim() != "entity-id" {
        return;
    }
    if *is_seen_entity {
        diagnostics.push(Diagnostic::new(
            "binding-conflict",
            "document declares entity-id more than once",
            line.number,
            1,
            line.span(),
        ));
        return;
    }
    *is_seen_entity = true;
    let value = value.trim();
    if value.is_empty() {
        diagnostics.push(Diagnostic::new(
            "binding-invalid",
            "entity-id must be a literal opaque identifier",
            line.number,
            1,
            line.span(),
        ));
        return;
    }
    if value.contains('{')
        || value.contains('}')
        || value.contains('+')
        || value.starts_with("pass:")
        || value.chars().any(char::is_whitespace)
    {
        diagnostics.push(Diagnostic::new(
            "binding-substitution",
            "entity-id must not use substitutions or continuations",
            line.number,
            1,
            line.span(),
        ));
        return;
    }
    match mneme_core::RecordId::from_hex(value) {
        Ok(id) => header.entity_id = Some(id),
        Err(_) => diagnostics.push(Diagnostic::new(
            "binding-invalid",
            "entity-id is not a valid opaque identifier",
            line.number,
            1,
            line.span(),
        )),
    }
}

/// Scan include directives without resolving them.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn scan_includes(text: &str) -> Vec<IncludeDirective> {
    let source_lines = lines(text);
    let mut includes = Vec::with_capacity(source_lines.len());
    for line in source_lines {
        let raw = line.text;
        let Some(start) = raw.find("include::") else {
            continue;
        };
        if !raw[..start].trim().is_empty() {
            continue;
        }
        let rest = &raw[start + "include::".len()..];
        let Some(open) = rest.find('[') else {
            continue;
        };
        let Some(close_rel) = rest[open + 1..].find(']') else {
            continue;
        };
        let target = rest[..open].trim();
        let attributes = &rest[open + 1..open + 1 + close_rel];
        if target.is_empty() {
            continue;
        }
        let is_optional = attributes
            .split(',')
            .any(|attribute| attribute.trim().trim_matches('"') == "opts=optional");
        if let Some(span) = line.span() {
            includes.push(IncludeDirective {
                target: target.to_owned(),
                optional: is_optional,
                span,
                line: line.number,
                column: start + 1,
            });
        }
    }
    includes
}

/// Scan explicit anchors. Heading-derived IDs are intentionally not invented.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn scan_anchors(text: &str) -> Vec<AnchorSpec> {
    let source_lines = lines(text);
    let mut anchors = Vec::with_capacity(source_lines.len());
    for line in source_lines {
        let content = line.text.trim();
        let (inner, explicit) = if content.starts_with("[[") && content.ends_with("]]") {
            (&content[2..content.len() - 2], "bracket")
        } else if content.starts_with("[#") && content.ends_with(']') {
            (&content[2..content.len() - 1], "attribute")
        } else {
            continue;
        };
        let _ = explicit;
        let (id, label) = match inner.split_once(',') {
            Some((id, label)) => (id.trim(), Some(label.trim().to_owned())),
            None => (inner.trim(), None),
        };
        if !valid_anchor(id) {
            continue;
        }
        if let Some(span) = line.span() {
            anchors.push(AnchorSpec {
                anchor: id.to_owned(),
                label,
                span,
                line: line.number,
                column: 1,
            });
        }
    }
    anchors
}

/// Whether an explicit anchor name is safe for an HTML id.
pub fn valid_anchor(anchor: &str) -> bool {
    let mut characters = anchor.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | ':' | '.')
        })
}

/// Normalize a logical include path relative to the including document.
pub fn normalize_include_path(origin: &str, target: &str) -> Result<String, Diagnostic> {
    if target.contains("://")
        || target.starts_with("//")
        || target.starts_with("file:")
        || target.starts_with('/')
        || target.starts_with('\\')
        || target.contains('\\')
        || target.contains('{')
    {
        return Err(Diagnostic::new(
            "include-remote-or-absolute",
            "include target must be a local relative path without substitutions",
            1,
            1,
            None,
        ));
    }
    let mut segments: Vec<&str> = origin.split('/').collect();
    segments.pop();
    for segment in target.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Err(Diagnostic::new(
                        "include-path-escape",
                        "include target escapes the authorized workspace root",
                        1,
                        1,
                        None,
                    ));
                }
            }
            other => segments.push(other),
        }
    }
    if segments.is_empty() {
        return Err(Diagnostic::new(
            "include-path-empty",
            "include target does not name a document",
            1,
            1,
            None,
        ));
    }
    Ok(segments.join("/"))
}

/// Check a canonical logical path against configured allowlist roots.
pub fn allowed_path(path: &str, roots: &[String]) -> bool {
    roots.iter().any(|root| {
        root.is_empty()
            || path == root
            || path
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// A paragraph-like authored block with an exact source span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paragraph {
    pub span: mneme_core::SourceSpan,
    pub line: usize,
    pub column: usize,
}

/// Scan authored paragraphs, excluding headings, directives, anchors, comments,
/// listing/passthrough blocks, tables, and the document header.
pub fn scan_paragraphs(text: &str) -> Vec<Paragraph> {
    let mut paragraphs = Vec::new();
    let mut is_in_header = true;
    let mut mode = None::<&str>;
    let mut current: Option<(usize, usize, usize, usize)> = None;
    for line in lines(text) {
        let trimmed = line.text.trim();
        if is_in_header {
            if trimmed.is_empty() {
                is_in_header = false;
            }
            continue;
        }
        if let Some(block) = mode {
            let is_closes = match block {
                "----" | "...." => trimmed == "----" || trimmed == "....",
                "++++" => trimmed == "++++",
                "////" => trimmed == "////",
                "|===" => trimmed == "|===",
                _ => false,
            };
            if is_closes {
                mode = None;
            }
            continue;
        }
        match trimmed {
            "----" | "...." | "++++" | "////" | "|===" => {
                flush_paragraph(&mut paragraphs, &mut current);
                mode = Some(match trimmed {
                    "----" => "----",
                    "...." => "....",
                    "++++" => "++++",
                    "////" => "////",
                    _ => "|===",
                });
                continue;
            }
            "" => {
                flush_paragraph(&mut paragraphs, &mut current);
                continue;
            }
            _ => {}
        }
        if trimmed.starts_with("include::")
            || trimmed.starts_with("[[")
            || trimmed.starts_with("[#")
            || trimmed.starts_with("//")
            || trimmed.starts_with(':')
            || trimmed.starts_with("ifdef::")
            || trimmed.starts_with("ifndef::")
            || trimmed.starts_with("ifeval::")
            || heading(trimmed).is_some()
        {
            flush_paragraph(&mut paragraphs, &mut current);
            continue;
        }
        if let Some((_, end, _, _)) = current.as_mut() {
            *end = line.end;
        } else {
            current = Some((line.start, line.end, line.number, 1));
        }
    }
    flush_paragraph(&mut paragraphs, &mut current);
    paragraphs
}

fn flush_paragraph(
    paragraphs: &mut Vec<Paragraph>,
    current: &mut Option<(usize, usize, usize, usize)>,
) {
    if let Some((start, end, line, column)) = current.take()
        && end > start
        && let Ok(span) = mneme_core::SourceSpan::new(start as u64, (end - 1) as u64)
    {
        paragraphs.push(Paragraph { span, line, column });
    }
}

fn heading(trimmed: &str) -> Option<(usize, &str)> {
    let level = trimmed
        .chars()
        .take_while(|character| *character == '=')
        .count();
    if level == 0 || level > 6 {
        return None;
    }
    let rest = &trimmed[level..];
    rest.starts_with(' ').then_some((level, rest.trim()))
}
