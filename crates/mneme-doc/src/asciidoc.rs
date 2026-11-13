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
    /// Inclusive span of the header declarations (title and attribute
    /// entries), excluding trailing comment lines and the blank line that ends
    /// the header. `None` when the source has no header.
    pub span: Option<mneme_core::SourceSpan>,
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
pub(crate) struct Line<'a> {
    pub(crate) text: &'a str,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) number: usize,
}

impl Line<'_> {
    pub(crate) fn span(&self) -> Option<mneme_core::SourceSpan> {
        if self.text.is_empty() {
            return None;
        }
        mneme_core::SourceSpan::new(self.start as u64, (self.end - 1) as u64).ok()
    }
}

/// Split source into lines, stripping `\n` and `\r\n` terminators.
pub(crate) fn lines(text: &str) -> Vec<Line<'_>> {
    let max_lines = text.split_inclusive('\n').count();
    let mut output = Vec::with_capacity(max_lines);
    let mut offset = 0;
    for (index, chunk) in text.split_inclusive('\n').enumerate() {
        let start = offset;
        offset += chunk.len();
        let content = chunk.strip_suffix('\n').unwrap_or(chunk);
        let content = content.strip_suffix('\r').unwrap_or(content);
        let end = start + content.len();
        output.push(Line {
            text: content,
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

/// A delimited block recognized by the supported subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockKind {
    Comment,
    Listing,
    Literal,
    Passthrough,
    Table,
}

/// A block delimiter and its exact run length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Delimiter {
    kind: BlockKind,
    length: usize,
}

impl Delimiter {
    /// Recognize a delimiter line: a run of four or more identical characters,
    /// or a `|===` table delimiter. Longer runs nest, so only an identical
    /// delimiter closes the block it opened.
    fn parse(content: &str) -> Option<Self> {
        let trimmed = content.trim();
        let first = trimmed.chars().next()?;
        if !matches!(first, '/' | '-' | '.' | '+' | '|') {
            return None;
        }
        let length = trimmed.chars().count();
        if first == '|' {
            let is_table = trimmed
                .chars()
                .all(|character| character == '|' || character == '=');
            let equals = trimmed
                .chars()
                .filter(|character| *character == '=')
                .count();
            if !is_table || equals < 3 || equals == length {
                return None;
            }
            return Some(Delimiter {
                kind: BlockKind::Table,
                length,
            });
        }
        let run = trimmed
            .chars()
            .take_while(|character| *character == first)
            .count();
        if run < 4 || run != length {
            return None;
        }
        let kind = match first {
            '/' => BlockKind::Comment,
            '-' => BlockKind::Listing,
            '.' => BlockKind::Literal,
            '+' => BlockKind::Passthrough,
            _ => return None,
        };
        Some(Delimiter { kind, length })
    }
}

/// Tracks the delimited block that is open in one source scan.
///
/// Comments, listings, literals, passthroughs and tables all hide their content
/// from include, anchor and paragraph scanning, so every scanner shares this
/// state machine instead of re-deriving block boundaries.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BlockState {
    open: Option<Delimiter>,
}

impl BlockState {
    /// The kind of the open block, when one is open.
    pub(crate) fn kind(&self) -> Option<BlockKind> {
        self.open.map(|delimiter| delimiter.kind)
    }

    /// Whether a delimited block is currently open.
    pub(crate) fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// Apply one line. Returns whether the line was a delimiter for the
    /// supported subset: it either opens a block or closes the identical one.
    pub(crate) fn apply(&mut self, content: &str) -> bool {
        let Some(delimiter) = Delimiter::parse(content) else {
            return false;
        };
        match self.open {
            Some(open) if open == delimiter => {
                self.open = None;
                true
            }
            Some(_) => false,
            None => {
                self.open = Some(delimiter);
                true
            }
        }
    }
}

/// The document title of a line, when the line declares one.
fn document_title(content: &str) -> Option<&str> {
    content.strip_prefix("= ").map(str::trim)
}

pub(crate) fn is_conditional(content: &str) -> bool {
    content.starts_with("ifdef::")
        || content.starts_with("ifndef::")
        || content.starts_with("ifeval::")
}

/// Parse a header attribute entry, returning its lowercased name and whether
/// the entry unsets the attribute.
///
/// Both `:name!:` and `:!name:` unset the attribute; names are compared
/// case-insensitively because AsciiDoc lowercases attribute names.
fn attribute_entry_name(content: &str) -> Option<(&str, bool)> {
    let rest = content.strip_prefix(':')?;
    if let Some(unset) = rest.strip_prefix('!') {
        let name = unset.split_once(':').map_or(unset, |(name, _)| name).trim();
        return (!name.is_empty()).then_some((name, true));
    }
    let (name, _value) = rest.split_once(':')?;
    let is_unset = name.ends_with('!');
    let name = name.trim_end_matches('!').trim();
    (!name.is_empty()).then_some((name, is_unset))
}

/// The value of a header attribute entry.
fn attribute_entry_value(content: &str) -> Option<&str> {
    let rest = content.strip_prefix(':')?;
    let (_name, value) = rest.split_once(':')?;
    Some(value.trim())
}

/// Whether the line is an attribute entry rather than prose.
pub(crate) fn is_attribute_entry(content: &str) -> bool {
    attribute_entry_name(content).is_some()
}

/// Number of leading lines that belong to the document header.
///
/// A header exists only when the first declaration is a document title or an
/// attribute entry; header-less sources (included fragments) have none, so
/// their first paragraph is body text.
pub(crate) fn header_extent(text: &str) -> Option<usize> {
    let source_lines = lines(text);
    let scan = scan_header_lines(&source_lines);
    scan.has_header.then_some(scan.consumed)
}

/// Consume the leading lines that form the document header.
fn scan_header_lines(source_lines: &[Line<'_>]) -> HeaderScan {
    let mut scan = HeaderScan::new();
    for line in source_lines {
        if !scan.consume(line) {
            break;
        }
    }
    scan
}

/// Parse the document header and literal entity binding.
pub fn parse_header(text: &str) -> Result<Header, Vec<Diagnostic>> {
    let source_lines = lines(text);
    let scan = scan_header_lines(&source_lines);
    let consumed = scan.consumed;
    let has_header = scan.has_header;
    let is_conditional = scan.is_conditional;
    let is_seen_entity = scan.is_seen_entity;
    let mut state = scan.state;
    let mut diagnostics = scan.diagnostics;
    let header = if has_header {
        scan.header
    } else {
        Header::default()
    };
    if is_conditional && is_seen_entity {
        diagnostics.push(Diagnostic::new(
            "binding-conditional",
            "entity-id cannot be controlled by a conditional",
            1,
            1,
            None,
        ));
    }
    scan_body_entity_declarations(&source_lines[consumed..], &mut state, &mut diagnostics);
    if diagnostics.is_empty() {
        Ok(header)
    } else {
        Err(diagnostics)
    }
}

/// Scan the rest of the source for `entity-id` declarations.
///
/// AsciiDoc applies attribute entries wherever they appear, so a declaration in
/// the body would silently override the header binding. Comment blocks and
/// listing-style blocks are prose about bindings, not bindings, and stay legal.
fn scan_body_entity_declarations(
    source_lines: &[Line<'_>],
    state: &mut BlockState,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for line in source_lines {
        let content = line.text.trim();
        if state.is_open() {
            state.apply(content);
            continue;
        }
        if content.is_empty() {
            continue;
        }
        if state.apply(content) {
            continue;
        }
        if content.starts_with("//") {
            continue;
        }
        let Some((name, _is_unset)) = attribute_entry_name(content) else {
            continue;
        };
        if !name.eq_ignore_ascii_case("entity-id") {
            continue;
        }
        diagnostics.push(Diagnostic::new(
            "binding-outside-header",
            "entity-id must be declared in the document header",
            line.number,
            1,
            line.span(),
        ));
    }
}

struct HeaderScan {
    header: Header,
    diagnostics: Vec<Diagnostic>,
    state: BlockState,
    is_seen_entity: bool,
    is_conditional: bool,
    has_header: bool,
    consumed: usize,
}

impl HeaderScan {
    fn new() -> Self {
        HeaderScan {
            header: Header::default(),
            diagnostics: Vec::new(),
            state: BlockState::default(),
            is_seen_entity: false,
            is_conditional: false,
            has_header: false,
            consumed: 0,
        }
    }

    /// Consume one line; returns whether the line belongs to the header.
    fn consume(&mut self, line: &Line<'_>) -> bool {
        let content = line.text.trim();
        if self.state.is_open() {
            self.state.apply(content);
            self.advance(line);
            return true;
        }
        if content.is_empty() {
            return false;
        }
        if self.state.apply(content) {
            self.advance(line);
            return true;
        }
        if content.starts_with("//") {
            self.advance(line);
            return true;
        }
        if let Some(title) = document_title(content) {
            self.has_header = true;
            if self.header.title.is_none() {
                self.header.title = Some(title.to_owned());
            }
            self.advance(line);
            return true;
        }
        if is_conditional(content) {
            self.is_conditional = true;
            self.advance(line);
            return true;
        }
        if let Some((name, is_unset)) = attribute_entry_name(content) {
            self.has_header = true;
            if name.eq_ignore_ascii_case("entity-id") {
                self.entity_entry(content, is_unset, line);
            }
            self.advance(line);
            return true;
        }
        false
    }

    fn advance(&mut self, line: &Line<'_>) {
        self.consumed += 1;
        let Some(line_span) = line.span() else {
            return;
        };
        let start = self
            .header
            .span
            .map_or(line_span.start(), |span| span.start());
        self.header.span = mneme_core::SourceSpan::new(start, line_span.end()).ok();
    }

    fn entity_entry(&mut self, content: &str, is_unset: bool, line: &Line<'_>) {
        if is_unset {
            self.diagnostics.push(Diagnostic::new(
                "binding-unset",
                "entity-id cannot be unset in a document header",
                line.number,
                1,
                line.span(),
            ));
            return;
        }
        if self.is_seen_entity {
            self.diagnostics.push(Diagnostic::new(
                "binding-conflict",
                "document declares entity-id more than once",
                line.number,
                1,
                line.span(),
            ));
            return;
        }
        self.is_seen_entity = true;
        self.entity_value(content, line);
    }

    fn entity_value(&mut self, content: &str, line: &Line<'_>) {
        let value = attribute_entry_value(content).unwrap_or_default();
        if value.is_empty() {
            self.diagnostics.push(Diagnostic::new(
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
            self.diagnostics.push(Diagnostic::new(
                "binding-substitution",
                "entity-id must not use substitutions or continuations",
                line.number,
                1,
                line.span(),
            ));
            return;
        }
        match mneme_core::RecordId::from_hex(value) {
            Ok(id) => self.header.entity_id = Some(id),
            Err(_) => self.diagnostics.push(Diagnostic::new(
                "binding-invalid",
                "entity-id is not a valid opaque identifier",
                line.number,
                1,
                line.span(),
            )),
        }
    }
}

/// Scan include directives without resolving them.
///
/// Directives inside comments and delimited blocks are literal text, not
/// includes, and are skipped.
pub fn scan_includes(text: &str) -> Vec<IncludeDirective> {
    scan_includes_checked(text).0
}

/// Scan include directives and refuse attribute lists the subset cannot honour.
///
/// Only `opts=optional` is interpreted. Every other attribute (`tag=`,
/// `lines=`, `leveloffset=`, ...) selects content this processor would silently
/// ignore, so the directive is refused with a source-local diagnostic instead
/// of rendering the whole target.
pub fn scan_includes_checked(text: &str) -> (Vec<IncludeDirective>, Vec<Diagnostic>) {
    let source_lines = lines(text);
    let mut state = BlockState::default();
    let mut includes = Vec::new();
    let mut diagnostics = Vec::new();
    for line in &source_lines {
        let content = line.text.trim();
        if state.is_open() {
            state.apply(content);
            continue;
        }
        if content.is_empty() {
            continue;
        }
        if state.apply(content) {
            continue;
        }
        if content.starts_with("//") {
            continue;
        }
        scan_include_line(line, &mut includes, &mut diagnostics);
    }
    (includes, diagnostics)
}

fn scan_include_line(
    line: &Line<'_>,
    includes: &mut Vec<IncludeDirective>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let raw = line.text;
    let Some(start) = raw.find("include::") else {
        return;
    };
    if !raw[..start].trim().is_empty() {
        return;
    }
    let rest = &raw[start + "include::".len()..];
    let Some(open) = rest.find('[') else {
        return;
    };
    let Some(close_rel) = rest[open + 1..].find(']') else {
        return;
    };
    let target = rest[..open].trim();
    if target.is_empty() {
        return;
    }
    let attributes = &rest[open + 1..open + 1 + close_rel];
    match parse_include_attributes(attributes) {
        Ok(optional) => {
            if let Some(span) = line.span() {
                includes.push(IncludeDirective {
                    target: target.to_owned(),
                    optional,
                    span,
                    line: line.number,
                    column: start + 1,
                });
            }
        }
        Err(attribute) => diagnostics.push(Diagnostic::new(
            "include-attribute-unsupported",
            format!("include attribute {attribute:?} is not supported"),
            line.number,
            start + 1,
            line.span(),
        )),
    }
}

/// Interpret an include attribute list; `Err` names the first attribute the
/// supported subset cannot honour.
fn parse_include_attributes(attributes: &str) -> Result<bool, String> {
    let mut is_optional = false;
    for raw in attributes.split(',') {
        let attribute = raw.trim();
        if attribute.is_empty() {
            continue;
        }
        if attribute == "opts=optional" || attribute == "opts=\"optional\"" {
            is_optional = true;
            continue;
        }
        return Err(attribute.to_owned());
    }
    Ok(is_optional)
}

/// Scan explicit anchors. Heading-derived IDs are intentionally not invented.
///
/// Anchors inside comments and delimited blocks address text that is never
/// rendered, so they are not anchors.
pub fn scan_anchors(text: &str) -> Vec<AnchorSpec> {
    let source_lines = lines(text);
    let mut state = BlockState::default();
    let mut anchors = Vec::with_capacity(source_lines.len());
    for line in &source_lines {
        let content = line.text.trim();
        if state.is_open() {
            state.apply(content);
            continue;
        }
        if content.is_empty() {
            continue;
        }
        if state.apply(content) {
            continue;
        }
        if content.starts_with("//") {
            continue;
        }
        let inner = if content.starts_with("[[") && content.ends_with("]]") {
            &content[2..content.len() - 2]
        } else if content.starts_with("[#") && content.ends_with(']') {
            &content[2..content.len() - 1]
        } else {
            continue;
        };
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
    let source_lines = lines(text);
    let extent = header_extent(text).unwrap_or(0);
    let mut paragraphs = Vec::new();
    let mut state = BlockState::default();
    let mut current: Option<(usize, usize, usize, usize)> = None;
    for line in source_lines.iter().skip(extent) {
        let content = line.text.trim();
        if state.is_open() {
            state.apply(content);
            flush_paragraph(&mut paragraphs, &mut current);
            continue;
        }
        if content.is_empty() {
            flush_paragraph(&mut paragraphs, &mut current);
            continue;
        }
        if state.apply(content) {
            flush_paragraph(&mut paragraphs, &mut current);
            continue;
        }
        if content.starts_with("include::")
            || content.starts_with("image::")
            || content.starts_with("[[")
            || content.starts_with("[#")
            || content.starts_with("//")
            || content.starts_with(':')
            || is_conditional(content)
            || heading(content).is_some()
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
