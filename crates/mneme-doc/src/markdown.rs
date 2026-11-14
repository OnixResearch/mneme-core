//! Markdown notes: front matter, title, entity binding, authored paragraphs, the
//! binding patch and a restricted HTML preview.
//!
//! Front matter is a block of `key: value` lines between `---` lines at the very
//! start of the source. Only `title` and `entity-id` carry meaning here; other
//! keys are kept byte for byte and ignored. A note without a front matter title
//! takes its title from its first `# ` heading outside fenced code. Markdown has
//! no include or anchor syntax: `include::` and `[[...]]` stay text, and `[[...]]`
//! renders as a wiki link.

/// Whether a logical path names a Markdown note: `.md` or `.markdown`.
pub fn is_note_path(path: &str) -> bool {
    let extension = std::path::Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    extension.eq_ignore_ascii_case("md") || extension.eq_ignore_ascii_case("markdown")
}

/// One `key: value` front matter line.
struct Entry<'a> {
    key: &'a str,
    value: &'a str,
    /// The one-based line number.
    number: usize,
    /// Byte offsets of the line's text, without its line break.
    start: usize,
    end: usize,
    span: Option<mneme_core::SourceSpan>,
}

/// The front matter block at the start of a source.
struct FrontMatter<'a> {
    entries: Vec<Entry<'a>>,
    /// Where the opening delimiter starts.
    open_start: usize,
    /// Where the closing delimiter line starts and its text ends.
    close_start: usize,
    close_end: usize,
}

/// The front matter of `lines`, when the first line opens one that a later
/// `---` or `...` line closes.
fn front_matter<'a>(lines: &[crate::asciidoc::Line<'a>]) -> Option<FrontMatter<'a>> {
    let open = lines.first().filter(|line| line.text == "---")?;
    let close_index = lines
        .iter()
        .skip(1)
        .position(|line| line.text == "---" || line.text == "...")?
        .saturating_add(1);
    let entries = lines
        .get(1..close_index)?
        .iter()
        .filter_map(|line| {
            let (key, value) = line.text.split_once(':')?;
            let key = key.trim();
            (!key.is_empty() && !key.starts_with('#')).then(|| Entry {
                key,
                value: unquote(value.trim()),
                number: line.number,
                start: line.start,
                end: line.end,
                span: line.span(),
            })
        })
        .collect();
    let close = lines.get(close_index)?;
    Some(FrontMatter {
        entries,
        open_start: open.start,
        close_start: close.start,
        close_end: close.end,
    })
}

/// A value without one pair of surrounding single or double quotes.
fn unquote(value: &str) -> &str {
    ['"', '\'']
        .iter()
        .find_map(|quote| {
            value
                .strip_prefix(*quote)
                .and_then(|inner| inner.strip_suffix(*quote))
        })
        .unwrap_or(value)
}

/// Whether a line opens or closes fenced code, and with which marker.
fn fence(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    ["```", "~~~"]
        .into_iter()
        .find(|marker| trimmed.starts_with(marker))
}

/// The level and text of an ATX heading: one to six `#` and a space.
fn heading(line: &str) -> Option<(usize, &str)> {
    let level = line.bytes().take_while(|byte| *byte == b'#').count();
    let rest = line.get(level..)?;
    let is_heading = (1..=6).contains(&level) && (rest.is_empty() || rest.starts_with(' '));
    is_heading.then(|| (level, rest.trim().trim_end_matches('#').trim_end()))
}

/// The lines after the front matter, with whether each is inside fenced code.
fn body_lines<'a>(
    lines: &'a [crate::asciidoc::Line<'a>],
) -> impl Iterator<Item = (bool, &'a crate::asciidoc::Line<'a>)> {
    let skip = front_matter(lines).map_or(0, |matter| {
        lines
            .iter()
            .position(|line| line.start == matter.close_start)
            .map_or(0, |index| index.saturating_add(1))
    });
    let mut open: Option<&'static str> = None;
    lines.iter().skip(skip).map(move |line| {
        let marker = fence(line.text);
        let is_code = match (open, marker) {
            (Some(current), Some(found)) if current == found => {
                open = None;
                true
            }
            (Some(_), _) => true,
            (None, Some(found)) => {
                open = Some(found);
                true
            }
            (None, None) => false,
        };
        (is_code, line)
    })
}

/// Parse the front matter title and literal entity binding, or the first
/// heading's title.
pub fn parse_header(
    text: &str,
) -> Result<crate::asciidoc::Header, Vec<crate::asciidoc::Diagnostic>> {
    let lines = crate::asciidoc::lines(text);
    let mut header = crate::asciidoc::Header::default();
    let mut diagnostics = Vec::new();
    if let Some(matter) = front_matter(&lines) {
        header.span =
            mneme_core::SourceSpan::new(matter.open_start as u64, matter.close_end as u64).ok();
        let mut is_seen_entity = false;
        for entry in &matter.entries {
            if entry.key.eq_ignore_ascii_case("title") && !entry.value.is_empty() {
                header.title = Some(entry.value.to_owned());
            }
            if !entry.key.eq_ignore_ascii_case("entity-id") {
                continue;
            }
            if is_seen_entity {
                diagnostics.push(crate::asciidoc::Diagnostic::new(
                    "binding-conflict",
                    "document declares entity-id more than once",
                    entry.number,
                    1,
                    entry.span,
                ));
                continue;
            }
            is_seen_entity = true;
            match mneme_core::RecordId::from_hex(entry.value) {
                Ok(id) => header.entity_id = Some(id),
                Err(_) => diagnostics.push(crate::asciidoc::Diagnostic::new(
                    "binding-invalid",
                    "entity-id is not a valid opaque identifier",
                    entry.number,
                    1,
                    entry.span,
                )),
            }
        }
    }
    if header.title.is_none() {
        header.title = body_lines(&lines)
            .filter(|(is_code, _)| !is_code)
            .find_map(|(_, line)| heading(line.text).filter(|(level, _)| *level == 1))
            .map(|(_, title)| title.to_owned())
            .filter(|title| !title.is_empty());
    }
    if diagnostics.is_empty() {
        Ok(header)
    } else {
        Err(diagnostics)
    }
}

/// Authored paragraphs: runs of text lines outside the front matter, fenced
/// code, headings, tables, comments and rules.
pub fn scan_paragraphs(text: &str) -> Vec<crate::asciidoc::Paragraph> {
    let lines = crate::asciidoc::lines(text);
    let mut paragraphs = Vec::with_capacity(lines.len());
    let mut current: Option<(usize, usize, usize)> = None;
    for (is_code, line) in body_lines(&lines) {
        let content = line.text.trim();
        let is_text = !is_code
            && !content.is_empty()
            && heading(content).is_none()
            && !content.starts_with('|')
            && !content.starts_with("<!--")
            && !is_rule(content);
        if !is_text {
            flush(&mut paragraphs, &mut current);
            continue;
        }
        current = Some(match current {
            Some((start, _, number)) => (start, line.end, number),
            None => (line.start, line.end, line.number),
        });
    }
    flush(&mut paragraphs, &mut current);
    paragraphs
}

fn flush(
    paragraphs: &mut Vec<crate::asciidoc::Paragraph>,
    current: &mut Option<(usize, usize, usize)>,
) {
    if let Some((start, end, line)) = current.take()
        && end > start
        && let Ok(span) = mneme_core::SourceSpan::new(start as u64, end.saturating_sub(1) as u64)
    {
        paragraphs.push(crate::asciidoc::Paragraph {
            span,
            line,
            column: 1,
        });
    }
}

/// A thematic break: three or more `-`, `*` or `_` and nothing else.
fn is_rule(content: &str) -> bool {
    let mut marks = content
        .chars()
        .filter(|character| !character.is_whitespace());
    let Some(first) = marks
        .next()
        .filter(|first| matches!(first, '-' | '*' | '_'))
    else {
        return false;
    };
    let mut count: u32 = 1;
    for mark in marks {
        if mark != first {
            return false;
        }
        count = count.saturating_add(1);
    }
    count >= 3
}

/// `text` with the front matter `entity-id` set to `entity`, or removed when
/// `entity` is `None`. A source without front matter gains one when a binding
/// is added. Every other byte is kept.
pub(crate) fn patch_entity(text: &str, entity: Option<mneme_core::RecordId>) -> Vec<u8> {
    let lines = crate::asciidoc::lines(text);
    let Some(matter) = front_matter(&lines) else {
        return match entity {
            Some(entity) => {
                format!("---\nentity-id: {}\n---\n{text}", entity.to_hex()).into_bytes()
            }
            None => text.as_bytes().to_vec(),
        };
    };
    let existing = matter
        .entries
        .iter()
        .find(|entry| entry.key.eq_ignore_ascii_case("entity-id"));
    let (start, end, replacement) = match (existing, entity) {
        (Some(entry), Some(entity)) => (
            entry.start,
            entry.end,
            format!("entity-id: {}", entity.to_hex()),
        ),
        (Some(entry), None) => (
            entry.start,
            line_end_with_break(text, entry.end),
            String::new(),
        ),
        (None, Some(entity)) => (
            matter.close_start,
            matter.close_start,
            format!("entity-id: {}\n", entity.to_hex()),
        ),
        (None, None) => return text.as_bytes().to_vec(),
    };
    let mut patched = String::with_capacity(text.len().saturating_add(replacement.len()));
    patched.push_str(&text[..start]);
    patched.push_str(&replacement);
    patched.push_str(&text[end..]);
    patched.into_bytes()
}

/// The byte after the line break that ends a line ending at `end`.
fn line_end_with_break(text: &str, end: usize) -> usize {
    let rest = &text[end..];
    if rest.starts_with("\r\n") {
        end.saturating_add(2)
    } else if rest.starts_with('\n') {
        end.saturating_add(1)
    } else {
        end
    }
}

/// A restricted HTML rendering of a Markdown note.
pub(crate) struct Rendered {
    pub(crate) html: String,
    /// Set when the output bound stopped rendering before the end.
    pub(crate) is_truncated: bool,
}

/// The kind of block being collected while rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Paragraph,
    Quote,
    Table,
    List { is_ordered: bool },
    Code { language: String },
}

/// One block being collected: its kind and its lines.
struct Block {
    kind: Kind,
    lines: Vec<String>,
}

/// Render `text` as escaped HTML, stopping once the output passes `max_bytes`.
///
/// Raw HTML is escaped, never emitted; links keep only `http`, `https` and
/// `mailto` targets or scheme-less relative paths; images are not fetched.
pub(crate) fn render(text: &str, max_bytes: usize) -> Rendered {
    let lines = crate::asciidoc::lines(text);
    let mut html = String::with_capacity(text.len().min(max_bytes).saturating_add(64));
    let mut open: Option<Block> = None;
    let mut fence_marker: Option<&'static str> = None;
    for (_, line) in body_lines(&lines) {
        if html.len() > max_bytes {
            return Rendered {
                html,
                is_truncated: true,
            };
        }
        let Some(marker) = fence_marker else {
            open = render_line(&mut html, open, line.text, &mut fence_marker);
            continue;
        };
        if fence(line.text) == Some(marker) {
            fence_marker = None;
            flush_block(&mut html, open.take());
        } else if let Some(block) = open.as_mut() {
            block.lines.push(line.text.to_owned());
        }
    }
    flush_block(&mut html, open);
    Rendered {
        is_truncated: html.len() > max_bytes,
        html,
    }
}

/// Feed one line outside fenced code to the open block.
fn render_line(
    html: &mut String,
    open: Option<Block>,
    raw: &str,
    fence_marker: &mut Option<&'static str>,
) -> Option<Block> {
    let content = raw.trim();
    if let Some(marker) = fence(raw) {
        flush_block(html, open);
        *fence_marker = Some(marker);
        let language = content.trim_start_matches(marker).trim();
        return Some(Block {
            kind: Kind::Code {
                language: language.chars().take(32).collect(),
            },
            lines: Vec::new(),
        });
    }
    if content.is_empty() {
        flush_block(html, open);
        return None;
    }
    if let Some((level, title)) = heading(content) {
        flush_block(html, open);
        html.push_str(&format!("<h{level}>{}</h{level}>", inline(title)));
        return None;
    }
    if is_rule(content) {
        flush_block(html, open);
        html.push_str("<hr>");
        return None;
    }
    let (kind, line) = classify(content);
    let mut open = open;
    if let Some(block) = open.as_mut().filter(|block| block.kind == kind) {
        block.lines.push(line.to_owned());
        return open;
    }
    flush_block(html, open);
    Some(Block {
        kind,
        lines: vec![line.to_owned()],
    })
}

/// The block kind and text of a quote, table, list or paragraph line.
fn classify(content: &str) -> (Kind, &str) {
    if let Some(quoted) = content.strip_prefix('>') {
        return (Kind::Quote, quoted.trim());
    }
    if content.starts_with('|') {
        return (Kind::Table, content);
    }
    match list_item(content) {
        Some((is_ordered, item)) => (Kind::List { is_ordered }, item),
        None => (Kind::Paragraph, content),
    }
}

/// A list item's marker kind and text: `-`, `*`, `+` or digits and `.` or `)`.
fn list_item(content: &str) -> Option<(bool, &str)> {
    for marker in ["- ", "* ", "+ "] {
        if let Some(item) = content.strip_prefix(marker) {
            return Some((false, item));
        }
    }
    let digits = content.bytes().take_while(u8::is_ascii_digit).count();
    let rest = content.get(digits..)?;
    let item = rest
        .strip_prefix(". ")
        .or_else(|| rest.strip_prefix(") "))?;
    (digits > 0).then_some((true, item))
}

/// Write a finished block.
fn flush_block(html: &mut String, open: Option<Block>) {
    let Some(block) = open else {
        return;
    };
    match block.kind {
        Kind::Paragraph => {
            html.push_str("<p>");
            html.push_str(&inline(&block.lines.join(" ")));
            html.push_str("</p>");
        }
        Kind::Quote => {
            html.push_str("<blockquote><p>");
            html.push_str(&inline(&block.lines.join(" ")));
            html.push_str("</p></blockquote>");
        }
        Kind::List { is_ordered } => {
            let (open_tag, close_tag) = if is_ordered {
                ("<ol>", "</ol>")
            } else {
                ("<ul>", "</ul>")
            };
            html.push_str(open_tag);
            for item in &block.lines {
                list_item_html(html, item);
            }
            html.push_str(close_tag);
        }
        Kind::Table => table_html(html, &block.lines),
        Kind::Code { language } => {
            html.push_str("<pre><code");
            if !language.is_empty() {
                html.push_str(" class=\"language-");
                escape_into(html, &language);
                html.push('"');
            }
            html.push('>');
            escape_into(html, &block.lines.join("\n"));
            html.push_str("</code></pre>");
        }
    }
}

/// One list item, with a disabled checkbox for a checklist item.
fn list_item_html(html: &mut String, item: &str) {
    let task = [("[ ] ", false), ("[x] ", true), ("[X] ", true)]
        .into_iter()
        .find_map(|(marker, is_done)| item.strip_prefix(marker).map(|rest| (is_done, rest)));
    match task {
        Some((is_done, rest)) => {
            html.push_str(if is_done {
                "<li class=\"task\"><input type=\"checkbox\" disabled checked> "
            } else {
                "<li class=\"task\"><input type=\"checkbox\" disabled> "
            });
            html.push_str(&inline(rest));
        }
        None => {
            html.push_str("<li>");
            html.push_str(&inline(item));
        }
    }
    html.push_str("</li>");
}

/// The trimmed cells of one pipe table row.
fn row_cells(row: &str) -> impl Iterator<Item = &str> {
    let inner = row.trim();
    let inner = inner.strip_prefix('|').unwrap_or(inner);
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    inner.split('|').map(str::trim)
}

/// Whether a row only separates the header row: dashes, colons and spaces.
fn is_separator_row(row: &str) -> bool {
    row_cells(row).all(|cell| {
        !cell.is_empty()
            && cell
                .chars()
                .all(|character| matches!(character, '-' | ':' | ' '))
    })
}

/// A pipe table: a separator row after the first row makes it a header.
fn table_html(html: &mut String, rows: &[String]) {
    html.push_str("<table>");
    let mut body = rows.iter();
    if let Some(header) = rows.first()
        && rows.get(1).is_some_and(|row| is_separator_row(row))
    {
        html.push_str("<thead><tr>");
        cells_html(html, header, ("<th>", "</th>"));
        html.push_str("</tr></thead>");
        body = rows.get(2..).unwrap_or_default().iter();
    }
    html.push_str("<tbody>");
    for row in body {
        html.push_str("<tr>");
        cells_html(html, row, ("<td>", "</td>"));
        html.push_str("</tr>");
    }
    html.push_str("</tbody></table>");
}

/// The cells of one row, each wrapped in the opening and closing tag.
fn cells_html(html: &mut String, row: &str, tags: (&'static str, &'static str)) {
    for cell in row_cells(row) {
        html.push_str(tags.0);
        html.push_str(&inline(cell));
        html.push_str(tags.1);
    }
}

/// Append `text` escaped for HTML element content and attribute values.
fn escape_into(html: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => html.push_str("&amp;"),
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            '"' => html.push_str("&quot;"),
            '\'' => html.push_str("&#39;"),
            other => html.push(other),
        }
    }
}

/// Whether a link target is safe to emit: `http`, `https`, `mailto`, or a
/// relative path without a scheme.
fn is_safe_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    let has_scheme = lower
        .split_once(':')
        .is_some_and(|(scheme, _)| !scheme.contains(['/', '?', '#']));
    !has_scheme
        || lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("mailto:")
}

/// Inline markup: code, wiki links, links, images as text, strong and emphasis.
///
/// Each delimiter search runs forward from the current position, and a marker
/// with no closer is remembered, so a line of unmatched markers stays linear.
/// An underscore inside a word is text, as in `snake_case`.
fn inline(text: &str) -> String {
    let mut html = String::with_capacity(text.len().saturating_add(16));
    let mut unclosed = std::collections::BTreeSet::new();
    let mut resume_at = 0;
    for (index, character) in text.char_indices() {
        if index < resume_at {
            continue;
        }
        let rest = &text[index..];
        let is_intraword = rest.starts_with('_')
            && text[..index]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric);
        if !is_intraword && let Some(consumed) = inline_at(&mut html, rest, &mut unclosed) {
            resume_at = index.saturating_add(consumed);
            continue;
        }
        escape_into(&mut html, &rest[..character.len_utf8()]);
    }
    html
}

/// Render the construct at the start of `rest` and return the bytes it
/// consumed, or `None` when `rest` starts with plain text.
fn inline_at(
    html: &mut String,
    rest: &str,
    unclosed: &mut std::collections::BTreeSet<&'static str>,
) -> Option<usize> {
    if let Some(inner) = rest.strip_prefix("[[") {
        let close = closer(inner, "]]", unclosed)?;
        let raw = &inner[..close];
        let (target, label) = raw.split_once('|').unwrap_or((raw, raw));
        html.push_str("<span class=\"wiki-link\" data-target=\"");
        escape_into(html, target.trim());
        html.push_str("\">");
        escape_into(html, label.trim());
        html.push_str("</span>");
        return Some(close.saturating_add(4));
    }
    if let Some(inner) = rest.strip_prefix('`') {
        let close = closer(inner, "`", unclosed)?;
        html.push_str("<code>");
        escape_into(html, &inner[..close]);
        html.push_str("</code>");
        return Some(close.saturating_add(2));
    }
    if rest.starts_with('[') || rest.starts_with("![") {
        return link_at(html, rest, unclosed);
    }
    emphasis_at(html, rest, unclosed)
}

/// A `[label](target)` link or an `![alt](source)` image, shown as text.
fn link_at(
    html: &mut String,
    rest: &str,
    unclosed: &mut std::collections::BTreeSet<&'static str>,
) -> Option<usize> {
    let is_image = rest.starts_with("![");
    let label_start = if is_image { 2 } else { 1 };
    let after = &rest[label_start..];
    let label_end = closer(after, "](", unclosed)?;
    let target_part = &after[label_end.saturating_add(2)..];
    let target_end = closer(target_part, ")", unclosed)?;
    let label = &after[..label_end];
    let target = target_part[..target_end].trim();
    if is_image {
        html.push_str("[image: ");
        escape_into(html, label);
        html.push(']');
    } else if is_safe_target(target) {
        html.push_str("<a href=\"");
        escape_into(html, target);
        html.push_str("\">");
        escape_into(html, label);
        html.push_str("</a>");
    } else {
        escape_into(html, label);
    }
    Some(
        label_start
            .saturating_add(label_end)
            .saturating_add(target_end)
            .saturating_add(3),
    )
}

/// Strong or emphasised text at the start of `rest`.
fn emphasis_at(
    html: &mut String,
    rest: &str,
    unclosed: &mut std::collections::BTreeSet<&'static str>,
) -> Option<usize> {
    let (marker, tag) = [("**", "strong"), ("__", "strong"), ("*", "em"), ("_", "em")]
        .into_iter()
        .find(|(marker, _)| rest.starts_with(marker))?;
    let inner = &rest[marker.len()..];
    if inner.starts_with(' ') {
        return None;
    }
    let close = closer(inner, marker, unclosed)?;
    if close == 0 {
        return None;
    }
    html.push('<');
    html.push_str(tag);
    html.push('>');
    escape_into(html, &inner[..close]);
    html.push_str("</");
    html.push_str(tag);
    html.push('>');
    Some(close.saturating_add(marker.len().saturating_mul(2)))
}

/// The offset of `needle` in `inner`, remembering when there is none so later
/// positions, which only see less text, do not search again.
fn closer(
    inner: &str,
    needle: &'static str,
    unclosed: &mut std::collections::BTreeSet<&'static str>,
) -> Option<usize> {
    if unclosed.contains(needle) {
        return None;
    }
    let found = inner.find(needle);
    if found.is_none() {
        unclosed.insert(needle);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTITY: &str = "0102030405060708090a0b0c0d0e0f10";

    #[test]
    fn note_paths_are_recognized_by_extension() {
        assert!(is_note_path("notes/plan.md"));
        assert!(is_note_path("notes/Plan.MARKDOWN"));
        assert!(!is_note_path("notes/plan.adoc"));
        assert!(!is_note_path("notes/md"));
    }

    #[test]
    fn front_matter_supplies_title_and_binding_before_the_first_heading() {
        let source =
            format!("---\ntitle: \"Plan B\"\nentity-id: {ENTITY}\ntags: [a]\n---\n# Heading\n");
        let header = parse_header(&source).expect("header");
        assert_eq!(header.title.as_deref(), Some("Plan B"));
        assert_eq!(
            header.entity_id.map(|id| id.to_hex()),
            Some(ENTITY.to_owned())
        );
        let span = header.span.expect("front matter span");
        assert_eq!(span.start(), 0);
        let fallback =
            parse_header("intro\n```\n# not a title\n```\n# Real Title #\n").expect("header");
        assert_eq!(fallback.title.as_deref(), Some("Real Title"));
        assert_eq!(parse_header("no title").expect("header").title, None);
    }

    #[test]
    fn invalid_and_repeated_bindings_are_refused() {
        let invalid = parse_header("---\nentity-id: nope\n---\n").expect_err("invalid");
        assert_eq!(invalid[0].code, "binding-invalid");
        let repeated = format!("---\nentity-id: {ENTITY}\nentity-id: {ENTITY}\n---\n");
        assert_eq!(
            parse_header(&repeated).expect_err("repeated")[0].code,
            "binding-conflict"
        );
        let unclosed = format!("---\nentity-id: {ENTITY}\n");
        assert_eq!(parse_header(&unclosed).expect("header").entity_id, None);
    }

    #[test]
    fn paragraphs_skip_front_matter_code_headings_tables_and_rules() {
        let source = "---\ntitle: T\n---\n# T\nfirst line\nsecond line\n\n```\ncode\n```\n| a |\n***\nlast\n";
        let spans: Vec<&str> = scan_paragraphs(source)
            .iter()
            .map(|paragraph| {
                let start = usize::try_from(paragraph.span.start()).expect("start");
                let end = usize::try_from(paragraph.span.end()).expect("end");
                &source[start..=end]
            })
            .collect();
        assert_eq!(spans, vec!["first line\nsecond line", "last"]);
    }

    #[test]
    fn the_binding_patch_inserts_replaces_and_removes_only_its_line() {
        let entity = mneme_core::RecordId::from_hex(ENTITY).expect("entity");
        let bare = "# Note\nbody\n";
        let added = String::from_utf8(patch_entity(bare, Some(entity))).expect("utf8");
        assert_eq!(
            added,
            format!("---\nentity-id: {ENTITY}\n---\n# Note\nbody\n")
        );
        assert_eq!(
            parse_header(&added).expect("header").entity_id,
            Some(entity)
        );
        let with_matter = "---\ntitle: T\n---\nbody\n";
        let inserted = String::from_utf8(patch_entity(with_matter, Some(entity))).expect("utf8");
        assert_eq!(
            inserted,
            format!("---\ntitle: T\nentity-id: {ENTITY}\n---\nbody\n")
        );
        let removed = String::from_utf8(patch_entity(&inserted, None)).expect("utf8");
        assert_eq!(removed, with_matter);
        assert_eq!(patch_entity(bare, None), bare.as_bytes());
    }

    #[test]
    fn the_preview_renders_blocks_and_escapes_everything_else() {
        let source = "---\ntitle: T\n---\n# Title\n\nSee **bold** and *em* `a<b` [[Other|other note]] [site](https://example.com) [bad](javascript:alert(1)) <script>x</script>\n\nKeep snake_case_name and _this_ and ![diagram](d.png).\n\n- [ ] open\n- [x] done\n\n1. one\n\n> quoted\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n```rust\nlet x = \"<y>\";\n```\n";
        let rendered = render(source, 1 << 20);
        assert!(!rendered.is_truncated);
        let html = rendered.html;
        assert!(html.starts_with("<h1>Title</h1>"), "{html}");
        assert!(
            html.contains("<p>Keep snake_case_name and <em>this</em> and [image: diagram].</p>"),
            "{html}"
        );
        assert!(html.contains("<strong>bold</strong> and <em>em</em> <code>a&lt;b</code>"));
        assert!(html.contains("data-target=\"Other\">other note</span>"));
        assert!(html.contains("<a href=\"https://example.com\">site</a>"));
        assert!(!html.contains("javascript:"), "{html}");
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("<input type=\"checkbox\" disabled> open"));
        assert!(html.contains("<input type=\"checkbox\" disabled checked> done"));
        assert!(html.contains("<ol><li>one</li></ol>"));
        assert!(html.contains("<blockquote><p>quoted</p></blockquote>"));
        assert!(html.contains("<thead><tr><th>A</th><th>B</th></tr></thead><tbody><tr><td>1</td><td>2</td></tr></tbody>"));
        assert!(html.contains(
            "<pre><code class=\"language-rust\">let x = &quot;&lt;y&gt;&quot;;</code></pre>"
        ));
        assert!(!html.contains("title: T"), "front matter is not rendered");
    }

    #[test]
    fn unmatched_markers_render_literally_and_output_is_bounded() {
        let markers = format!(
            "x{}{}{}",
            "*".repeat(5_000),
            "[".repeat(5_000),
            "_".repeat(5_000)
        );
        let rendered = render(&markers, 1 << 20);
        assert_eq!(rendered.html, format!("<p>{markers}</p>"));
        let long = "word ".repeat(10_000);
        let source = format!("{long}\n\n{long}\n\n{long}\n");
        let bounded = render(&source, 1_000);
        assert!(bounded.is_truncated);
    }
}
