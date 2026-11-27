//! Deterministic extractor for fenced `[mneme]` declarative DSL sections inside
//! AsciiDoc documents.
//!
//! Recognizes `[mneme]`, `[mneme, ...]`, and `[source,mneme]` attribute lines
//! immediately followed by a listing (`----`) or literal (`....`) delimiter.
//! Sections nested inside AsciiDoc comment (`////`) or unrelated delimited
//! regions are skipped so prose examples never produce false extractions.

const MIN_DELIMITER_LEN: usize = 4;
const MAX_SECTIONS_PER_DOC: usize = 4_096;

/// One fenced `[mneme]` DSL section extracted from an AsciiDoc source document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DslSection {
    /// 1-based line number of the first content line inside the fence.
    pub start_line: u64,
    /// 1-based line number of the last content line (or opening fence if empty).
    pub end_line: u64,
    /// Exact byte span of the section body inside the AsciiDoc source.
    pub span: Option<mneme_core::SourceSpan>,
    /// Raw extracted DSL text inside the fences.
    pub content: String,
}

/// Whether a trimmed AsciiDoc attribute line introduces a `[mneme]` section.
pub fn is_dsl_attribute(trimmed: &str) -> bool {
    let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return false;
    };
    let mut parts = inner.split(',').map(str::trim);
    let Some(first) = parts.next() else {
        return false;
    };
    if first == "mneme" {
        return true;
    }
    first == "source" && parts.next() == Some("mneme")
}

fn parse_delimiter(trimmed: &str) -> Option<(char, usize)> {
    let first = trimmed.chars().next()?;
    if !matches!(first, '-' | '.' | '/' | '+') {
        return None;
    }
    let count = trimmed.chars().count();
    let is_uniform = count >= MIN_DELIMITER_LEN && trimmed.chars().all(|c| c == first);
    if is_uniform {
        Some((first, count))
    } else {
        None
    }
}

const fn is_dsl_delimiter_char(ch: char) -> bool {
    matches!(ch, '-' | '.')
}

/// Extract all fenced `[mneme]` sections from an AsciiDoc document.
///
/// Returns an error diagnostic if a `[mneme]` section is opened with a
/// delimiter that is never closed before EOF.
pub fn extract_dsl_sections(text: &str) -> Result<Vec<DslSection>, crate::asciidoc::Diagnostic> {
    let lines = crate::asciidoc::lines(text);
    let mut sections = Vec::new();
    let mut idx: usize = 0;
    let mut active_foreign: Option<(char, usize)> = None;

    while idx < lines.len() {
        let trimmed = lines[idx].text.trim();
        if let Some(foreign) = active_foreign {
            if parse_delimiter(trimmed) == Some(foreign) {
                active_foreign = None;
            }
            idx = idx.saturating_add(1);
            continue;
        }
        if is_dsl_attribute(trimmed) {
            let next_idx = idx.saturating_add(1);
            if next_idx < lines.len()
                && let Some(delim) = parse_delimiter(lines[next_idx].text.trim())
                && is_dsl_delimiter_char(delim.0)
            {
                let (section, after_close) = collect_section(&lines, next_idx, delim)?;
                if sections.len() < MAX_SECTIONS_PER_DOC {
                    sections.push(section);
                }
                idx = after_close;
                continue;
            }
        }
        if let Some(delim) = parse_delimiter(trimmed) {
            active_foreign = Some(delim);
        }
        idx = idx.saturating_add(1);
    }

    Ok(sections)
}

fn collect_section(
    lines: &[crate::asciidoc::Line<'_>],
    open_idx: usize,
    delim: (char, usize),
) -> Result<(DslSection, usize), crate::asciidoc::Diagnostic> {
    let body_start_idx = open_idx.saturating_add(1);
    let mut scan = body_start_idx;
    let mut close_idx: Option<usize> = None;
    while scan < lines.len() {
        if parse_delimiter(lines[scan].text.trim()) == Some(delim) {
            close_idx = Some(scan);
            break;
        }
        scan = scan.saturating_add(1);
    }
    let Some(close_at) = close_idx else {
        let open_line = &lines[open_idx];
        return Err(crate::asciidoc::Diagnostic::new(
            "unclosed-mneme-block",
            "unclosed [mneme] fenced block",
            open_line.number,
            1,
            open_line.span(),
        ));
    };

    let body_lines = &lines[body_start_idx..close_at];
    let mut content = String::new();
    for (pos, line) in body_lines.iter().enumerate() {
        if pos > 0 {
            content.push('\n');
        }
        content.push_str(line.text);
    }
    let start_line_num = body_lines
        .first()
        .map_or(lines[open_idx].number, |line| line.number);
    let end_line_num = body_lines
        .last()
        .map_or(lines[open_idx].number, |line| line.number);
    let span = match (body_lines.first(), body_lines.last()) {
        (Some(first), Some(last)) if last.end > first.start => {
            mneme_core::SourceSpan::new(first.start as u64, last.end.saturating_sub(1) as u64).ok()
        }
        _ => None,
    };

    let section = DslSection {
        start_line: start_line_num as u64,
        end_line: end_line_num as u64,
        span,
        content,
    };
    Ok((section, close_at.saturating_add(1)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn extracts_dsl_and_source_sections_skipping_comments() {
        let doc = concat!(
            "= Design Note\n\n",
            "////\n",
            "[mneme]\n",
            "----\n",
            "propose ignored owner nobody\n",
            "----\n",
            "////\n\n",
            "[mneme]\n",
            "----\n",
            "scope project:cedar\n",
            "declare functional owner\n",
            "----\n\n",
            "[source,mneme]\n",
            "....\n",
            "propose svc owner alice\n",
            "....\n",
        );
        let sections = super::extract_dsl_sections(doc).expect("sections");
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].start_line, 12);
        assert_eq!(sections[0].end_line, 13);
        assert!(sections[0].content.contains("declare functional owner"));
        assert_eq!(sections[1].start_line, 18);
        assert_eq!(sections[1].content, "propose svc owner alice");
    }

    #[test]
    fn unclosed_dsl_section_returns_fatal_diagnostic() {
        let doc = "[mneme]\n----\nscope project:cedar\n";
        let err = super::extract_dsl_sections(doc).expect_err("unclosed");
        assert_eq!(err.code, "unclosed-mneme-block");
        assert!(err.fatal);
    }
}
