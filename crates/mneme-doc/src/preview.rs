//! Restricted preview rendering and explicit include occurrence mapping.

#![allow(unknown_lints, ignored_result)] // fmt::Write to String and test cleanup cannot fail recoverably

use std::fmt::Write;

#[derive(Clone, Debug)]
pub(crate) struct RenderSource {
    pub path: String,
    pub pin: crate::SourcePin,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct RenderOutput {
    pub html: String,
    pub diagnostics: Vec<crate::asciidoc::Diagnostic>,
    pub occurrences: Vec<crate::IncludeOccurrence>,
}

struct Renderer<'a> {
    sources: &'a std::collections::BTreeMap<String, RenderSource>,
    config: &'a crate::RenderConfig,
    deadline: Option<std::time::Instant>,
    html: String,
    diagnostics: Vec<crate::asciidoc::Diagnostic>,
    occurrences: Vec<crate::IncludeOccurrence>,
    expanded_bytes: usize,
    stack: std::collections::BTreeSet<String>,
}

pub(crate) fn render(
    root: &RenderSource,
    sources: &std::collections::BTreeMap<String, RenderSource>,
    metadata: Option<&mneme_core::RecordEnvelope>,
    config: &crate::RenderConfig,
    deadline: Option<std::time::Instant>,
) -> RenderOutput {
    let mut renderer = Renderer {
        sources,
        config,
        deadline,
        html: String::new(),
        diagnostics: Vec::new(),
        occurrences: Vec::new(),
        expanded_bytes: 0,
        stack: std::collections::BTreeSet::new(),
    };
    if config.version != crate::RENDER_CONFIG_VERSION {
        renderer
            .diagnostics
            .push(crate::asciidoc::Diagnostic::warning(
                "unsupported-render-config",
                format!(
                    "render configuration {} is not supported; using {}",
                    config.version,
                    crate::RENDER_CONFIG_VERSION
                ),
                1,
                1,
                None,
            ));
    }
    if config.include_entity_metadata
        && let Some(entity) = metadata
    {
        renderer.render_metadata(entity);
    }
    renderer.render_source(root, 0);
    RenderOutput {
        html: renderer.html,
        diagnostics: renderer.diagnostics,
        occurrences: renderer.occurrences,
    }
}

impl Renderer<'_> {
    fn render_metadata(&mut self, entity: &mneme_core::RecordEnvelope) {
        let entity_type = entity
            .payload
            .get("entity-type")
            .and_then(mneme_core::Value::as_symbol)
            .map_or("entity", |symbol| symbol.as_str());
        let label = entity
            .payload
            .get("label")
            .and_then(mneme_core::Value::as_string)
            .unwrap_or("(unlabelled)");
        let mut properties = String::new();
        if let Some(dictionary) = entity
            .payload
            .get("properties")
            .and_then(mneme_core::Value::as_dictionary)
        {
            for (key, value) in dictionary {
                let key = key
                    .as_symbol()
                    .map(|symbol| symbol.as_str())
                    .or_else(|| key.as_string())
                    .unwrap_or("property");
                let value = display_value(value);
                let _ = write!(
                    properties,
                    "<dt>{}</dt><dd>{}</dd>",
                    escape_html(key),
                    escape_html(&value)
                );
            }
        }
        let _ = write!(
            self.html,
            "<section class=\"mneme-metadata\" data-projection=\"entity-metadata\" data-entity=\"{}\">\
             <h2>Entity metadata <span class=\"projection-label\">(projection)</span></h2>\
             <p><strong>{}</strong> {}</p><dl>{}</dl></section>",
            entity.record_id.to_hex(),
            escape_html(entity_type),
            escape_html(label),
            properties
        );
    }

    fn render_source(&mut self, source: &RenderSource, depth: usize) {
        if self.expired() {
            return;
        }
        if !self.stack.insert(source.path.clone()) {
            self.diagnostics.push(crate::asciidoc::Diagnostic::new(
                "include-cycle",
                format!("include cycle at {}", source.path),
                1,
                1,
                None,
            ));
            return;
        }
        let text = match std::str::from_utf8(&source.bytes) {
            Ok(text) => text,
            Err(error) => {
                self.diagnostics.push(crate::asciidoc::Diagnostic::new(
                    "invalid-utf8",
                    "included source is not valid UTF-8",
                    1,
                    error.valid_up_to(),
                    None,
                ));
                self.stack.remove(&source.path);
                return;
            }
        };
        let includes = crate::asciidoc::scan_includes(text)
            .into_iter()
            .map(|directive| (line_start(text, directive.line), directive))
            .collect::<std::collections::BTreeMap<_, _>>();
        let anchors = crate::asciidoc::scan_anchors(text)
            .into_iter()
            .map(|anchor| (line_start(text, anchor.line), anchor))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut pending_anchor: Option<String> = None;
        let mut paragraph: Vec<&str> = Vec::new();
        let mut skip_until = 0_usize;
        let mut mode = Block::Normal;
        let mut mode_start = 1_usize;
        let mut mode_buffer = String::new();
        let mut line_number = 0_usize;
        for line in text.split_inclusive('\n') {
            line_number += 1;
            if line_number <= skip_until {
                continue;
            }
            if self.expired() {
                break;
            }
            if self.html.len() > self.config.max_output_bytes {
                self.diagnostics.push(crate::asciidoc::Diagnostic::warning(
                    "output-size-limit",
                    "preview stopped at the configured output limit",
                    line_number,
                    1,
                    None,
                ));
                break;
            }
            let start = line_start(text, line_number);
            let content = line
                .strip_suffix('\n')
                .unwrap_or(line)
                .strip_suffix('\r')
                .unwrap_or_else(|| line.strip_suffix('\n').unwrap_or(line));
            match mode {
                Block::Listing | Block::Passthrough | Block::Comment | Block::Table => {
                    let trimmed = content.trim();
                    let is_closes = match mode {
                        Block::Listing => trimmed == "----" || trimmed == "....",
                        Block::Passthrough => trimmed == "++++",
                        Block::Comment => trimmed == "////",
                        Block::Table => trimmed == "|===",
                        Block::Normal => false,
                    };
                    if is_closes {
                        match mode {
                            Block::Listing => {
                                let _ = write!(
                                    self.html,
                                    "<pre class=\"listing\">{}</pre>",
                                    escape_html(&mode_buffer)
                                );
                            }
                            Block::Passthrough => {
                                self.diagnostics.push(crate::asciidoc::Diagnostic::warning(
                                    "raw-passthrough-escaped",
                                    "raw passthrough content was escaped, not executed",
                                    mode_start,
                                    1,
                                    None,
                                ));
                                let _ = write!(
                                    self.html,
                                    "<pre class=\"unsafe-passthrough\">{}</pre>",
                                    escape_html(&mode_buffer)
                                );
                            }
                            Block::Table => {
                                self.diagnostics.push(crate::asciidoc::Diagnostic::warning(
                                    "unsupported-table",
                                    "table content is escaped in the supported preview subset",
                                    mode_start,
                                    1,
                                    None,
                                ));
                                let _ = write!(
                                    self.html,
                                    "<pre class=\"unsupported-table\">{}</pre>",
                                    escape_html(&mode_buffer)
                                );
                            }
                            Block::Comment => {}
                            Block::Normal => {}
                        }
                        mode = Block::Normal;
                        mode_buffer.clear();
                    } else if mode != Block::Comment {
                        mode_buffer.push_str(content);
                        mode_buffer.push('\n');
                    }
                    continue;
                }
                Block::Normal => {}
            }
            if let Some(anchor) = anchors.get(&start) {
                pending_anchor = Some(anchor.anchor.clone());
                continue;
            }
            if let Some(directive) = includes.get(&start) {
                self.flush_paragraph(&mut paragraph, &mut pending_anchor);
                if let Some(anchor) = pending_anchor.take() {
                    let _ = write!(self.html, "<span id=\"{}\"></span>", escape_html(&anchor));
                }
                self.render_include(source, directive, depth);
                continue;
            }
            let trimmed = content.trim();
            if trimmed.is_empty() {
                self.flush_paragraph(&mut paragraph, &mut pending_anchor);
                continue;
            }
            if trimmed == "----" || trimmed == "...." {
                self.flush_paragraph(&mut paragraph, &mut pending_anchor);
                mode = Block::Listing;
                mode_start = line_number;
                continue;
            }
            if trimmed == "++++" {
                self.flush_paragraph(&mut paragraph, &mut pending_anchor);
                mode = Block::Passthrough;
                mode_start = line_number;
                continue;
            }
            if trimmed == "////" {
                self.flush_paragraph(&mut paragraph, &mut pending_anchor);
                mode = Block::Comment;
                continue;
            }
            if trimmed == "|===" {
                self.flush_paragraph(&mut paragraph, &mut pending_anchor);
                mode = Block::Table;
                mode_start = line_number;
                continue;
            }
            if trimmed.starts_with("ifdef::")
                || trimmed.starts_with("ifndef::")
                || trimmed.starts_with("ifeval::")
            {
                self.flush_paragraph(&mut paragraph, &mut pending_anchor);
                self.diagnostics.push(crate::asciidoc::Diagnostic::warning(
                    "unsupported-conditional",
                    "conditional directive was not evaluated",
                    line_number,
                    1,
                    mneme_core::SourceSpan::new(
                        start as u64,
                        (start + content.len().max(1) - 1) as u64,
                    )
                    .ok(),
                ));
                let _ = write!(
                    self.html,
                    "<pre class=\"unsupported-conditional\">{}</pre>",
                    escape_html(content)
                );
                continue;
            }
            if let Some((level, heading)) = heading(content) {
                self.flush_paragraph(&mut paragraph, &mut pending_anchor);
                let id = pending_anchor.take();
                let id_attribute = id
                    .as_deref()
                    .filter(|anchor| crate::asciidoc::valid_anchor(anchor))
                    .map(|anchor| format!(" id=\"{}\"", escape_html(anchor)))
                    .unwrap_or_default();
                let level = level.min(6);
                let _ = write!(
                    self.html,
                    "<h{level}{id_attribute}>{}</h{level}>",
                    escape_html(heading)
                );
                continue;
            }
            if content.starts_with(' ') || content.starts_with('\t') {
                self.flush_paragraph(&mut paragraph, &mut pending_anchor);
                let _ = write!(
                    self.html,
                    "<pre class=\"literal\">{}</pre>",
                    escape_html(content)
                );
                continue;
            }
            if is_list_item(content, '*') || is_list_item(content, '.') {
                self.flush_paragraph(&mut paragraph, &mut pending_anchor);
                let is_ordered = is_list_item(content, '.');
                let mut items = Vec::new();
                let mut current_line = line_number;
                let mut current_content = content.to_owned();
                for next in text.split_inclusive('\n').skip(line_number) {
                    let next_number = current_line + 1;
                    let next_content = next
                        .strip_suffix('\n')
                        .unwrap_or(next)
                        .strip_suffix('\r')
                        .unwrap_or_else(|| next.strip_suffix('\n').unwrap_or(next));
                    if is_list_item(next_content, '*') || is_list_item(next_content, '.') {
                        if is_list_item(next_content, '.') != is_ordered {
                            break;
                        }
                        items.push(current_content);
                        current_content = next_content.to_owned();
                        current_line = next_number;
                    } else {
                        break;
                    }
                }
                items.push(current_content);
                skip_until = line_number + items.len().saturating_sub(1);
                let tag = if is_ordered { "ol" } else { "ul" };
                let _ = write!(self.html, "<{tag}>");
                for item in items {
                    let text = item
                        .trim_start()
                        .strip_prefix(if is_ordered { "." } else { "*" })
                        .unwrap_or(&item)
                        .trim();
                    let (rendered, diagnostics) = inline(text, line_number, &self.config.version);
                    self.diagnostics.extend(diagnostics);
                    let _ = write!(self.html, "<li>{rendered}</li>");
                }
                let _ = write!(self.html, "</{tag}>");
                continue;
            }
            paragraph.push(content);
        }
        self.flush_paragraph(&mut paragraph, &mut pending_anchor);
        self.stack.remove(&source.path);
        self.expanded_bytes += source.bytes.len();
        if self.expanded_bytes > self.config.max_output_bytes {
            self.diagnostics.push(crate::asciidoc::Diagnostic::warning(
                "expanded-size-limit",
                "preview expansion exceeded the configured output limit",
                line_number,
                1,
                None,
            ));
        }
        let _ = depth;
    }

    fn render_include(
        &mut self,
        source: &RenderSource,
        directive: &crate::asciidoc::IncludeDirective,
        depth: usize,
    ) {
        let path = match crate::asciidoc::normalize_include_path(&source.path, &directive.target) {
            Ok(path) => path,
            Err(diagnostic) => {
                self.diagnostics.push(diagnostic);
                return;
            }
        };
        let Some(target) = self.sources.get(&path) else {
            self.diagnostics.push(crate::asciidoc::Diagnostic::warning(
                if directive.optional {
                    "include-optional-missing"
                } else {
                    "include-unavailable"
                },
                format!("include target {path:?} is unavailable"),
                directive.line,
                directive.column,
                Some(directive.span),
            ));
            let _ = write!(
                self.html,
                "<pre class=\"include-unavailable\">include unavailable: {}</pre>",
                escape_html(&path)
            );
            return;
        };
        self.occurrences.push(crate::IncludeOccurrence {
            including_path: source.path.clone(),
            target_path: path.clone(),
            directive_span: directive.span,
            source: target.pin,
        });
        self.render_source(target, depth + 1);
    }

    fn flush_paragraph(&mut self, paragraph: &mut Vec<&str>, pending_anchor: &mut Option<String>) {
        if paragraph.is_empty() {
            return;
        }
        let text = paragraph.join("\n");
        paragraph.clear();
        let (rendered, diagnostics) = inline(&text, 0, &self.config.version);
        self.diagnostics.extend(diagnostics);
        let id = pending_anchor.take();
        if let Some(anchor) = id {
            let _ = write!(
                self.html,
                "<span id=\"{}\"></span><p>{rendered}</p>",
                escape_html(&anchor)
            );
        } else {
            let _ = write!(self.html, "<p>{rendered}</p>");
        }
    }

    #[allow(unknown_lints, ambient_clock)] // render deadline is the preview shell
    fn expired(&mut self) -> bool {
        let Some(deadline) = self.deadline else {
            return false;
        };
        if std::time::Instant::now() > deadline {
            self.diagnostics.push(crate::asciidoc::Diagnostic::warning(
                "render-time-limit",
                "preview stopped at the configured time limit",
                1,
                1,
                None,
            ));
            self.deadline = None;
            return true;
        }
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Block {
    Normal,
    Listing,
    Passthrough,
    Comment,
    Table,
}

fn line_start(text: &str, line_number: usize) -> usize {
    if line_number <= 1 {
        return 0;
    }
    let mut start = 0;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        if index + 1 == line_number {
            return start;
        }
        start += line.len();
    }
    text.len()
}

fn heading(line: &str) -> Option<(usize, &str)> {
    let trimmed = line.trim_start();
    let level = trimmed
        .chars()
        .take_while(|character| *character == '=')
        .count();
    if level == 0 || level > 6 {
        return None;
    }
    let rest = &trimmed[level..];
    if !rest.starts_with(' ') {
        return None;
    }
    Some((level, rest.trim()))
}

fn is_list_item(line: &str, marker: char) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with(marker)
        && trimmed[marker.len_utf8()..].starts_with(' ')
        && !trimmed.starts_with("**")
}

fn inline(
    text: &str,
    line: usize,
    config_version: &str,
) -> (String, Vec<crate::asciidoc::Diagnostic>) {
    let mut diagnostics = Vec::new();
    if config_version != crate::RENDER_CONFIG_VERSION {
        diagnostics.push(crate::asciidoc::Diagnostic::warning(
            "unsupported-inline-config",
            "inline rendering used the supported configuration",
            line,
            1,
            None,
        ));
    }
    let mut output = String::new();
    let mut index = 0;
    while index < text.len() {
        let rest = &text[index..];
        if rest.starts_with("pass:[") {
            let end = rest.find(']').map(|end| index + end + 1);
            let literal = end.map(|end| &text[index..end]).unwrap_or(rest);
            diagnostics.push(crate::asciidoc::Diagnostic::warning(
                "passthrough-inline-escaped",
                "inline passthrough content was escaped",
                line,
                1,
                None,
            ));
            output.push_str(&escape_html(literal));
            index += literal.len();
            continue;
        }
        if rest.starts_with("image:") || rest.starts_with("link:") || rest.starts_with("xref:") {
            let kind = if rest.starts_with("image:") {
                "image"
            } else if rest.starts_with("link:") {
                "link"
            } else {
                "xref"
            };
            if let Some((end, target, label)) = parse_macro(rest) {
                match kind {
                    "image" => {
                        diagnostics.push(crate::asciidoc::Diagnostic::warning(
                            "external-asset-not-fetched",
                            "image target was not fetched or embedded",
                            line,
                            1,
                            None,
                        ));
                        let text = label.unwrap_or_else(|| {
                            target.rsplit('/').next().unwrap_or(target).to_owned()
                        });
                        let _ = write!(
                            output,
                            "<span class=\"image-alt\">{}</span>",
                            escape_html(&text)
                        );
                    }
                    "link" => render_link(&mut output, &mut diagnostics, target, label, line),
                    _ => render_xref(&mut output, &mut diagnostics, target, label, line),
                }
                index += end;
                continue;
            }
        }
        let Some(character) = rest.chars().next() else {
            break;
        };
        match character {
            '<' | '>' => {
                diagnostics.push(crate::asciidoc::Diagnostic::warning(
                    "raw-html-escaped",
                    "raw HTML was escaped",
                    line,
                    1,
                    None,
                ));
                output.push_str(&escape_html(&character.to_string()));
            }
            '&' => output.push_str("&amp;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            '{' => {
                diagnostics.push(crate::asciidoc::Diagnostic::warning(
                    "attribute-substitution-not-evaluated",
                    "attribute substitution was not evaluated",
                    line,
                    1,
                    None,
                ));
                output.push('{');
            }
            ':' => {
                let prefix = &text[..index];
                if prefix
                    .chars()
                    .last()
                    .is_some_and(|character| character.is_ascii_alphanumeric())
                    && rest[1..].contains('[')
                    && !rest.starts_with("::")
                {
                    diagnostics.push(crate::asciidoc::Diagnostic::warning(
                        "unsupported-macro",
                        "custom macro was not executed",
                        line,
                        1,
                        None,
                    ));
                }
                output.push(':');
            }
            other => output.push_str(&escape_html(&other.to_string())),
        }
        index += character.len_utf8();
    }
    (output, diagnostics)
}

fn render_xref(
    output: &mut String,
    diagnostics: &mut Vec<crate::asciidoc::Diagnostic>,
    target: &str,
    label: Option<String>,
    line: usize,
) {
    if crate::asciidoc::valid_anchor(target) {
        let label_text = label.as_deref().unwrap_or(target);
        let _ = write!(
            output,
            "<a href=\"#{}\">{}</a>",
            escape_html(target),
            escape_html(label_text)
        );
        return;
    }
    diagnostics.push(crate::asciidoc::Diagnostic::warning(
        "xref-unavailable",
        "cross-reference target is not a safe local anchor",
        line,
        1,
        None,
    ));
    output.push_str(&escape_html(target));
}

fn render_link(
    output: &mut String,
    diagnostics: &mut Vec<crate::asciidoc::Diagnostic>,
    target: &str,
    label: Option<String>,
    line: usize,
) {
    let label = label.unwrap_or_else(|| target.to_owned());
    if let Some(anchor) = target.strip_prefix('#')
        && crate::asciidoc::valid_anchor(anchor)
    {
        let _ = write!(
            output,
            "<a href=\"#{}\">{}</a>",
            escape_html(anchor),
            escape_html(&label)
        );
        return;
    }
    diagnostics.push(crate::asciidoc::Diagnostic::warning(
        "external-navigation-not-automatic",
        "external link target was not made navigable by the preview",
        line,
        1,
        None,
    ));
    let _ = write!(
        output,
        "<span class=\"external-link\">{}</span>",
        escape_html(&label)
    );
}

fn parse_macro(text: &str) -> Option<(usize, &str, Option<String>)> {
    let colon = text.find(':')?;
    let open = text[colon + 1..].find('[')? + colon + 1;
    let close = text[open + 1..].find(']')? + open + 1;
    let target = &text[colon + 1..open];
    let label = text[open + 1..close].trim();
    Some((
        close + 1,
        target,
        (!label.is_empty()).then(|| label.to_owned()),
    ))
}

fn escape_html(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            other => output.push(other),
        }
    }
    output
}

fn display_value(value: &mneme_core::Value) -> String {
    if let Some(text) = value.as_string() {
        return text.to_owned();
    }
    if let Some(symbol) = value.as_symbol() {
        return symbol.as_str().to_owned();
    }
    if let Some(integer) = value.as_integer().and_then(|integer| integer.to_i64()) {
        return integer.to_string();
    }
    if let Some(boolean) = value.as_boolean() {
        return boolean.to_string();
    }
    "<structured value>".to_owned()
}
