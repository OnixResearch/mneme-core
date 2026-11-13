//! Restricted preview rendering and explicit include occurrence mapping.
// fmt::Write to String and test cleanup cannot fail recoverably

use std::fmt::Write;

#[derive(Clone, Debug)]
pub(crate) struct RenderSource {
    pub path: String,
    pub pin: crate::SourcePin,
    pub scope: mneme_core::ScopeId,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct RenderOutput {
    pub html: String,
    pub diagnostics: Vec<crate::asciidoc::Diagnostic>,
    pub occurrences: Vec<crate::IncludeOccurrence>,
    /// Whether a limit stopped the preview before the whole source was
    /// expanded, so the returned result is explicitly partial.
    pub truncated: bool,
}

/// Includes one preview may expand. Exponential include fan-out stops here
/// instead of multiplying work and memory by the fan-out at every level.
const MAX_RENDER_INCLUDES: u64 = 1_024;
/// Diagnostics one preview may collect before further ones are suppressed.
const MAX_RENDER_DIAGNOSTICS: usize = 1_024;
/// Include nesting a preview follows before it reports the depth limit.
const MAX_RENDER_DEPTH: usize = 64;
/// Bytes an inline scan consumes between deadline checks.
const INLINE_DEADLINE_STRIDE: u64 = 4_096;
/// Inline bytes one preview may scan, independent of the wall-clock deadline.
const MAX_INLINE_SCAN_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum unique images decoded while rendering one preview.
const MAX_RENDER_IMAGES: usize = 256;
/// Hard ceiling for cumulative HTML output, including embedded image data.
const MAX_IMAGE_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
/// Marker appended to a preview that a limit stopped before the end.
const PARTIAL_PREVIEW_MARKER: &str = "<!-- preview is partial: a limit stopped rendering -->";

#[derive(Clone)]
struct EncodedImage {
    media_type: &'static str,
    width: u32,
    height: u32,
    base64: String,
}

type ImageLoader<'a> = dyn FnMut(
        &mneme_core::ScopeId,
        crate::SourcePin,
    ) -> Option<(crate::images::Loaded, crate::images::Decoded)>
    + 'a;

pub(crate) struct Renderer<'a> {
    sources: &'a std::collections::BTreeMap<String, RenderSource>,
    config: &'a crate::RenderConfig,
    deadline: Option<std::time::Instant>,
    is_timed_out: bool,
    is_budget_exhausted: bool,
    is_refused: bool,
    is_diagnostic_limited: bool,
    html: String,
    diagnostics: Vec<crate::asciidoc::Diagnostic>,
    occurrences: Vec<crate::IncludeOccurrence>,
    expanded_bytes: u64,
    include_count: u64,
    inline_bytes: u64,
    stack: std::collections::BTreeSet<String>,
    image_loader: Option<&'a mut ImageLoader<'a>>,
    image_cache:
        std::collections::BTreeMap<(mneme_core::ScopeId, crate::SourcePin), Option<EncodedImage>>,
}

impl<'a> Renderer<'a> {
    pub(crate) fn render(
        mut self,
        root: &RenderSource,
        metadata: Option<&mneme_core::RecordEnvelope>,
    ) -> RenderOutput {
        self.run(root, metadata);
        let mut output = self.finish();
        if output.truncated {
            output.html.push_str(PARTIAL_PREVIEW_MARKER);
        }
        output
    }

    fn new(
        sources: &'a std::collections::BTreeMap<String, RenderSource>,
        config: &'a crate::RenderConfig,
        deadline: Option<std::time::Instant>,
    ) -> Self {
        Renderer {
            sources,
            config,
            deadline,
            is_timed_out: false,
            is_budget_exhausted: false,
            is_refused: false,
            is_diagnostic_limited: false,
            html: String::new(),
            diagnostics: Vec::new(),
            occurrences: Vec::new(),
            expanded_bytes: 0,
            include_count: 0,
            inline_bytes: 0,
            stack: std::collections::BTreeSet::new(),
            image_loader: None,
            image_cache: std::collections::BTreeMap::new(),
        }
    }

    pub(crate) fn new_with_images(
        sources: &'a std::collections::BTreeMap<String, RenderSource>,
        config: &'a crate::RenderConfig,
        deadline: Option<std::time::Instant>,
        image_loader: &'a mut ImageLoader<'a>,
    ) -> Self {
        let mut renderer = Self::new(sources, config, deadline);
        renderer.image_loader = Some(image_loader);
        renderer
    }

    fn run(&mut self, root: &RenderSource, metadata: Option<&mneme_core::RecordEnvelope>) {
        if !self.accepts_config() {
            return;
        }
        if self.expired() {
            return;
        }
        if self.config.include_entity_metadata
            && let Some(entity) = metadata
        {
            self.render_metadata(entity);
        }
        self.render_source(root, 0);
    }

    fn finish(self) -> RenderOutput {
        let is_truncated = self.is_stopped();
        RenderOutput {
            html: self.html,
            diagnostics: self.diagnostics,
            occurrences: self.occurrences,
            truncated: is_truncated,
        }
    }

    /// Whether a limit has stopped this preview for good.
    fn is_stopped(&self) -> bool {
        self.is_timed_out || self.is_budget_exhausted || self.is_refused
    }

    /// Refuse a configuration this build cannot honour.
    ///
    /// Falling back to another version while the artifact reported the
    /// requested one made the artifact describe a configuration it never used.
    fn accepts_config(&mut self) -> bool {
        if self.config.version == crate::RENDER_CONFIG_VERSION {
            return true;
        }
        let version = self.config.version.clone();
        self.is_refused = true;
        self.note(crate::asciidoc::Diagnostic::new(
            "unsupported-render-config",
            format!("render configuration {version} is not supported by this processor"),
            1,
            1,
            None,
        ));
        false
    }

    /// Record one diagnostic, bounded by the diagnostic budget.
    fn note(&mut self, diagnostic: crate::asciidoc::Diagnostic) {
        if self.diagnostics.len() < MAX_RENDER_DIAGNOSTICS {
            self.diagnostics.push(diagnostic);
            return;
        }
        if self.is_diagnostic_limited {
            return;
        }
        self.is_diagnostic_limited = true;
        let limited = crate::asciidoc::Diagnostic::warning(
            "diagnostic-limit",
            "further preview diagnostics were suppressed at the configured limit",
            1,
            1,
            None,
        );
        self.diagnostics.push(limited);
    }

    /// Charge one source's bytes before it is expanded.
    fn charge_expansion(&mut self, bytes: usize) -> bool {
        let cost = crate::budget_count(bytes);
        let limit = crate::budget_count(self.config.max_output_bytes);
        match mneme_kernel::budget::charge(self.expanded_bytes, cost, limit) {
            Some(used) => {
                self.expanded_bytes = used;
                true
            }
            None => {
                self.exhaust("preview stopped: expanded source bytes exceed the configured limit");
                false
            }
        }
    }

    /// Charge one include expansion before its target is rendered.
    fn charge_include(&mut self) -> bool {
        match mneme_kernel::budget::charge(self.include_count, 1, MAX_RENDER_INCLUDES) {
            Some(used) => {
                self.include_count = used;
                true
            }
            None => {
                self.exhaust("preview stopped: include expansion exceeds the configured limit");
                false
            }
        }
    }

    fn exhaust(&mut self, message: &'static str) {
        if self.is_budget_exhausted {
            return;
        }
        self.is_budget_exhausted = true;
        self.note(crate::asciidoc::Diagnostic::warning(
            "render-budget-exhausted",
            message,
            1,
            1,
            None,
        ));
    }

    #[allow(unknown_lints, ambient_clock)] // render deadline is the preview shell
    fn expired(&mut self) -> bool {
        if self.is_timed_out {
            return true;
        }
        let Some(deadline) = self.deadline else {
            return false;
        };
        if std::time::Instant::now() > deadline {
            self.is_timed_out = true;
            self.note(crate::asciidoc::Diagnostic::warning(
                "render-time-limit",
                "preview stopped at the configured time limit",
                1,
                1,
                None,
            ));
            return true;
        }
        false
    }

    #[allow(unknown_lints, ignored_result)] // lint boundary documented at the implementation
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
        if self.is_stopped() {
            return;
        }
        if depth > MAX_RENDER_DEPTH {
            self.note(crate::asciidoc::Diagnostic::warning(
                "include-depth-limit",
                "preview stopped at the configured include depth",
                1,
                1,
                None,
            ));
            return;
        }
        if !self.charge_expansion(source.bytes.len()) {
            return;
        }
        if !self.stack.insert(source.path.clone()) {
            self.note(crate::asciidoc::Diagnostic::new(
                "include-cycle",
                format!("include cycle at {}", source.path),
                1,
                1,
                None,
            ));
            return;
        }
        self.render_source_text(source, depth);
        self.stack.remove(&source.path);
    }

    fn render_source_text(&mut self, source: &RenderSource, depth: usize) {
        let text = match std::str::from_utf8(&source.bytes) {
            Ok(text) => text,
            Err(error) => {
                self.note(crate::asciidoc::Diagnostic::new(
                    "invalid-utf8",
                    "included source is not valid UTF-8",
                    1,
                    error.valid_up_to(),
                    None,
                ));
                return;
            }
        };
        self.render_source_lines(source, depth, text);
    }

    fn render_source_lines(&mut self, source: &RenderSource, depth: usize, text: &str) {
        let source_lines = crate::asciidoc::lines(text);
        let (directives, diagnostics) = LineDirectives::scan(text);
        for diagnostic in diagnostics {
            self.note(diagnostic);
        }
        let mut cursor = SourceCursor::default();
        for index in 0..source_lines.len() {
            let line = &source_lines[index];
            if line.number <= cursor.skip_before {
                continue;
            }
            if self.stop_at_line(line.number) {
                break;
            }
            self.render_source_line(
                &LineContext {
                    source,
                    depth,
                    source_lines: &source_lines,
                    index,
                },
                &directives,
                &mut cursor,
            );
        }
        self.close_source_block(&mut cursor);
        self.flush_paragraph(&mut cursor);
    }

    fn stop_at_line(&mut self, line_number: usize) -> bool {
        if self.expired() {
            return true;
        }
        if self.is_stopped() {
            return true;
        }
        if self.inline_bytes >= MAX_INLINE_SCAN_BYTES {
            self.exhaust("preview stopped: inline scanning exceeds the configured work limit");
            return true;
        }
        if self.html.len() > self.config.max_output_bytes {
            self.note(crate::asciidoc::Diagnostic::warning(
                "output-size-limit",
                "preview stopped at the configured output limit",
                line_number,
                1,
                None,
            ));
            return true;
        }
        false
    }

    fn render_source_line<'source>(
        &mut self,
        line_context: &LineContext<'_, 'source>,
        directives: &LineDirectives,
        cursor: &mut SourceCursor<'source>,
    ) {
        let line = &line_context.source_lines[line_context.index];
        if self.render_block_line(line, cursor) {
            return;
        }
        if cursor.state.apply(line.text) {
            cursor.block_start = line.number;
            cursor.block_buffer.clear();
            return;
        }
        self.render_normal_line(line_context, directives, cursor);
    }

    /// Feed one line to the open delimited block.
    fn render_block_line(
        &mut self,
        line: &crate::asciidoc::Line<'_>,
        cursor: &mut SourceCursor<'_>,
    ) -> bool {
        let Some(kind) = cursor.state.kind() else {
            return false;
        };
        if cursor.state.apply(line.text) {
            self.finish_block(kind, cursor);
        } else if kind != crate::asciidoc::BlockKind::Comment {
            cursor.block_buffer.push_str(line.text);
            cursor.block_buffer.push('\n');
        }
        true
    }

    fn render_normal_line<'source>(
        &mut self,
        line_context: &LineContext<'_, 'source>,
        directives: &LineDirectives,
        cursor: &mut SourceCursor<'source>,
    ) {
        let line = &line_context.source_lines[line_context.index];
        let trimmed = line.text.trim();
        if trimmed.starts_with("//") {
            self.flush_paragraph(cursor);
            return;
        }
        if directives.is_header_attribute(line.number, trimmed) {
            self.flush_paragraph(cursor);
            return;
        }
        if let Some(anchor) = directives.anchors.get(&line.number) {
            cursor.pending_anchor = Some(anchor.anchor.clone());
            return;
        }
        if let Some(directive) = directives.includes.get(&line.number) {
            self.flush_paragraph(cursor);
            self.flush_pending_anchor(cursor);
            self.render_include(line_context.source, directive, line_context.depth);
            return;
        }
        self.render_content_line(
            line_context.source,
            line_context.source_lines,
            line_context.index,
            cursor,
        );
    }

    fn render_content_line<'source>(
        &mut self,
        source: &RenderSource,
        source_lines: &[crate::asciidoc::Line<'source>],
        index: usize,
        cursor: &mut SourceCursor<'source>,
    ) {
        let line = &source_lines[index];
        let content = line.text;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            self.flush_paragraph(cursor);
            return;
        }
        if crate::asciidoc::is_conditional(trimmed) {
            self.flush_paragraph(cursor);
            self.note(crate::asciidoc::Diagnostic::warning(
                "unsupported-conditional",
                "conditional directive was not evaluated",
                line.number,
                1,
                line.span(),
            ));
            self.push_pre("unsupported-conditional", trimmed);
            return;
        }
        if let Some((target, caption)) = crate::images::parse_block(trimmed) {
            self.flush_paragraph(cursor);
            self.flush_pending_anchor(cursor);
            self.render_image(source, target, &caption, line.number);
            return;
        }
        if let Some(name) = block_macro(trimmed) {
            self.note(crate::asciidoc::Diagnostic::warning(
                "unsupported-block-macro",
                format!("block macro {name:?} was not executed"),
                line.number,
                1,
                line.span(),
            ));
        }
        if self.render_heading_line(content, cursor) {
            return;
        }
        if content.starts_with(' ') || content.starts_with('\t') {
            self.flush_paragraph(cursor);
            self.push_pre("literal", content);
            return;
        }
        if self.render_list_line(source_lines, index, cursor) {
            return;
        }
        cursor.paragraph.push(content);
    }

    fn render_image(&mut self, source: &RenderSource, target: &str, caption: &str, line: usize) {
        let pin = match crate::images::parse_target(target) {
            Ok(pin) => pin,
            Err(_) => {
                self.unavailable_image(caption, line);
                return;
            }
        };
        let key = (source.scope.clone(), pin);
        if !self.image_cache.contains_key(&key) {
            if self.image_cache.len() >= MAX_RENDER_IMAGES {
                self.note(crate::asciidoc::Diagnostic::warning(
                    "image-limit",
                    "preview stopped resolving images at the configured image limit",
                    line,
                    1,
                    None,
                ));
                self.unavailable_image(caption, line);
                return;
            }
            let loaded = self
                .image_loader
                .as_deref_mut()
                .and_then(|loader| loader(&source.scope, pin));
            let Some((loaded, decoded)) = loaded else {
                self.image_cache.insert(key.clone(), None);
                self.unavailable_image(caption, line);
                return;
            };
            if loaded.pin != pin
                || !matches!(decoded.media_type, "image/png" | "image/jpeg")
                || loaded.media_type != decoded.media_type
                || loaded.bytes.len() > crate::images::MAX_ENCODED_BYTES
            {
                self.image_cache.insert(key.clone(), None);
                self.unavailable_image(caption, line);
                return;
            }
            let Some(encoded_length) = base64_length(loaded.bytes.len()) else {
                self.exhaust_image_output(line);
                return;
            };
            if !self.image_markup_fits(
                encoded_length,
                decoded.media_type,
                decoded.width,
                decoded.height,
                caption,
            ) {
                self.exhaust_image_output(line);
                return;
            }
            let base64 = mneme_core::base64::encode(&loaded.bytes);
            let encoded = EncodedImage {
                media_type: decoded.media_type,
                width: decoded.width,
                height: decoded.height,
                base64,
            };
            self.image_cache.insert(key.clone(), Some(encoded));
        }
        self.append_cached_image(caption, line, key);
    }

    fn append_cached_image(
        &mut self,
        caption: &str,
        line: usize,
        key: (mneme_core::ScopeId, crate::SourcePin),
    ) {
        match self.image_cache.remove(&key) {
            Some(Some(image)) => {
                self.append_image(&image, caption, line);
                self.image_cache.insert(key, Some(image));
            }
            Some(None) => {
                self.image_cache.insert(key, None);
                self.unavailable_image(caption, line);
            }
            None => self.unavailable_image(caption, line),
        }
    }

    fn append_image(&mut self, image: &EncodedImage, caption: &str, line: usize) {
        if !self.image_markup_fits(
            image.base64.len(),
            image.media_type,
            image.width,
            image.height,
            caption,
        ) {
            self.exhaust_image_output(line);
            return;
        }
        let escaped_caption = escape_html(caption);
        self.html
            .push_str("<figure class=\"mneme-image\"><img alt=\"");
        self.html.push_str(&escaped_caption);
        self.html.push_str("\" width=\"");
        self.html.push_str(&image.width.to_string());
        self.html.push_str("\" height=\"");
        self.html.push_str(&image.height.to_string());
        self.html.push_str("\" src=\"data:");
        self.html.push_str(image.media_type);
        self.html.push_str(";base64,");
        self.html.push_str(&image.base64);
        self.html.push_str("\">");
        if !caption.is_empty() {
            self.html.push_str("<figcaption>");
            self.html.push_str(&escaped_caption);
            self.html.push_str("</figcaption>");
        }
        self.html.push_str("</figure>");
    }

    fn unavailable_image(&mut self, caption: &str, line: usize) {
        self.note(crate::asciidoc::Diagnostic::warning(
            "image-unavailable",
            "pinned image is unavailable or unsupported",
            line,
            1,
            None,
        ));
        let Some(caption_length) = escaped_html_length(caption) else {
            self.exhaust_image_output(line);
            return;
        };
        let markup_length =
            "<figure class=\"mneme-image-unavailable\"><span>image unavailable</span></figure>"
                .len()
                .saturating_add(if caption.is_empty() {
                    0
                } else {
                    "<figcaption></figcaption>"
                        .len()
                        .saturating_add(caption_length)
                });
        if !self.image_markup_length_fits(markup_length) {
            self.exhaust_image_output(line);
            return;
        }
        self.html
            .push_str("<figure class=\"mneme-image-unavailable\"><span>image unavailable</span>");
        if !caption.is_empty() {
            self.html.push_str("<figcaption>");
            self.html.push_str(&escape_html(caption));
            self.html.push_str("</figcaption>");
        }
        self.html.push_str("</figure>");
    }

    fn image_markup_fits(
        &self,
        base64_length: usize,
        media_type: &str,
        width: u32,
        height: u32,
        caption: &str,
    ) -> bool {
        let Some(caption_length) = escaped_html_length(caption) else {
            return false;
        };
        let width_length = width.to_string().len();
        let height_length = height.to_string().len();
        let mut markup_length = 0_usize;
        for length in [
            "<figure class=\"mneme-image\"><img alt=\"".len(),
            caption_length,
            "\" width=\"".len(),
            width_length,
            "\" height=\"".len(),
            height_length,
            "\" src=\"data:".len(),
            media_type.len(),
            ";base64,".len(),
            base64_length,
            "\">".len(),
            if caption.is_empty() {
                0
            } else {
                "<figcaption></figcaption>"
                    .len()
                    .saturating_add(caption_length)
            },
            "</figure>".len(),
        ] {
            let Some(total) = markup_length.checked_add(length) else {
                return false;
            };
            markup_length = total;
        }
        self.image_markup_length_fits(markup_length)
    }

    fn image_markup_length_fits(&self, markup_length: usize) -> bool {
        let limit = self.config.max_output_bytes.min(MAX_IMAGE_OUTPUT_BYTES);
        self.html
            .len()
            .checked_add(markup_length)
            .is_some_and(|total| total <= limit)
    }

    fn exhaust_image_output(&mut self, line: usize) {
        self.note(crate::asciidoc::Diagnostic::warning(
            "image-output-limit",
            "preview stopped because embedded image output exceeds its byte budget",
            line,
            1,
            None,
        ));
        self.is_budget_exhausted = true;
    }

    fn render_heading_line(&mut self, content: &str, cursor: &mut SourceCursor<'_>) -> bool {
        let Some((level, heading)) = heading(content) else {
            return false;
        };
        self.flush_paragraph(cursor);
        let id = cursor.pending_anchor.take();
        let id_attribute = id
            .as_deref()
            .filter(|anchor| crate::asciidoc::valid_anchor(anchor))
            .map(|anchor| format!(" id=\"{}\"", escape_html(anchor)))
            .unwrap_or_default();
        let level = level.min(6);
        self.html.push_str(&format!(
            "<h{level}{id_attribute}>{}</h{level}>",
            escape_html(heading)
        ));
        true
    }

    /// Render a list from the current line, consuming its items.
    fn render_list_line(
        &mut self,
        source_lines: &[crate::asciidoc::Line<'_>],
        index: usize,
        cursor: &mut SourceCursor<'_>,
    ) -> bool {
        let Some(marker) = list_marker(source_lines[index].text) else {
            return false;
        };
        self.flush_paragraph(cursor);
        let tag = if marker == '.' { "ol" } else { "ul" };
        self.html.push_str(&format!("<{tag}>"));
        let mut item = index;
        while item < source_lines.len() {
            let line = &source_lines[item];
            if list_marker(line.text) != Some(marker) {
                break;
            }
            let text = line.text.trim_start();
            let content = text.strip_prefix(marker).unwrap_or(text).trim();
            let rendered = self.inline(content, line.number);
            self.html.push_str("<li>");
            self.html.push_str(&rendered);
            self.html.push_str("</li>");
            cursor.skip_before = line.number;
            item += 1;
        }
        self.html.push_str(&format!("</{tag}>"));
        true
    }

    fn render_include(
        &mut self,
        source: &RenderSource,
        directive: &crate::asciidoc::IncludeDirective,
        depth: usize,
    ) {
        if !self.charge_include() {
            return;
        }
        let path = match crate::asciidoc::normalize_include_path(&source.path, &directive.target) {
            Ok(path) => path,
            Err(diagnostic) => {
                self.note(diagnostic);
                return;
            }
        };
        let sources = self.sources;
        let Some(target) = sources.get(&path) else {
            let code = if directive.optional {
                "include-optional-missing"
            } else {
                "include-unavailable"
            };
            self.note(crate::asciidoc::Diagnostic::warning(
                code,
                format!("include target {path:?} is unavailable"),
                directive.line,
                directive.column,
                Some(directive.span),
            ));
            self.push_pre(
                "include-unavailable",
                &format!("include unavailable: {path}"),
            );
            return;
        };
        self.occurrences.push(crate::IncludeOccurrence {
            including_path: source.path.clone(),
            target_path: path,
            directive_span: directive.span,
            source: target.pin,
        });
        self.render_source(target, depth + 1);
    }

    /// Emit an escaped preformatted block.
    fn push_pre(&mut self, class: &str, content: &str) {
        self.html.push_str("<pre class=\"");
        self.html.push_str(class);
        self.html.push_str("\">");
        self.html.push_str(&escape_html(content));
        self.html.push_str("</pre>");
    }

    fn finish_block(&mut self, kind: crate::asciidoc::BlockKind, cursor: &mut SourceCursor<'_>) {
        let buffer = std::mem::take(&mut cursor.block_buffer);
        let start = cursor.block_start;
        match kind {
            crate::asciidoc::BlockKind::Listing | crate::asciidoc::BlockKind::Literal => {
                self.push_pre("listing", &buffer);
            }
            crate::asciidoc::BlockKind::Passthrough => {
                self.note(crate::asciidoc::Diagnostic::warning(
                    "raw-passthrough-escaped",
                    "raw passthrough content was escaped, not executed",
                    start,
                    1,
                    None,
                ));
                self.push_pre("unsafe-passthrough", &buffer);
            }
            crate::asciidoc::BlockKind::Table => {
                self.note(crate::asciidoc::Diagnostic::warning(
                    "unsupported-table",
                    "table content is escaped in the supported preview subset",
                    start,
                    1,
                    None,
                ));
                self.push_pre("unsupported-table", &buffer);
            }
            crate::asciidoc::BlockKind::Comment => {}
        }
    }

    /// Close the block that is still open at the end of a source.
    ///
    /// AsciiDoc extends an unterminated delimited block to the end of input, so
    /// the buffered content is kept and the missing delimiter is reported
    /// instead of dropping the rest of the document without a signal.
    fn close_source_block(&mut self, cursor: &mut SourceCursor<'_>) {
        let Some(kind) = cursor.state.kind() else {
            return;
        };
        self.note(crate::asciidoc::Diagnostic::warning(
            "unterminated-block",
            "delimited block is not closed; it extends to the end of the source",
            cursor.block_start,
            1,
            None,
        ));
        self.finish_block(kind, cursor);
        cursor.state = crate::asciidoc::BlockState::default();
    }

    fn flush_pending_anchor(&mut self, cursor: &mut SourceCursor<'_>) {
        if let Some(anchor) = cursor.pending_anchor.take() {
            let anchor = escape_html(&anchor);
            self.html
                .push_str(&format!("<span id=\"{anchor}\"></span>"));
        }
    }

    fn flush_paragraph(&mut self, cursor: &mut SourceCursor<'_>) {
        if cursor.paragraph.is_empty() {
            return;
        }
        let text = cursor.paragraph.join("\n");
        cursor.paragraph.clear();
        let rendered = self.inline(&text, 0);
        self.flush_pending_anchor(cursor);
        self.html.push_str("<p>");
        self.html.push_str(&rendered);
        self.html.push_str("</p>");
    }

    /// Render inline markup for one authored block.
    ///
    /// Every bracket search starts at or after the previous one and the
    /// deadline is re-checked every [`INLINE_DEADLINE_STRIDE`] bytes, so an
    /// unclosed macro on a long line costs one pass instead of a rescan.
    fn inline(&mut self, text: &str, line: usize) -> String {
        let mut scan = InlineScan::new(text);
        let mut html = String::with_capacity(text.len());
        let mut next_check = INLINE_DEADLINE_STRIDE;
        while scan.position < text.len() {
            if scan.scanned >= next_check {
                next_check = scan.scanned.saturating_add(INLINE_DEADLINE_STRIDE);
                if self.expired() {
                    break;
                }
            }
            if let Some(consumed) = self.render_inline_passthrough(&mut scan, line, &mut html) {
                scan.advance(consumed);
                continue;
            }
            if let Some(consumed) = self.render_inline_macro(&mut scan, line, &mut html) {
                scan.advance(consumed);
                continue;
            }
            let consumed = self.render_inline_character(&mut scan, line, &mut html);
            scan.advance(consumed);
        }
        self.inline_bytes = self.inline_bytes.saturating_add(scan.scanned);
        html
    }

    fn render_inline_passthrough(
        &mut self,
        scan: &mut InlineScan<'_>,
        line: usize,
        html: &mut String,
    ) -> Option<usize> {
        let rest = scan.rest();
        if !rest.starts_with("pass:[") {
            return None;
        }
        let position = scan.position;
        let end = scan
            .close_bracket
            .find(position, &mut scan.scanned)
            .map_or(scan.text.len(), |close| close + 1);
        let literal = &scan.text[position..end];
        self.note(crate::asciidoc::Diagnostic::warning(
            "passthrough-inline-escaped",
            "inline passthrough content was escaped",
            line,
            1,
            None,
        ));
        html.push_str(&escape_html(literal));
        Some(literal.len())
    }

    fn render_inline_macro(
        &mut self,
        scan: &mut InlineScan<'_>,
        line: usize,
        html: &mut String,
    ) -> Option<usize> {
        let kind = inline_macro_kind(scan.rest())?;
        let (consumed, target, label) = parse_inline_macro(scan)?;
        match kind {
            InlineMacroKind::Image => {
                self.note(crate::asciidoc::Diagnostic::warning(
                    "external-asset-not-fetched",
                    "image target was not fetched or embedded",
                    line,
                    1,
                    None,
                ));
                let text =
                    label.unwrap_or_else(|| target.rsplit('/').next().unwrap_or(target).to_owned());
                html.push_str("<span class=\"image-alt\">");
                html.push_str(&escape_html(&text));
                html.push_str("</span>");
            }
            InlineMacroKind::Link => self.render_link(html, target, label, line),
            InlineMacroKind::Xref => self.render_xref(html, target, label, line),
        }
        Some(consumed)
    }

    fn render_xref(&mut self, html: &mut String, target: &str, label: Option<String>, line: usize) {
        if crate::asciidoc::valid_anchor(target) {
            let label_text = label.as_deref().unwrap_or(target);
            html.push_str(&format!(
                "<a href=\"#{}\">{}</a>",
                escape_html(target),
                escape_html(label_text)
            ));
            return;
        }
        self.note(crate::asciidoc::Diagnostic::warning(
            "xref-unavailable",
            "cross-reference target is not a safe local anchor",
            line,
            1,
            None,
        ));
        html.push_str(&escape_html(target));
    }

    fn render_link(&mut self, html: &mut String, target: &str, label: Option<String>, line: usize) {
        let label = label.unwrap_or_else(|| target.to_owned());
        if let Some(anchor) = target.strip_prefix('#')
            && crate::asciidoc::valid_anchor(anchor)
        {
            html.push_str(&format!(
                "<a href=\"#{}\">{}</a>",
                escape_html(anchor),
                escape_html(&label)
            ));
            return;
        }
        self.note(crate::asciidoc::Diagnostic::warning(
            "external-navigation-not-automatic",
            "external link target was not made navigable by the preview",
            line,
            1,
            None,
        ));
        html.push_str("<span class=\"external-link\">");
        html.push_str(&escape_html(&label));
        html.push_str("</span>");
    }

    /// Escape one character of prose; returns the bytes it consumed.
    fn render_inline_character(
        &mut self,
        scan: &mut InlineScan<'_>,
        line: usize,
        html: &mut String,
    ) -> usize {
        let rest = scan.rest();
        let Some(character) = rest.chars().next() else {
            return 1;
        };
        match character {
            '<' => {
                self.note(crate::asciidoc::Diagnostic::warning(
                    "raw-html-escaped",
                    "raw HTML was escaped",
                    line,
                    1,
                    None,
                ));
                html.push_str("&lt;");
            }
            '>' => {
                self.note(crate::asciidoc::Diagnostic::warning(
                    "raw-html-escaped",
                    "raw HTML was escaped",
                    line,
                    1,
                    None,
                ));
                html.push_str("&gt;");
            }
            '&' => html.push_str("&amp;"),
            '"' => html.push_str("&quot;"),
            '\'' => html.push_str("&#39;"),
            '{' => {
                self.note(crate::asciidoc::Diagnostic::warning(
                    "attribute-substitution-not-evaluated",
                    "attribute substitution was not evaluated",
                    line,
                    1,
                    None,
                ));
                html.push('{');
            }
            ':' => {
                self.diagnose_custom_macro(scan, line);
                html.push(':');
            }
            other => html.push(other),
        }
        character.len_utf8()
    }

    /// Report a `name:target[]` custom macro the processor will not execute.
    fn diagnose_custom_macro(&mut self, scan: &mut InlineScan<'_>, line: usize) {
        let position = scan.position;
        if position == 0 {
            return;
        }
        let has_prefix = scan.text[..position]
            .chars()
            .next_back()
            .is_some_and(|character| character.is_ascii_alphanumeric());
        if !has_prefix {
            return;
        }
        if scan.rest().starts_with("::") {
            return;
        }
        if scan
            .open_bracket
            .find(position + 1, &mut scan.scanned)
            .is_none()
        {
            return;
        }
        self.note(crate::asciidoc::Diagnostic::warning(
            "unsupported-macro",
            "custom macro was not executed",
            line,
            1,
            None,
        ));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InlineMacroKind {
    Image,
    Link,
    Xref,
}

fn inline_macro_kind(rest: &str) -> Option<InlineMacroKind> {
    if rest.starts_with("image:") {
        return Some(InlineMacroKind::Image);
    }
    if rest.starts_with("link:") {
        return Some(InlineMacroKind::Link);
    }
    if rest.starts_with("xref:") {
        return Some(InlineMacroKind::Xref);
    }
    None
}

/// Parse `name:target[label]`; returns the bytes it covers.
fn parse_inline_macro<'a>(scan: &mut InlineScan<'a>) -> Option<(usize, &'a str, Option<String>)> {
    let position = scan.position;
    let colon = scan.rest().find(':')?;
    let target_start = position + colon + 1;
    let open = scan.open_bracket.find(target_start, &mut scan.scanned)?;
    let close = scan.close_bracket.find(open + 1, &mut scan.scanned)?;
    let target = &scan.text[target_start..open];
    let label = scan.text[open + 1..close].trim();
    Some((
        close + 1 - position,
        target,
        (!label.is_empty()).then(|| label.to_owned()),
    ))
}

/// Inline scan state: the position reached and the memoized bracket searches.
struct InlineScan<'a> {
    text: &'a str,
    position: usize,
    scanned: u64,
    open_bracket: Finder<'a>,
    close_bracket: Finder<'a>,
}

impl<'a> InlineScan<'a> {
    fn new(text: &'a str) -> Self {
        InlineScan {
            text,
            position: 0,
            scanned: 0,
            open_bracket: Finder::new(text, '['),
            close_bracket: Finder::new(text, ']'),
        }
    }

    fn rest(&self) -> &'a str {
        &self.text[self.position..]
    }

    fn advance(&mut self, consumed: usize) {
        let step = consumed.min(self.text.len().saturating_sub(self.position));
        self.position += step;
        self.scanned = self.scanned.saturating_add(crate::budget_count(step));
    }
}

/// Memoized forward search for one character.
///
/// Callers scan left to right, so a search either reuses the previous hit or
/// starts where the last search stopped: every byte is examined once.
struct Finder<'a> {
    text: &'a str,
    needle: char,
    /// A position from which an earlier search found no needle at or after it.
    searched_to_end_from: Option<usize>,
    /// The most recent search start and its hit, reused for later positions.
    last_hit: Option<(usize, usize)>,
}

impl<'a> Finder<'a> {
    fn new(text: &'a str, needle: char) -> Self {
        Finder {
            text,
            needle,
            searched_to_end_from: None,
            last_hit: None,
        }
    }

    /// Next position of the needle at or after `position`, charging the bytes
    /// it examined to `scanned`.
    ///
    /// A scan that already reached the end answers every later position
    /// without searching again, so a forward caller examines each byte once.
    fn find(&mut self, position: usize, scanned: &mut u64) -> Option<usize> {
        if let Some(bound) = self.searched_to_end_from
            && position >= bound
        {
            return None;
        }
        if let Some((start, hit)) = self.last_hit
            && position >= start
            && hit >= position
        {
            return Some(hit);
        }
        if position >= self.text.len() {
            return None;
        }
        match self.text[position..].find(self.needle) {
            Some(offset) => {
                let hit = position + offset;
                *scanned = scanned.saturating_add(crate::budget_count(offset + 1));
                self.last_hit = Some((position, hit));
                Some(hit)
            }
            None => {
                let examined = self.text.len().saturating_sub(position);
                *scanned = scanned.saturating_add(crate::budget_count(examined));
                self.searched_to_end_from = Some(position);
                None
            }
        }
    }
}

/// Include directives and anchors of one source, keyed by line number, plus the
/// number of leading header lines.
struct LineDirectives {
    includes: std::collections::BTreeMap<usize, crate::asciidoc::IncludeDirective>,
    anchors: std::collections::BTreeMap<usize, crate::asciidoc::AnchorSpec>,
    header_lines: usize,
}

impl LineDirectives {
    fn scan(text: &str) -> (Self, Vec<crate::asciidoc::Diagnostic>) {
        let (includes, diagnostics) = crate::asciidoc::scan_includes_checked(text);
        let includes = includes
            .into_iter()
            .map(|directive| (directive.line, directive))
            .collect::<std::collections::BTreeMap<_, _>>();
        let anchors = crate::asciidoc::scan_anchors(text)
            .into_iter()
            .map(|anchor| (anchor.line, anchor))
            .collect::<std::collections::BTreeMap<_, _>>();
        let header_lines = crate::asciidoc::header_extent(text).unwrap_or(0);
        (
            LineDirectives {
                includes,
                anchors,
                header_lines,
            },
            diagnostics,
        )
    }

    /// Whether the line is a header attribute entry, which is configuration
    /// rather than body prose.
    fn is_header_attribute(&self, line_number: usize, content: &str) -> bool {
        line_number <= self.header_lines && crate::asciidoc::is_attribute_entry(content)
    }
}

#[derive(Default)]
struct SourceCursor<'a> {
    pending_anchor: Option<String>,
    paragraph: Vec<&'a str>,
    skip_before: usize,
    state: crate::asciidoc::BlockState,
    block_start: usize,
    block_buffer: String,
}

/// One source line as the renderer walks it: the document being laid out, its
/// include depth, and the position of the line within that document.
struct LineContext<'a, 'source> {
    source: &'a RenderSource,
    depth: usize,
    source_lines: &'a [crate::asciidoc::Line<'source>],
    index: usize,
}

/// Recognize a block macro such as `gist::12345[]`.
fn block_macro(line: &str) -> Option<&str> {
    let (name, rest) = line.split_once("::")?;
    if name.is_empty() || matches!(name, "include" | "endif") {
        return None;
    }
    let is_name = name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '-');
    if !is_name || !rest.contains('[') || !rest.ends_with(']') {
        return None;
    }
    Some(name)
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

/// The list marker of a list item line.
fn list_marker(line: &str) -> Option<char> {
    ['*', '.']
        .into_iter()
        .find(|&marker| is_list_item(line, marker))
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

fn escaped_html_length(text: &str) -> Option<usize> {
    text.chars().try_fold(0_usize, |length, character| {
        length.checked_add(match character {
            '&' => "&amp;".len(),
            '<' => "&lt;".len(),
            '>' => "&gt;".len(),
            '"' => "&quot;".len(),
            '\'' => "&#39;".len(),
            other => other.len_utf8(),
        })
    })
}

fn base64_length(byte_length: usize) -> Option<usize> {
    byte_length
        .checked_add(2)
        .and_then(|length| (length / 3).checked_mul(4))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn source(path: &str, bytes: &[u8]) -> RenderSource {
        RenderSource {
            path: path.to_owned(),
            pin: crate::SourcePin {
                source: mneme_core::RecordId::from_bytes([0x11; 16]),
                revision: mneme_core::RevisionId::from_bytes([0x12; 16]),
            },
            scope: mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar")
                .expect("fixture scope"),
            bytes: bytes.to_vec(),
        }
    }

    fn tiny_png() -> Vec<u8> {
        let pixels =
            image::RgbaImage::from_raw(1, 1, vec![255, 0, 0, 255]).expect("fixture pixels");
        let mut encoded = std::io::Cursor::new(Vec::new());
        pixels
            .write_to(&mut encoded, image::ImageFormat::Png)
            .expect("encode fixture PNG");
        encoded.into_inner()
    }

    fn fixture_image(pin: crate::SourcePin) -> (crate::images::Loaded, crate::images::Decoded) {
        let bytes = tiny_png();
        let decoded = crate::images::decode(&bytes).expect("decode fixture PNG");
        let loaded = crate::images::Loaded {
            pin,
            digest: mneme_core::ContentDigest::of_source_bytes(&bytes),
            media_type: decoded.media_type,
            width: decoded.width,
            height: decoded.height,
            bytes,
            generation: 1,
            workspace_revision: mneme_core::WorkspaceRevisionId::from_bytes([0x13; 16]),
        };
        (loaded, decoded)
    }

    #[test]
    fn only_authorized_pinned_images_become_escaped_data_urls() {
        let pin = source("root.adoc", b"").pin;
        let (loaded, decoded) = fixture_image(pin);
        let target = crate::images::target(pin);
        let root = source(
            "root.adoc",
            format!("image::{target}[<Caption & \"quote\">]\n").as_bytes(),
        );
        let sources = std::collections::BTreeMap::new();
        let config = crate::RenderConfig::default();
        let expected_scope = root.scope.clone();
        let mut payload = Some((loaded, decoded));
        let mut calls = 0_usize;
        let mut loader = |scope: &mneme_core::ScopeId, target: crate::SourcePin| {
            calls += 1;
            if scope == &expected_scope && target == pin {
                payload.take()
            } else {
                None
            }
        };
        let rendered =
            Renderer::new_with_images(&sources, &config, None, &mut loader).render(&root, None);
        assert!(rendered.html.contains("src=\"data:image/png;base64,"));
        assert!(
            rendered
                .html
                .contains("alt=\"&lt;Caption &amp; &quot;quote&quot;&gt;\"")
        );
        assert!(
            rendered
                .html
                .contains("<figcaption>&lt;Caption &amp; &quot;quote&quot;&gt;</figcaption>")
        );
        assert_eq!(calls, 1);
        assert!(!rendered.truncated);
    }

    #[test]
    fn external_and_data_targets_are_visible_but_never_fetched() {
        let root = source(
            "root.adoc",
            b"image::https://example.invalid/x.png[remote]\nimage::data:image/png;base64,AA==[active]\nimage::../photo.png[path]\n",
        );
        let sources = std::collections::BTreeMap::new();
        let config = crate::RenderConfig::default();
        let mut calls = 0_usize;
        let mut loader = |_scope: &mneme_core::ScopeId, _pin: crate::SourcePin| {
            calls += 1;
            None
        };
        let rendered =
            Renderer::new_with_images(&sources, &config, None, &mut loader).render(&root, None);
        assert_eq!(calls, 0);
        assert!(!rendered.html.contains("<img"));
        assert_eq!(rendered.html.matches("image unavailable").count(), 3);
        assert!(rendered.html.contains("<figcaption>remote</figcaption>"));
        assert!(rendered.html.contains("<figcaption>active</figcaption>"));
        assert!(rendered.html.contains("<figcaption>path</figcaption>"));
    }

    #[test]
    fn repeated_images_obey_the_cumulative_html_budget() {
        let pin = source("root.adoc", b"").pin;
        let (loaded, decoded) = fixture_image(pin);
        let target = crate::images::target(pin);
        let one = source(
            "root.adoc",
            format!("image::{target}[caption]\n").as_bytes(),
        );
        let sources = std::collections::BTreeMap::new();
        let default_config = crate::RenderConfig::default();
        let mut payload = Some((loaded.clone(), decoded.clone()));
        let mut loader = |_scope: &mneme_core::ScopeId, _pin: crate::SourcePin| payload.take();
        let first = Renderer::new_with_images(&sources, &default_config, None, &mut loader)
            .render(&one, None);
        let first_length = first.html.len();
        let repeated = source(
            "root.adoc",
            format!("image::{target}[caption]\nimage::{target}[caption]\n").as_bytes(),
        );
        let config = crate::RenderConfig {
            max_output_bytes: first_length.saturating_add(1),
            ..crate::RenderConfig::default()
        };
        let mut payload = Some((loaded, decoded));
        let mut loader = |_scope: &mneme_core::ScopeId, _pin: crate::SourcePin| payload.take();
        let rendered =
            Renderer::new_with_images(&sources, &config, None, &mut loader).render(&repeated, None);
        assert_eq!(rendered.html.matches("<img ").count(), 1);
        assert!(rendered.truncated);
    }

    #[test]
    fn unclosed_inline_macros_are_scanned_once() {
        let text = "link:".repeat(20_000);
        let sources = std::collections::BTreeMap::new();
        let config = crate::RenderConfig::default();
        let mut renderer = Renderer::new(&sources, &config, None);
        let before = renderer.inline_bytes;
        let html = renderer.inline(&text, 1);
        let scanned = renderer.inline_bytes.saturating_sub(before);
        let bound = u64::try_from(text.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(4);
        assert!(scanned <= bound);
        assert_eq!(html.len(), text.len());
    }

    #[test]
    fn a_timed_out_document_stops_every_later_render() {
        let mut sources = std::collections::BTreeMap::new();
        sources.insert(
            "root.adoc".to_owned(),
            source("root.adoc", b"= Root\n\nbody\n"),
        );
        let config = crate::RenderConfig::default();
        let mut renderer = Renderer::new(&sources, &config, None);
        renderer.is_timed_out = true;
        renderer.run(&sources["root.adoc"], None);
        assert!(renderer.html.is_empty());
        renderer.run(&sources["root.adoc"], None);
        assert!(renderer.html.is_empty());
        assert!(renderer.is_stopped());
        let output = renderer.finish();
        assert!(output.truncated);
    }

    #[test]
    fn exponential_include_fan_out_stops_at_the_include_budget() {
        let leaf = b"leaf prose\n";
        let mut shared = Vec::new();
        for _ in 0..10 {
            shared.extend_from_slice(b"include::leaf.adoc[]\n");
        }
        let mut middle = Vec::new();
        for _ in 0..10 {
            middle.extend_from_slice(b"include::shared.adoc[]\n");
        }
        // One source per fan-out branch, so the map is built at exactly that
        // size instead of growing one insert at a time.
        let fan_out = 10;
        let mut sources: std::collections::BTreeMap<String, RenderSource> = (0..fan_out)
            .map(|index| {
                let path = format!("l1-{index}.adoc");
                let render_source = source(&path, &middle);
                (path, render_source)
            })
            .collect();
        let mut root = String::from("= Root\n\n");
        for index in 0..fan_out {
            root.push_str(&format!("include::l1-{index}.adoc[]\n"));
        }
        sources.insert("shared.adoc".to_owned(), source("shared.adoc", &shared));
        sources.insert("leaf.adoc".to_owned(), source("leaf.adoc", leaf));
        sources.insert("root.adoc".to_owned(), source("root.adoc", root.as_bytes()));
        let config = crate::RenderConfig::default();
        let mut renderer = Renderer::new(&sources, &config, None);
        renderer.run(&sources["root.adoc"], None);
        let output = renderer.finish();
        assert!(output.truncated);
        assert_eq!(count_code_in(&output, "render-budget-exhausted"), 1);
        assert_eq!(output.occurrences.len(), 1_024);
    }

    #[test]
    fn a_refused_include_attribute_is_reported_by_the_renderer() {
        let mut sources = std::collections::BTreeMap::new();
        sources.insert(
            "notes.adoc".to_owned(),
            source("notes.adoc", b"Target prose.\n"),
        );
        sources.insert(
            "root.adoc".to_owned(),
            source("root.adoc", b"= Root\n\ninclude::notes.adoc[tag=public]\n"),
        );
        let config = crate::RenderConfig::default();
        let mut renderer = Renderer::new(&sources, &config, None);
        renderer.run(&sources["root.adoc"], None);
        let output = renderer.finish();
        assert_eq!(count_code_in(&output, "include-attribute-unsupported"), 1);
        assert!(!output.html.contains("Target prose."));
        assert!(output.occurrences.is_empty());
    }

    #[test]
    fn an_unterminated_block_keeps_its_content_and_reports_the_missing_delimiter() {
        let mut sources = std::collections::BTreeMap::new();
        sources.insert(
            "root.adoc".to_owned(),
            source(
                "root.adoc",
                b"= Root\n\nBefore.\n\n----\nnever closed\n\ntrailing prose\n",
            ),
        );
        let config = crate::RenderConfig::default();
        let mut renderer = Renderer::new(&sources, &config, None);
        renderer.run(&sources["root.adoc"], None);
        let output = renderer.finish();
        assert!(output.html.contains("trailing prose"));
        assert_eq!(count_code_in(&output, "unterminated-block"), 1);
    }

    #[test]
    fn header_attribute_entries_are_not_body_prose() {
        let mut sources = std::collections::BTreeMap::new();
        sources.insert(
            "root.adoc".to_owned(),
            source(
                "root.adoc",
                b"= Probe\n:entity-id: 01010101010101010101010101010101\n\nBody prose.\n",
            ),
        );
        let config = crate::RenderConfig::default();
        let mut renderer = Renderer::new(&sources, &config, None);
        renderer.run(&sources["root.adoc"], None);
        let output = renderer.finish();
        assert!(!output.html.contains("entity-id"));
        assert!(output.html.contains("<h1>Probe</h1>"));
        assert!(output.html.contains("Body prose."));
    }

    #[test]
    fn an_unsupported_configuration_is_refused() {
        let mut sources = std::collections::BTreeMap::new();
        sources.insert(
            "root.adoc".to_owned(),
            source("root.adoc", b"= Root\n\nbody\n"),
        );
        let config = crate::RenderConfig {
            version: "mneme-preview/v99-strict".to_owned(),
            ..crate::RenderConfig::default()
        };
        let output = Renderer::new_with_images(&sources, &config, None, &mut |_, _| None)
            .render(&sources["root.adoc"], None);
        assert!(!output.html.contains("<p>"));
        assert!(output.html.contains("preview is partial"));
        assert!(output.truncated);
        assert_eq!(count_code_in(&output, "unsupported-render-config"), 1);
    }

    fn count_code_in(output: &RenderOutput, code: &str) -> usize {
        output
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == code)
            .count()
    }
}
