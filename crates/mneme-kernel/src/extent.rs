//! Byte spans and excerpt windows.
//!
//! Spans are half-open byte ranges `[start, stop)`. Every window returned here
//! lies inside the text it was computed for, so slicing with it cannot fail.

/// A request for an excerpt of a cited span.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct ExcerptRequest {
    /// First byte of the cited span.
    pub start: u64,
    /// One past the last byte of the cited span.
    pub stop: u64,
    /// Length of the text the span refers to.
    pub text_len: u64,
    /// Largest excerpt the caller accepts.
    pub max_bytes: u64,
}

/// A window to slice from the text.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct Window {
    /// First byte of the window.
    pub start: u64,
    /// One past the last byte of the window.
    pub stop: u64,
    /// The window is shorter than the cited span.
    pub truncated: bool,
}

/// The length of a span, or `None` when it runs backwards.
pub fn span_length(start: u64, stop: u64) -> Option<u64> {
    if stop < start {
        None
    } else {
        Some(stop - start)
    }
}

/// Whether a span lies inside a text of the given length.
pub fn span_in_text(start: u64, stop: u64, text_len: u64) -> bool {
    start <= stop && stop <= text_len
}

/// The window to excerpt for a cited span, or `None` when the span does not
/// lie inside the text. A span longer than `max_bytes` is cut to its first
/// `max_bytes` bytes and marked truncated.
pub fn excerpt_window(request: &ExcerptRequest) -> Option<Window> {
    if !span_in_text(request.start, request.stop, request.text_len) {
        None
    } else {
        let length = request.stop - request.start;
        if length <= request.max_bytes {
            Some(Window {
                start: request.start,
                stop: request.stop,
                truncated: false,
            })
        } else {
            Some(Window {
                start: request.start,
                stop: request.start + request.max_bytes,
                truncated: true,
            })
        }
    }
}

/// Whether a byte is a UTF-8 continuation byte.
pub fn is_continuation(byte: u8) -> bool {
    (byte & 0xC0) == 0x80
}

/// Step back from `index` over UTF-8 continuation bytes: the largest position
/// not above `index` that holds a non-continuation byte, or `0` when every
/// byte up to `index` is a continuation byte; `bytes.len()` when `index` is at
/// or past the end.
///
/// In well-formed UTF-8 the result is a character boundary, so a window whose
/// ends were floored can be sliced as text.
#[allow(unknown_lints, usize_in_public_api)] // byte positions index the slice
pub fn floor_boundary(bytes: &[u8], index: usize) -> usize {
    if index >= bytes.len() {
        bytes.len()
    } else {
        let mut position = index;
        while position > 0 && is_continuation(bytes[position]) {
            position -= 1;
        }
        position
    }
}
