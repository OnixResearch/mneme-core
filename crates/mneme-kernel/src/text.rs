//! Byte-level syntax checks for text that crosses a trust boundary.

/// Whether a byte is a lowercase hexadecimal digit.
pub fn is_lower_hex_byte(byte: u8) -> bool {
    (byte >= b'0' && byte <= b'9') || (byte >= b'a' && byte <= b'f')
}

/// Whether every byte is a lowercase hexadecimal digit.
///
/// Identifiers and digests have one spelling. Uppercase digits are refused so
/// that the bytes a caller submitted are the bytes that are hashed.
pub fn is_lower_hex(bytes: &[u8]) -> bool {
    let mut is_valid = true;
    let mut index = 0_usize;
    while index < bytes.len() && is_valid {
        is_valid = is_lower_hex_byte(bytes[index]);
        index += 1;
    }
    is_valid
}

/// Whether a byte may start an unquoted logic-program atom.
pub fn is_atom_start(byte: u8) -> bool {
    byte >= b'a' && byte <= b'z'
}

/// Whether a byte may continue an unquoted logic-program atom.
pub fn is_atom_continue(byte: u8) -> bool {
    (byte >= b'a' && byte <= b'z')
        || (byte >= b'A' && byte <= b'Z')
        || (byte >= b'0' && byte <= b'9')
        || byte == b'_'
}

/// Whether text can be emitted verbatim as a logic-program atom or functor.
///
/// Accepted text starts with a lowercase ASCII letter and continues with ASCII
/// letters, digits or underscores. It therefore contains no parenthesis,
/// comma, period, quote, whitespace or operator character, and cannot be read
/// as a variable, a second goal or a directive.
pub fn is_safe_atom(bytes: &[u8]) -> bool {
    if bytes.is_empty() || !is_atom_start(bytes[0]) {
        false
    } else {
        let mut is_safe = true;
        let mut index = 1_usize;
        while index < bytes.len() && is_safe {
            is_safe = is_atom_continue(bytes[index]);
            index += 1;
        }
        is_safe
    }
}

/// Progress of the canonical-path scan.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct PathScan {
    /// No rule has been broken so far.
    pub valid: bool,
    /// Number of bytes in the current segment, counted up to three.
    pub segment_len: u8,
    /// Every byte of the current segment so far is a period.
    pub only_dots: bool,
}

/// Whether a finished segment is acceptable: not empty, not `.`, not `..`.
const fn segment_ok(segment_len: u8, only_dots: bool) -> bool {
    segment_len > 0 && !(only_dots && segment_len <= 2)
}

/// Advance the canonical-path scan by one byte.
pub fn path_step(scan: &PathScan, byte: u8) -> PathScan {
    if byte == 0 || byte == b'\\' {
        PathScan {
            valid: false,
            segment_len: scan.segment_len,
            only_dots: scan.only_dots,
        }
    } else if byte == b'/' {
        PathScan {
            valid: scan.valid && segment_ok(scan.segment_len, scan.only_dots),
            segment_len: 0,
            only_dots: true,
        }
    } else {
        PathScan {
            valid: scan.valid,
            segment_len: if scan.segment_len < 3 {
                scan.segment_len + 1
            } else {
                3
            },
            only_dots: scan.only_dots && byte == b'.',
        }
    }
}

/// Whether a logical path is in canonical relative form.
///
/// A canonical path is a non-empty sequence of segments separated by single
/// `/` bytes. No segment is empty, `.` or `..`, and no byte is NUL or a
/// backslash. So the path has no leading or trailing slash, no `//`, and no
/// way to name its parent; two different canonical paths never name the same
/// working file.
pub fn is_canonical_relative_path(path: &[u8]) -> bool {
    let mut scan = PathScan {
        valid: true,
        segment_len: 0,
        only_dots: true,
    };
    let mut index = 0_usize;
    while index < path.len() && scan.valid {
        scan = path_step(&scan, path[index]);
        index += 1;
    }
    scan.valid && segment_ok(scan.segment_len, scan.only_dots)
}
