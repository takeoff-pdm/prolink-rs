//! Inline strings for the protocol's fixed-width text fields.

use core::fmt;
use core::ops::Deref;

use crate::error::CodecError;

/// A UTF-8 string stored inline in `N` bytes.
///
/// Every text field in Pro DJ Link occupies a fixed slot on the wire — the
/// `model` field is 20 bytes, `firmware` is 4, a media slot's name is 64 bytes
/// of UTF-16 — so nothing is gained by putting them on the heap. Storing them
/// inline is what lets the receive path run without an allocator, which matters
/// when six CDJ-3000s are between them producing tens of packets a second.
///
/// The content is always valid UTF-8; both constructors validate.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FixedStr<const N: usize> {
    bytes: [u8; N],
    len: u8,
}

impl<const N: usize> FixedStr<N> {
    /// The empty string.
    pub const EMPTY: Self = FixedStr {
        bytes: [0; N],
        len: 0,
    };

    /// Copies `s` in, failing if it does not fit.
    ///
    /// Truncation is not offered because slicing UTF-8 at an arbitrary byte
    /// offset can split a character; a caller that genuinely wants a prefix
    /// should choose the boundary itself.
    pub fn new(s: &str) -> Result<Self, CodecError> {
        const { assert!(N <= u8::MAX as usize) };
        if s.len() > N {
            return Err(CodecError::StringTooLong {
                field: "string",
                max_len: N,
            });
        }
        let mut bytes = [0u8; N];
        bytes[..s.len()].copy_from_slice(s.as_bytes());
        Ok(FixedStr {
            bytes,
            len: s.len() as u8,
        })
    }

    /// Builds a string from exactly `N` ASCII bytes, in a `const` context.
    ///
    /// Returns `None` if any byte is not ASCII. [`new`](FixedStr::new) cannot
    /// be `const` because it takes a `&str` of arbitrary length; this exists
    /// for the handful of fixed strings the library builds at compile time.
    pub const fn from_ascii_const(bytes: [u8; N]) -> Option<Self> {
        let mut i = 0;
        while i < N {
            if bytes[i] >= 0x80 {
                return None;
            }
            i += 1;
        }
        Some(FixedStr {
            bytes,
            len: N as u8,
        })
    }

    /// Decodes a NUL-padded ASCII field.
    ///
    /// Devices pad with NULs, but some firmware leaves stale bytes after the
    /// terminator, so everything from the first NUL onwards is discarded.
    pub fn from_ascii_padded(raw: &[u8], field: &'static str) -> Result<Self, CodecError> {
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let text = &raw[..end];
        if text.len() > N {
            return Err(CodecError::StringTooLong { field, max_len: N });
        }
        if !text.is_ascii() {
            return Err(CodecError::InvalidString { field });
        }
        let mut bytes = [0u8; N];
        bytes[..text.len()].copy_from_slice(text);
        Ok(FixedStr {
            bytes,
            len: text.len() as u8,
        })
    }

    /// Decodes a NUL-padded big-endian UTF-16 field.
    ///
    /// Surrogate pairs are rejected rather than silently mangled: no field in
    /// this protocol that uses UTF-16 carries anything outside the basic
    /// multilingual plane, so a surrogate means the offsets are wrong.
    pub fn from_utf16_padded(raw: &[u8], field: &'static str) -> Result<Self, CodecError> {
        if raw.len() % 2 != 0 {
            return Err(CodecError::InvalidString { field });
        }
        let mut bytes = [0u8; N];
        let mut len = 0usize;
        for pair in raw.chunks_exact(2) {
            let unit = u16::from_be_bytes([pair[0], pair[1]]);
            if unit == 0 {
                break;
            }
            let ch = char::from_u32(unit as u32).ok_or(CodecError::InvalidString { field })?;
            let encoded = ch.len_utf8();
            if len + encoded > N {
                return Err(CodecError::StringTooLong { field, max_len: N });
            }
            ch.encode_utf8(&mut bytes[len..]);
            len += encoded;
        }
        Ok(FixedStr {
            bytes,
            len: len as u8,
        })
    }

    /// The string contents.
    pub fn as_str(&self) -> &str {
        // Both constructors validate, and `new` only ever copies whole `&str`s.
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the string is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Writes the string into `out` as NUL-padded ASCII, filling the whole
    /// slice.
    pub fn write_ascii_padded(
        &self,
        out: &mut [u8],
        field: &'static str,
    ) -> Result<(), CodecError> {
        let text = self.as_str().as_bytes();
        if text.len() > out.len() {
            return Err(CodecError::StringTooLong {
                field,
                max_len: out.len(),
            });
        }
        out[..text.len()].copy_from_slice(text);
        out[text.len()..].fill(0);
        Ok(())
    }

    /// Writes the string into `out` as NUL-padded big-endian UTF-16, filling
    /// the whole slice.
    pub fn write_utf16_padded(
        &self,
        out: &mut [u8],
        field: &'static str,
    ) -> Result<(), CodecError> {
        if out.len() % 2 != 0 {
            return Err(CodecError::InvalidString { field });
        }
        let mut offset = 0usize;
        for ch in self.as_str().chars() {
            let mut buf = [0u16; 2];
            let units = ch.encode_utf16(&mut buf);
            if units.len() != 1 {
                // Outside the BMP; no field in this protocol can carry it.
                return Err(CodecError::InvalidString { field });
            }
            if offset + 2 > out.len() {
                return Err(CodecError::StringTooLong {
                    field,
                    max_len: out.len(),
                });
            }
            out[offset..offset + 2].copy_from_slice(&units[0].to_be_bytes());
            offset += 2;
        }
        out[offset..].fill(0);
        Ok(())
    }
}

impl<const N: usize> Default for FixedStr<N> {
    fn default() -> Self {
        FixedStr::EMPTY
    }
}

impl<const N: usize> Deref for FixedStr<N> {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize> AsRef<str> for FixedStr<N> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize> PartialEq<str> for FixedStr<N> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<const N: usize> PartialEq<&str> for FixedStr<N> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl<const N: usize> fmt::Display for FixedStr<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<const N: usize> fmt::Debug for FixedStr<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl<const N: usize> core::str::FromStr for FixedStr<N> {
    type Err = CodecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FixedStr::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_padding_round_trips() {
        let raw = b"CDJ-3000\0\0\0\0\0\0\0\0\0\0\0\0";
        let s = FixedStr::<20>::from_ascii_padded(raw, "model").unwrap();
        assert_eq!(s, "CDJ-3000");

        let mut out = [0xffu8; 20];
        s.write_ascii_padded(&mut out, "model").unwrap();
        assert_eq!(&out, raw);
    }

    #[test]
    fn ascii_stops_at_the_first_nul_ignoring_stale_bytes() {
        let raw = b"CDJ-3000\0GARBAGE\0\0\0\0";
        let s = FixedStr::<20>::from_ascii_padded(raw, "model").unwrap();
        assert_eq!(s, "CDJ-3000");
    }

    #[test]
    fn utf16_padding_round_trips() {
        let mut raw = [0u8; 16];
        for (i, unit) in "USB".encode_utf16().enumerate() {
            raw[i * 2..i * 2 + 2].copy_from_slice(&unit.to_be_bytes());
        }
        let s = FixedStr::<32>::from_utf16_padded(&raw, "name").unwrap();
        assert_eq!(s, "USB");

        let mut out = [0xffu8; 16];
        s.write_utf16_padded(&mut out, "name").unwrap();
        assert_eq!(out, raw);
    }

    #[test]
    fn rejects_strings_that_do_not_fit() {
        assert!(matches!(
            FixedStr::<4>::new("toolong"),
            Err(CodecError::StringTooLong { max_len: 4, .. })
        ));
        assert!(matches!(
            FixedStr::<4>::from_ascii_padded(b"toolong\0", "model"),
            Err(CodecError::StringTooLong { max_len: 4, .. })
        ));
    }

    #[test]
    fn rejects_non_ascii_in_ascii_fields() {
        assert!(matches!(
            FixedStr::<20>::from_ascii_padded(b"caf\xe9\0", "model"),
            Err(CodecError::InvalidString { .. })
        ));
    }

    #[test]
    fn rejects_odd_length_utf16() {
        assert!(matches!(
            FixedStr::<20>::from_utf16_padded(&[0, 0x55, 0], "name"),
            Err(CodecError::InvalidString { .. })
        ));
    }

    #[test]
    fn rejects_surrogates() {
        // A lone high surrogate — offsets are wrong if we ever see one.
        assert!(matches!(
            FixedStr::<20>::from_utf16_padded(&[0xd8, 0x00, 0, 0], "name"),
            Err(CodecError::InvalidString { .. })
        ));
    }
}
