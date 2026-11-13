//! Two tiers of error: codec failures, which are never fatal, and session
//! failures, which usually are.

use core::fmt;

/// Something went wrong encoding or decoding a packet.
///
/// A `CodecError` produced while *decoding* is never fatal. Pro DJ Link is a
/// reverse-engineered protocol on a network you do not control, so a device
/// running unfamiliar firmware must not be able to kill your main loop. The
/// [`Session`](crate::session::Session) surfaces these as
/// [`Event::DecodeError`](crate::event::Event::DecodeError) rather than
/// returning them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecError {
    /// The packet ended before a field we needed.
    UnexpectedEof {
        /// Bytes the field required.
        needed: usize,
        /// Bytes actually left.
        remaining: usize,
    },
    /// The datagram did not start with `Qspt1WmJOL`.
    InvalidMagic,
    /// A field held a value outside its documented range.
    InvalidField {
        /// Dotted path of the offending field.
        field: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A text field was not valid ASCII or UTF-16.
    InvalidString {
        /// Dotted path of the offending field.
        field: &'static str,
    },
    /// A string did not fit its fixed-width slot on the wire.
    StringTooLong {
        /// Dotted path of the offending field.
        field: &'static str,
        /// Bytes available.
        max_len: usize,
    },
    /// The destination buffer was too small to encode into.
    BufferOverflow {
        /// Bytes the encoder needed.
        needed: usize,
        /// Bytes the buffer had.
        capacity: usize,
    },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::UnexpectedEof { needed, remaining } => {
                write!(
                    f,
                    "unexpected end of packet: need {needed}, have {remaining}"
                )
            }
            CodecError::InvalidMagic => f.write_str("packet does not carry the Pro DJ Link magic"),
            CodecError::InvalidField { field, reason } => {
                write!(f, "invalid field `{field}`: {reason}")
            }
            CodecError::InvalidString { field } => write!(f, "field `{field}` is not valid text"),
            CodecError::StringTooLong { field, max_len } => {
                write!(f, "field `{field}` exceeds its {max_len}-byte slot")
            }
            CodecError::BufferOverflow { needed, capacity } => {
                write!(f, "buffer overflow: need {needed} bytes, have {capacity}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CodecError {}

/// Something went wrong driving a [`Session`](crate::session::Session).
///
/// Generic over the adapter's own error type so no boxing — and therefore no
/// allocator and no `std` — is required to carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError<E> {
    /// The adapter failed. Usually fatal: the socket is gone.
    Transport(E),
    /// We failed to *build* an outbound packet. A bug or bad configuration.
    Encode(CodecError),
    /// A send-side method was called before player-number negotiation finished.
    NotOnline,
    /// [`start`](crate::session::Session::start) was called without an IP and
    /// MAC address to advertise.
    MissingIdentity,
}

impl<E> From<CodecError> for SessionError<E> {
    fn from(error: CodecError) -> Self {
        SessionError::Encode(error)
    }
}

impl<E: fmt::Debug> fmt::Display for SessionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Transport(error) => write!(f, "transport error: {error:?}"),
            SessionError::Encode(error) => write!(f, "encode error: {error}"),
            SessionError::NotOnline => f.write_str("session is not online yet"),
            SessionError::MissingIdentity => {
                f.write_str("no local IP/MAC configured; call VcdjConfig::with_identity")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error + 'static> std::error::Error for SessionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SessionError::Transport(error) => Some(error),
            SessionError::Encode(error) => Some(error),
            SessionError::NotOnline | SessionError::MissingIdentity => None,
        }
    }
}
