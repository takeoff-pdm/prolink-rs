//! Ethernet hardware addresses.

use core::fmt;

/// A 48-bit Ethernet MAC address.
///
/// The protocol carries one in every keepalive: it is how devices tell each
/// other apart while they are still arguing about player numbers, before
/// anybody has an identity worth trusting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The all-zero address.
    pub const ZERO: MacAddr = MacAddr([0; 6]);

    /// Wraps six raw octets.
    pub const fn new(octets: [u8; 6]) -> Self {
        MacAddr(octets)
    }

    /// The underlying octets.
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        MacAddr(octets)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// Why a string could not be parsed as a [`MacAddr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAddrParseError {
    /// The input did not have exactly six colon-separated groups.
    WrongGroupCount,
    /// A group was not a pair of hex digits.
    InvalidHex,
}

impl fmt::Display for MacAddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacAddrParseError::WrongGroupCount => {
                f.write_str("expected six colon-separated groups")
            }
            MacAddrParseError::InvalidHex => f.write_str("expected two hex digits per group"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MacAddrParseError {}

impl core::str::FromStr for MacAddr {
    type Err = MacAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut groups = s.split(':');
        for octet in &mut octets {
            let group = groups.next().ok_or(MacAddrParseError::WrongGroupCount)?;
            if group.len() != 2 {
                return Err(MacAddrParseError::InvalidHex);
            }
            *octet = u8::from_str_radix(group, 16).map_err(|_| MacAddrParseError::InvalidHex)?;
        }
        if groups.next().is_some() {
            return Err(MacAddrParseError::WrongGroupCount);
        }
        Ok(MacAddr(octets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    #[test]
    fn round_trips_through_text() {
        let mac = MacAddr([0x74, 0x5e, 0x1c, 0x0a, 0xbb, 0x03]);
        let text = "74:5e:1c:0a:bb:03";
        assert_eq!(MacAddr::from_str(text).unwrap(), mac);
        #[cfg(feature = "alloc")]
        assert_eq!(alloc::format!("{mac}"), text);
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(
            MacAddr::from_str("74:5e:1c:0a:bb"),
            Err(MacAddrParseError::WrongGroupCount)
        );
        assert_eq!(
            MacAddr::from_str("74:5e:1c:0a:bb:03:ff"),
            Err(MacAddrParseError::WrongGroupCount)
        );
        assert_eq!(
            MacAddr::from_str("74:5e:1c:0a:bb:zz"),
            Err(MacAddrParseError::InvalidHex)
        );
        assert_eq!(
            MacAddr::from_str("74:5e:1c:0a:bb:3"),
            Err(MacAddrParseError::InvalidHex)
        );
    }
}
