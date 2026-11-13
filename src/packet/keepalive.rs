//! Announce-channel packets: UDP port 50000.
//!
//! This one family carries the whole device lifecycle. A player joining the
//! network asks who else is there, argues its way to an unused player number
//! over four escalating claims, and then settles into a steady 1.5-second
//! heartbeat for as long as it stays powered on.
//!
//! # Layout
//!
//! Every packet in this family shares a 36-byte header:
//!
//! ```text
//! 0x00  10  magic "Qspt1WmJOL"
//! 0x0a   1  packet type
//! 0x0b   1  padding
//! 0x0c  20  model name, NUL-padded ASCII
//! 0x20   1  protocol version (always 1)
//! 0x21   1  device type
//! 0x22   1  padding
//! 0x23   1  subtype
//! 0x24  ..  body, varying by packet type
//! ```
//!
//! The subtype byte is the *total packet length*: a steady-state keepalive is
//! `0x36` bytes long and carries subtype `0x36`. [`KeepAlivePacket::decode`]
//! checks this and reports a mismatch, which catches a truncated or
//! misinterpreted packet that would otherwise decode into plausible nonsense.
//! The check is skipped for the `0x00` subtype, which the DJM-900NXS sends on
//! its keepalives in place of a length.

use core::net::Ipv4Addr;

use crate::constants::MODEL_LEN;
use crate::error::CodecError;
use crate::packet::flags::StatusFeatureFlags;
use crate::wire::{FixedStr, MacAddr, ReadCursor, WriteCursor};

/// Offset at which every keepalive body begins.
const HEADER_LEN: usize = 0x24;

/// The value of the protocol-version byte on all known hardware.
const PROTOCOL_VERSION: u8 = 1;

tolerant_enum! {
    /// What kind of hardware sent a packet.
    pub enum DeviceType {
        /// A mixer.
        Djm = 1,
        /// A player. The CDJ-3000 reports [`Rekordbox`](DeviceType::Rekordbox).
        Cdj = 2,
        /// rekordbox software, and also the CDJ-3000.
        Rekordbox = 3,
    }
}

tolerant_enum! {
    /// Which stage of the lifecycle a keepalive belongs to.
    ///
    /// The numbering is not sequential; these are the values hardware sends.
    pub enum KeepAliveType {
        /// Publishing a MAC address, first claim in the sequence.
        Mac = 0x00,
        /// Publishing an IP address together with a proposed player number.
        Ip = 0x02,
        /// Asserting a player number, and how a conflict is signalled.
        Number = 0x04,
        /// The steady-state heartbeat.
        Status = 0x06,
        /// Announcing a change of player number.
        Change = 0x08,
        /// Asking who else is on the network.
        Hello = 0x0a,
    }
}

tolerant_enum! {
    /// How a device came by its player number.
    pub enum PlayerNumberAssignment {
        /// The network assigned it.
        Auto = 1,
        /// A human set it on the front panel.
        Manual = 2,
    }
}

/// The conventional subtype byte for each packet type.
///
/// Equal to the total encoded length in every case.
const fn conventional_subtype(packet_type: KeepAliveType) -> u8 {
    match packet_type {
        KeepAliveType::Mac => 0x2c,
        KeepAliveType::Ip => 0x32,
        KeepAliveType::Number => 0x26,
        KeepAliveType::Status => 0x36,
        KeepAliveType::Change => 0x29,
        KeepAliveType::Hello => 0x25,
        KeepAliveType::Unknown(_) => 0,
    }
}

/// The part of a keepalive that varies by type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeepAliveBody {
    /// Type `0x0a`. "Who else is out there?" — sent three times on startup so
    /// the sender can hear everyone's keepalives before choosing a number.
    Hello {
        /// `1` from players, `3` from a DJM-900NXS. Meaning unknown.
        counter: u8,
    },

    /// Type `0x00`. First claim: "this MAC address is joining."
    ClaimMac {
        /// Repeat counter, 1 through 3.
        iteration: u8,
        /// What the sender claims to be.
        flags: StatusFeatureFlags,
        /// The sender's hardware address.
        mac: MacAddr,
    },

    /// Type `0x02`. Second claim: "this IP wants this player number."
    ClaimIp {
        /// The sender's address.
        ip: Ipv4Addr,
        /// The sender's hardware address.
        mac: MacAddr,
        /// The number being claimed.
        player_number: u8,
        /// Repeat counter, 1 through 3.
        iteration: u8,
        /// What the sender claims to be.
        flags: StatusFeatureFlags,
        /// Whether a human chose the number.
        assignment: PlayerNumberAssignment,
    },

    /// Type `0x04`. Final claim, and also how an existing device objects to
    /// someone claiming its number.
    ClaimNumber {
        /// The number being claimed or defended.
        player_number: u8,
        /// Repeat counter, 1 through 3.
        iteration: u8,
    },

    /// Type `0x06`. The steady-state heartbeat, every 1.5 seconds.
    Status {
        /// The sender's player number.
        player_number: u8,
        /// Sometimes the sender's own number, sometimes another device's.
        /// Meaning unknown; preserved so it round-trips.
        related_player_number: u8,
        /// The sender's hardware address.
        mac: MacAddr,
        /// The sender's address.
        ip: Ipv4Addr,
        /// How many devices the sender can see. CDJ-3000s expect at least 2.
        device_count: u8,
        /// What the sender claims to be.
        flags: StatusFeatureFlags,
        /// Often `0`, `0x64` on a CDJ-3000. Meaning unknown.
        extra_flags: u8,
    },

    /// Type `0x08`. "I used to be player N."
    Change {
        /// The number the sender is giving up.
        previous_player_number: u8,
        /// The sender's address.
        ip: Ipv4Addr,
    },

    /// A packet type this library does not model. The header decoded fine, so
    /// the sender is still visible on the network; only the body is opaque.
    Unknown,
}

impl KeepAliveBody {
    /// The packet type this body belongs to.
    pub const fn packet_type(&self) -> KeepAliveType {
        match self {
            KeepAliveBody::Hello { .. } => KeepAliveType::Hello,
            KeepAliveBody::ClaimMac { .. } => KeepAliveType::Mac,
            KeepAliveBody::ClaimIp { .. } => KeepAliveType::Ip,
            KeepAliveBody::ClaimNumber { .. } => KeepAliveType::Number,
            KeepAliveBody::Status { .. } => KeepAliveType::Status,
            KeepAliveBody::Change { .. } => KeepAliveType::Change,
            KeepAliveBody::Unknown => KeepAliveType::Unknown(0),
        }
    }

    /// The player number this body claims or reports, if it carries one.
    pub const fn player_number(&self) -> Option<u8> {
        match self {
            KeepAliveBody::ClaimIp { player_number, .. }
            | KeepAliveBody::ClaimNumber { player_number, .. }
            | KeepAliveBody::Status { player_number, .. } => Some(*player_number),
            _ => None,
        }
    }

    /// The sender's hardware address, if this body carries one.
    pub const fn mac(&self) -> Option<MacAddr> {
        match self {
            KeepAliveBody::ClaimMac { mac, .. }
            | KeepAliveBody::ClaimIp { mac, .. }
            | KeepAliveBody::Status { mac, .. } => Some(*mac),
            _ => None,
        }
    }

    /// The sender's IP address, if this body carries one.
    pub const fn ip(&self) -> Option<Ipv4Addr> {
        match self {
            KeepAliveBody::ClaimIp { ip, .. }
            | KeepAliveBody::Status { ip, .. }
            | KeepAliveBody::Change { ip, .. } => Some(*ip),
            _ => None,
        }
    }
}

/// A packet from UDP port 50000.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepAlivePacket {
    /// The sender's model name, e.g. `"CDJ-3000"`.
    pub model: FixedStr<MODEL_LEN>,
    /// Always `1` on known hardware. Preserved for byte-exact re-encoding.
    pub protocol_version: u8,
    /// What kind of hardware sent this.
    pub device_type: DeviceType,
    /// The raw subtype byte, normally the packet's total length.
    pub subtype: u8,
    /// The type-specific payload.
    pub body: KeepAliveBody,
}

impl KeepAlivePacket {
    /// Builds a packet with the conventional subtype for its body.
    pub fn new(model: FixedStr<MODEL_LEN>, device_type: DeviceType, body: KeepAliveBody) -> Self {
        KeepAlivePacket {
            model,
            protocol_version: PROTOCOL_VERSION,
            device_type,
            subtype: conventional_subtype(body.packet_type()),
            body,
        }
    }

    /// The packet type, taken from the body.
    pub const fn packet_type(&self) -> KeepAliveType {
        self.body.packet_type()
    }

    /// Decodes a datagram received on UDP 50000.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(bytes);
        cursor.read_magic()?;

        let packet_type = KeepAliveType::from_u8(cursor.read_u8()?);
        cursor.skip(1)?;
        let model = cursor.read_ascii::<MODEL_LEN>(MODEL_LEN, "keepalive.model")?;
        let protocol_version = cursor.read_u8()?;
        let device_type = DeviceType::from_u8(cursor.read_u8()?);
        cursor.skip(1)?;
        let subtype = cursor.read_u8()?;

        debug_assert_eq!(cursor.position(), HEADER_LEN);

        // The subtype doubles as a length field. A mismatch means we are
        // looking at something other than what the header says, so decoding
        // the body would produce plausible-looking garbage.
        //
        // Longer-than-declared is tolerated: newer firmware may append fields.
        if subtype != 0 && (subtype as usize) > bytes.len() {
            return Err(CodecError::InvalidField {
                field: "keepalive.subtype",
                reason: "declared length exceeds the datagram",
            });
        }

        let body = match packet_type {
            KeepAliveType::Hello => KeepAliveBody::Hello {
                counter: cursor.read_u8()?,
            },
            KeepAliveType::Mac => KeepAliveBody::ClaimMac {
                iteration: cursor.read_u8()?,
                flags: StatusFeatureFlags::from_bits_retain(cursor.read_u8()?),
                mac: cursor.read_mac()?,
            },
            KeepAliveType::Ip => KeepAliveBody::ClaimIp {
                ip: cursor.read_ipv4()?,
                mac: cursor.read_mac()?,
                player_number: cursor.read_u8()?,
                iteration: cursor.read_u8()?,
                flags: StatusFeatureFlags::from_bits_retain(cursor.read_u8()?),
                assignment: PlayerNumberAssignment::from_u8(cursor.read_u8()?),
            },
            KeepAliveType::Number => KeepAliveBody::ClaimNumber {
                player_number: cursor.read_u8()?,
                iteration: cursor.read_u8()?,
            },
            KeepAliveType::Status => KeepAliveBody::Status {
                player_number: cursor.read_u8()?,
                related_player_number: cursor.read_u8()?,
                mac: cursor.read_mac()?,
                ip: cursor.read_ipv4()?,
                device_count: cursor.read_u8()?,
                flags: {
                    cursor.skip(3)?;
                    StatusFeatureFlags::from_bits_retain(cursor.read_u8()?)
                },
                extra_flags: cursor.read_u8()?,
            },
            KeepAliveType::Change => KeepAliveBody::Change {
                previous_player_number: cursor.read_u8()?,
                ip: cursor.read_ipv4()?,
            },
            KeepAliveType::Unknown(_) => KeepAliveBody::Unknown,
        };

        Ok(KeepAlivePacket {
            model,
            protocol_version,
            device_type,
            subtype,
            body,
        })
    }

    /// Encodes into `out`, returning the number of bytes written.
    ///
    /// Fails with [`CodecError::InvalidField`] on a body this library cannot
    /// build, which is only [`KeepAliveBody::Unknown`] — that variant exists to
    /// carry an inbound packet through, not to be sent.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut cursor = WriteCursor::new(out);
        cursor.write_magic()?;
        cursor.write_u8(self.packet_type().to_u8())?;
        cursor.write_u8(0)?;
        cursor.write_ascii(&self.model, MODEL_LEN, "keepalive.model")?;
        cursor.write_u8(self.protocol_version)?;
        cursor.write_u8(self.device_type.to_u8())?;
        cursor.write_u8(0)?;
        cursor.write_u8(self.subtype)?;

        match &self.body {
            KeepAliveBody::Hello { counter } => cursor.write_u8(*counter)?,
            KeepAliveBody::ClaimMac {
                iteration,
                flags,
                mac,
            } => {
                cursor.write_u8(*iteration)?;
                cursor.write_u8(flags.bits())?;
                cursor.write_mac(*mac)?;
            }
            KeepAliveBody::ClaimIp {
                ip,
                mac,
                player_number,
                iteration,
                flags,
                assignment,
            } => {
                cursor.write_ipv4(*ip)?;
                cursor.write_mac(*mac)?;
                cursor.write_u8(*player_number)?;
                cursor.write_u8(*iteration)?;
                cursor.write_u8(flags.bits())?;
                cursor.write_u8(assignment.to_u8())?;
            }
            KeepAliveBody::ClaimNumber {
                player_number,
                iteration,
            } => {
                cursor.write_u8(*player_number)?;
                cursor.write_u8(*iteration)?;
            }
            KeepAliveBody::Status {
                player_number,
                related_player_number,
                mac,
                ip,
                device_count,
                flags,
                extra_flags,
            } => {
                cursor.write_u8(*player_number)?;
                cursor.write_u8(*related_player_number)?;
                cursor.write_mac(*mac)?;
                cursor.write_ipv4(*ip)?;
                cursor.write_u8(*device_count)?;
                cursor.write_zeros(3)?;
                cursor.write_u8(flags.bits())?;
                cursor.write_u8(*extra_flags)?;
            }
            KeepAliveBody::Change {
                previous_player_number,
                ip,
            } => {
                cursor.write_u8(*previous_player_number)?;
                cursor.write_ipv4(*ip)?;
            }
            KeepAliveBody::Unknown => {
                return Err(CodecError::InvalidField {
                    field: "keepalive.body",
                    reason: "cannot encode a body that was not understood",
                })
            }
        }

        Ok(cursor.position())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAX_PACKET_LEN;

    fn model() -> FixedStr<MODEL_LEN> {
        FixedStr::new("CDJ-3000").unwrap()
    }

    fn sample_bodies() -> [KeepAliveBody; 6] {
        [
            KeepAliveBody::Hello { counter: 1 },
            KeepAliveBody::ClaimMac {
                iteration: 2,
                flags: StatusFeatureFlags::IS_PLAYER_OR_MIXER,
                mac: MacAddr([0x74, 0x5e, 0x1c, 0x0a, 0xbb, 0x03]),
            },
            KeepAliveBody::ClaimIp {
                ip: Ipv4Addr::new(192, 168, 1, 5),
                mac: MacAddr([0x74, 0x5e, 0x1c, 0x0a, 0xbb, 0x03]),
                player_number: 5,
                iteration: 3,
                flags: StatusFeatureFlags::IS_PLAYER_OR_MIXER,
                assignment: PlayerNumberAssignment::Auto,
            },
            KeepAliveBody::ClaimNumber {
                player_number: 5,
                iteration: 1,
            },
            KeepAliveBody::Status {
                player_number: 5,
                related_player_number: 1,
                mac: MacAddr([0x74, 0x5e, 0x1c, 0x0a, 0xbb, 0x03]),
                ip: Ipv4Addr::new(192, 168, 1, 5),
                device_count: 2,
                flags: StatusFeatureFlags::IS_PLAYER_OR_MIXER,
                extra_flags: 0x64,
            },
            KeepAliveBody::Change {
                previous_player_number: 3,
                ip: Ipv4Addr::new(192, 168, 1, 5),
            },
        ]
    }

    #[test]
    fn every_body_round_trips() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        for body in sample_bodies() {
            let packet = KeepAlivePacket::new(model(), DeviceType::Cdj, body);
            let len = packet.encode(&mut buf).unwrap();
            let decoded = KeepAlivePacket::decode(&buf[..len]).unwrap();
            assert_eq!(decoded, packet, "body {body:?}");
        }
    }

    #[test]
    fn the_subtype_byte_is_the_packet_length() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        for body in sample_bodies() {
            let packet = KeepAlivePacket::new(model(), DeviceType::Cdj, body);
            let len = packet.encode(&mut buf).unwrap();
            assert_eq!(
                packet.subtype as usize, len,
                "subtype should equal the encoded length for {body:?}"
            );
        }
    }

    #[test]
    fn a_steady_state_keepalive_is_fifty_four_bytes() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let packet = KeepAlivePacket::new(model(), DeviceType::Cdj, sample_bodies()[4]);
        assert_eq!(packet.encode(&mut buf).unwrap(), 0x36);
    }

    #[test]
    fn unknown_device_types_survive() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let mut packet = KeepAlivePacket::new(model(), DeviceType::Cdj, sample_bodies()[0]);
        packet.device_type = DeviceType::Unknown(0x42);
        let len = packet.encode(&mut buf).unwrap();
        let decoded = KeepAlivePacket::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.device_type, DeviceType::Unknown(0x42));
    }

    #[test]
    fn unknown_packet_types_decode_the_header_and_stop() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let packet = KeepAlivePacket::new(model(), DeviceType::Cdj, sample_bodies()[4]);
        let len = packet.encode(&mut buf).unwrap();
        buf[10] = 0x7f; // a type from some future firmware

        let decoded = KeepAlivePacket::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.model, "CDJ-3000");
        assert_eq!(decoded.body, KeepAliveBody::Unknown);
    }

    #[test]
    fn trailing_bytes_are_ignored() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let packet = KeepAlivePacket::new(model(), DeviceType::Cdj, sample_bodies()[4]);
        let len = packet.encode(&mut buf).unwrap();
        // Pretend a firmware update appended four fields we know nothing about.
        let decoded = KeepAlivePacket::decode(&buf[..len + 4]).unwrap();
        assert_eq!(decoded.body, packet.body);
    }

    #[test]
    fn a_lying_length_field_is_rejected() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let packet = KeepAlivePacket::new(model(), DeviceType::Cdj, sample_bodies()[4]);
        let len = packet.encode(&mut buf).unwrap();
        buf[0x23] = 0xff; // claims 255 bytes, datagram is 54

        assert!(matches!(
            KeepAlivePacket::decode(&buf[..len]),
            Err(CodecError::InvalidField {
                field: "keepalive.subtype",
                ..
            })
        ));
    }

    #[test]
    fn a_djm_zero_subtype_is_accepted() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let mut packet = KeepAlivePacket::new(model(), DeviceType::Djm, sample_bodies()[4]);
        packet.subtype = 0x00; // what a DJM-900NXS sends
        let len = packet.encode(&mut buf).unwrap();
        assert_eq!(KeepAlivePacket::decode(&buf[..len]).unwrap(), packet);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let packet = KeepAlivePacket::new(model(), DeviceType::Cdj, sample_bodies()[4]);
        let len = packet.encode(&mut buf).unwrap();
        buf[0] = b'X';
        assert_eq!(
            KeepAlivePacket::decode(&buf[..len]),
            Err(CodecError::InvalidMagic)
        );
    }

    /// Every truncation of every packet must produce an error, not a panic and
    /// not a bogus success. This is the cheapest possible guard against a
    /// missing bounds check, and it runs against real network input.
    #[test]
    fn no_truncation_panics_or_silently_succeeds() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        for body in sample_bodies() {
            let packet = KeepAlivePacket::new(model(), DeviceType::Cdj, body);
            let len = packet.encode(&mut buf).unwrap();
            for n in 0..len {
                assert!(
                    KeepAlivePacket::decode(&buf[..n]).is_err(),
                    "{body:?} truncated to {n} of {len} bytes decoded successfully"
                );
            }
        }
    }

    #[test]
    fn encoding_refuses_a_buffer_that_is_too_small() {
        let mut buf = [0u8; 20];
        let packet = KeepAlivePacket::new(model(), DeviceType::Cdj, sample_bodies()[4]);
        assert!(matches!(
            packet.encode(&mut buf),
            Err(CodecError::BufferOverflow { .. })
        ));
    }
}
