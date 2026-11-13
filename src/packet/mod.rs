//! The wire codecs, one module per UDP channel.
//!
//! Every packet type here offers the same pair of methods:
//!
//! * `decode(&[u8]) -> Result<Self, CodecError>`
//! * `encode(&self, &mut [u8]) -> Result<usize, CodecError>`
//!
//! Neither performs I/O, consults a clock, or allocates. That is what makes
//! them usable from a test, from a packet capture, and from a bare-metal
//! interrupt handler alike.
//!
//! # Decoding is deliberately permissive
//!
//! Pro DJ Link is reverse-engineered from hardware nobody here controls, and
//! new firmware appears without warning. So:
//!
//! * unknown enum discriminants decode to an `Unknown(u8)` variant instead of
//!   failing,
//! * unknown flag bits are preserved rather than rejected,
//! * trailing bytes past the fields we understand are ignored.
//!
//! A packet is only rejected when it is too short for a field we need, or when
//! it does not carry the Pro DJ Link magic at all.

#[macro_use]
mod tolerant;

pub mod beat;
pub mod flags;
pub mod keepalive;
pub mod status;

pub use beat::{BeatBody, BeatDistances, BeatPacket, BeatType, FaderStartCommand};
pub use flags::{StateFlags, StatusFeatureFlags};
pub use keepalive::{
    DeviceType, KeepAliveBody, KeepAlivePacket, KeepAliveType, PlayerNumberAssignment,
};
pub use status::{
    ActivityIndicator, BpmSource, CdjStatus, DjmStatus, MediaInfo, PlayState, PlayerSlot,
    StatusBody, StatusPacket, StatusType, StorageIndicator, TrackAnalyzeType,
};

use crate::adapter::Channel;
use crate::error::CodecError;

/// Any packet this library understands, tagged by the channel it arrived on.
///
/// The channel is not redundant with the packet contents: all three channels
/// share the same ten-byte magic prefix and their type bytes overlap. `0x02`
/// means "IP claim" on the announce channel but "fader start" on the beat
/// channel, so the channel is the only thing that disambiguates them.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Packet {
    /// From UDP 50000.
    KeepAlive(KeepAlivePacket),
    /// From UDP 50001.
    Beat(BeatPacket),
    /// From UDP 50002.
    Status(StatusPacket),
}

impl Packet {
    /// Decodes a datagram received on `channel`.
    pub fn decode(channel: Channel, payload: &[u8]) -> Result<Self, CodecError> {
        match channel {
            Channel::Announce => KeepAlivePacket::decode(payload).map(Packet::KeepAlive),
            Channel::Beat => BeatPacket::decode(payload).map(Packet::Beat),
            Channel::Status => StatusPacket::decode(payload).map(Packet::Status),
        }
    }

    /// Encodes into `out`, returning the number of bytes written and the
    /// channel the result must be sent on.
    pub fn encode(&self, out: &mut [u8]) -> Result<(Channel, usize), CodecError> {
        match self {
            Packet::KeepAlive(packet) => packet.encode(out).map(|len| (Channel::Announce, len)),
            Packet::Beat(packet) => packet.encode(out).map(|len| (Channel::Beat, len)),
            Packet::Status(packet) => packet.encode(out).map(|len| (Channel::Status, len)),
        }
    }

    /// The channel this packet belongs on.
    pub fn channel(&self) -> Channel {
        match self {
            Packet::KeepAlive(_) => Channel::Announce,
            Packet::Beat(_) => Channel::Beat,
            Packet::Status(_) => Channel::Status,
        }
    }
}
