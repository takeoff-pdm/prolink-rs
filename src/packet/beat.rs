//! Beat-channel packets: UDP port 50001.
//!
//! Players broadcast a beat packet on every downbeat, carrying the tempo and —
//! more usefully — the number of milliseconds until each of the next several
//! beats and bars. That is what makes it possible to stay in time with a deck
//! without sampling its position continuously.
//!
//! Mixers use the same channel for on-air state and fader-start commands.
//!
//! # Layout
//!
//! The 36-byte header differs from the announce channel's: there is no padding
//! byte after the type, and the model field starts two bytes earlier.
//!
//! ```text
//! 0x00  10  magic "Qspt1WmJOL"
//! 0x0a   1  packet type
//! 0x0b  20  model name, NUL-padded ASCII
//! 0x1f   2  device kind (0x0100 for players, 0x0101 for rekordbox)
//! 0x21   1  player number
//! 0x22   1  padding
//! 0x23   1  subtype
//! 0x24  ..  body, varying by packet type
//! ```

use crate::constants::MODEL_LEN;
use crate::error::CodecError;
use crate::wire::{Bpm, FixedStr, Pitch, ReadCursor, WriteCursor};

/// Offset at which every beat body begins.
const HEADER_LEN: usize = 0x24;

/// The device-kind value players send.
pub const DEVICE_KIND_PLAYER: u16 = 0x0100;

/// The device-kind value rekordbox sends.
pub const DEVICE_KIND_REKORDBOX: u16 = 0x0101;

tolerant_enum! {
    /// What a beat-channel packet carries.
    pub enum BeatType {
        /// A mixer's fader-start command.
        FaderStart = 0x02,
        /// A mixer reporting which channels are live.
        MixerOnAir = 0x03,
        /// An undocumented packet from the DJM-900NXS2.
        MixerUnknown = 0x04,
        /// A CDJ-3000's precise playhead position.
        AbsolutePosition = 0x0b,
        /// The beat itself.
        Beat = 0x28,
    }
}

tolerant_enum! {
    /// What a mixer is telling a player to do when its fader moves.
    pub enum FaderStartCommand {
        /// Start playing.
        Start = 0,
        /// Stop playing.
        Stop = 1,
        /// Leave this player alone.
        Ignore = 2,
    }
}

/// The conventional subtype byte for each packet type.
const fn conventional_subtype(packet_type: BeatType) -> u8 {
    match packet_type {
        BeatType::Beat => 0x3c,
        BeatType::MixerOnAir => 0x09,
        BeatType::MixerUnknown => 0x40,
        BeatType::FaderStart => 0x04,
        // The CDJ-3000 absolute-position packet's subtype is its body length.
        BeatType::AbsolutePosition => 0x18,
        BeatType::Unknown(_) => 0,
    }
}

/// Milliseconds from now until each upcoming beat and bar.
///
/// This is the field that makes the beat channel worth listening to: it lets a
/// listener schedule against future beats instead of reacting to past ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BeatDistances {
    /// Until the next beat.
    pub next_beat: u32,
    /// Until the beat after that.
    pub second_beat: u32,
    /// Until the next bar line.
    pub next_bar: u32,
    /// Until the fourth beat from now.
    pub fourth_beat: u32,
    /// Until the bar line after next.
    pub second_bar: u32,
    /// Until the eighth beat from now.
    pub eighth_beat: u32,
}

/// The part of a beat-channel packet that varies by type.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum BeatBody {
    /// Type `0x28`. A player crossing a beat.
    Beat {
        /// Time until each upcoming beat and bar.
        distances: BeatDistances,
        /// The deck's current pitch.
        pitch: Pitch,
        /// The effective tempo, or `None` if the track has no known tempo.
        bpm: Option<Bpm>,
        /// Which beat of the bar this is, 1 through 4.
        beat: u8,
        /// The sender's player number, repeated at the end of the packet.
        player_number: u8,
    },

    /// Type `0x0b`. A CDJ-3000 reporting exactly where its playhead is.
    AbsolutePosition {
        /// Track length in milliseconds, rounded to the nearest second.
        track_length_ms: u32,
        /// Playhead position in milliseconds.
        playhead_ms: u32,
        /// Pitch, scaled by 100. See [`pitch_percent`].
        ///
        /// [`pitch_percent`]: BeatBody::pitch_percent
        pitch_raw: u32,
        /// Tempo, scaled by 10. See [`absolute_bpm`].
        ///
        /// [`absolute_bpm`]: BeatBody::absolute_bpm
        bpm_raw: u32,
    },

    /// Type `0x03`. Which mixer channels are routed to the live output.
    ///
    /// Each entry is the player number occupying that channel, or `0` if the
    /// channel is not on air.
    MixerOnAir {
        /// One entry per mixer channel.
        channels: [u8; 4],
    },

    /// Type `0x04`. Undocumented; sent by the DJM-900NXS2.
    MixerUnknown {
        /// Counts up through `0x14`, `0x24`, `0x34`, `0x44`.
        counter: u8,
        /// The sender's player number.
        player_number: u8,
    },

    /// Type `0x02`. A mixer telling players to start or stop with the fader.
    FaderStart {
        /// One command per mixer channel.
        commands: [FaderStartCommand; 4],
    },

    /// A packet type this library does not model.
    Unknown,
}

impl BeatBody {
    /// The packet type this body belongs to.
    pub const fn packet_type(&self) -> BeatType {
        match self {
            BeatBody::Beat { .. } => BeatType::Beat,
            BeatBody::AbsolutePosition { .. } => BeatType::AbsolutePosition,
            BeatBody::MixerOnAir { .. } => BeatType::MixerOnAir,
            BeatBody::MixerUnknown { .. } => BeatType::MixerUnknown,
            BeatBody::FaderStart { .. } => BeatType::FaderStart,
            BeatBody::Unknown => BeatType::Unknown(0),
        }
    }

    /// Tempo from an [`AbsolutePosition`] body, which uses its own scaling.
    ///
    /// [`AbsolutePosition`]: BeatBody::AbsolutePosition
    pub fn absolute_bpm(&self) -> Option<Bpm> {
        match self {
            BeatBody::AbsolutePosition { bpm_raw, .. } => Some(Bpm(*bpm_raw as f32 / 10.0)),
            _ => None,
        }
    }

    /// Pitch from an [`AbsolutePosition`] body, as a percentage.
    ///
    /// The scaling here is inferred from the reference implementations rather
    /// than confirmed against hardware; treat it as approximate until it has
    /// been checked against a CDJ-3000 capture.
    ///
    /// [`AbsolutePosition`]: BeatBody::AbsolutePosition
    pub fn pitch_percent(&self) -> Option<f32> {
        match self {
            BeatBody::AbsolutePosition { pitch_raw, .. } => Some(*pitch_raw as f32 / 100.0),
            _ => None,
        }
    }
}

/// A packet from UDP port 50001.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BeatPacket {
    /// The sender's model name.
    pub model: FixedStr<MODEL_LEN>,
    /// `0x0100` for players, `0x0101` for rekordbox.
    pub device_kind: u16,
    /// The sender's player number.
    pub player_number: u8,
    /// The raw subtype byte.
    pub subtype: u8,
    /// The type-specific payload.
    pub body: BeatBody,
}

impl BeatPacket {
    /// Builds a packet with the conventional subtype for its body.
    pub fn new(model: FixedStr<MODEL_LEN>, player_number: u8, body: BeatBody) -> Self {
        BeatPacket {
            model,
            device_kind: DEVICE_KIND_PLAYER,
            player_number,
            subtype: conventional_subtype(body.packet_type()),
            body,
        }
    }

    /// The packet type, taken from the body.
    pub const fn packet_type(&self) -> BeatType {
        self.body.packet_type()
    }

    /// Decodes a datagram received on UDP 50001.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(bytes);
        cursor.read_magic()?;

        let packet_type = BeatType::from_u8(cursor.read_u8()?);
        let model = cursor.read_ascii::<MODEL_LEN>(MODEL_LEN, "beat.model")?;
        let device_kind = cursor.read_u16()?;
        let player_number = cursor.read_u8()?;
        cursor.skip(1)?;
        let subtype = cursor.read_u8()?;

        debug_assert_eq!(cursor.position(), HEADER_LEN);

        let body = match packet_type {
            BeatType::Beat => {
                let distances = BeatDistances {
                    next_beat: cursor.read_u32()?,
                    second_beat: cursor.read_u32()?,
                    next_bar: cursor.read_u32()?,
                    fourth_beat: cursor.read_u32()?,
                    second_bar: cursor.read_u32()?,
                    eighth_beat: cursor.read_u32()?,
                };
                cursor.skip(24)?;
                let pitch = cursor.read_pitch()?;
                // Zero except while scratching, when it reads 0xffff.
                cursor.skip(2)?;
                let bpm = cursor.read_bpm()?;
                let beat = cursor.read_u8()?;
                cursor.skip(2)?;
                BeatBody::Beat {
                    distances,
                    pitch,
                    bpm,
                    beat,
                    player_number: cursor.read_u8()?,
                }
            }
            BeatType::AbsolutePosition => BeatBody::AbsolutePosition {
                track_length_ms: cursor.read_u32()?,
                playhead_ms: cursor.read_u32()?,
                pitch_raw: cursor.read_u32()?,
                bpm_raw: {
                    cursor.skip(8)?;
                    cursor.read_u32()?
                },
            },
            BeatType::MixerOnAir => BeatBody::MixerOnAir {
                channels: cursor.read_array::<4>()?,
            },
            BeatType::MixerUnknown => BeatBody::MixerUnknown {
                counter: cursor.read_u8()?,
                player_number: cursor.read_u8()?,
            },
            BeatType::FaderStart => {
                let raw = cursor.read_array::<4>()?;
                BeatBody::FaderStart {
                    commands: raw.map(FaderStartCommand::from_u8),
                }
            }
            BeatType::Unknown(_) => BeatBody::Unknown,
        };

        Ok(BeatPacket {
            model,
            device_kind,
            player_number,
            subtype,
            body,
        })
    }

    /// Encodes into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut cursor = WriteCursor::new(out);
        cursor.write_magic()?;
        cursor.write_u8(self.packet_type().to_u8())?;
        cursor.write_ascii(&self.model, MODEL_LEN, "beat.model")?;
        cursor.write_u16(self.device_kind)?;
        cursor.write_u8(self.player_number)?;
        cursor.write_u8(0)?;
        cursor.write_u8(self.subtype)?;

        match &self.body {
            BeatBody::Beat {
                distances,
                pitch,
                bpm,
                beat,
                player_number,
            } => {
                cursor.write_u32(distances.next_beat)?;
                cursor.write_u32(distances.second_beat)?;
                cursor.write_u32(distances.next_bar)?;
                cursor.write_u32(distances.fourth_beat)?;
                cursor.write_u32(distances.second_bar)?;
                cursor.write_u32(distances.eighth_beat)?;
                cursor.write_zeros(24)?;
                cursor.write_pitch(*pitch)?;
                cursor.write_zeros(2)?;
                cursor.write_bpm(*bpm)?;
                cursor.write_u8(*beat)?;
                cursor.write_zeros(2)?;
                cursor.write_u8(*player_number)?;
            }
            BeatBody::AbsolutePosition {
                track_length_ms,
                playhead_ms,
                pitch_raw,
                bpm_raw,
            } => {
                cursor.write_u32(*track_length_ms)?;
                cursor.write_u32(*playhead_ms)?;
                cursor.write_u32(*pitch_raw)?;
                cursor.write_zeros(8)?;
                cursor.write_u32(*bpm_raw)?;
            }
            BeatBody::MixerOnAir { channels } => cursor.write_bytes(channels)?,
            BeatBody::MixerUnknown {
                counter,
                player_number,
            } => {
                cursor.write_u8(*counter)?;
                cursor.write_u8(*player_number)?;
            }
            BeatBody::FaderStart { commands } => {
                for command in commands {
                    cursor.write_u8(command.to_u8())?;
                }
            }
            BeatBody::Unknown => {
                return Err(CodecError::InvalidField {
                    field: "beat.body",
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

    fn sample_bodies() -> [BeatBody; 5] {
        [
            BeatBody::Beat {
                distances: BeatDistances {
                    next_beat: 468,
                    second_beat: 937,
                    next_bar: 1406,
                    fourth_beat: 1875,
                    second_bar: 3750,
                    eighth_beat: 3750,
                },
                pitch: Pitch::NORMAL,
                bpm: Bpm::from_raw(12800),
                beat: 3,
                player_number: 2,
            },
            BeatBody::AbsolutePosition {
                track_length_ms: 240_000,
                playhead_ms: 61_500,
                pitch_raw: 10_000,
                bpm_raw: 1280,
            },
            BeatBody::MixerOnAir {
                channels: [1, 0, 2, 0],
            },
            BeatBody::MixerUnknown {
                counter: 0x24,
                player_number: 33,
            },
            BeatBody::FaderStart {
                commands: [
                    FaderStartCommand::Start,
                    FaderStartCommand::Stop,
                    FaderStartCommand::Ignore,
                    FaderStartCommand::Ignore,
                ],
            },
        ]
    }

    #[test]
    fn every_body_round_trips() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        for body in sample_bodies() {
            let packet = BeatPacket::new(model(), 2, body);
            let len = packet.encode(&mut buf).unwrap();
            let decoded = BeatPacket::decode(&buf[..len]).unwrap();
            assert_eq!(decoded, packet, "body {body:?}");
        }
    }

    #[test]
    fn a_beat_packet_is_ninety_six_bytes() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let packet = BeatPacket::new(model(), 2, sample_bodies()[0]);
        assert_eq!(packet.encode(&mut buf).unwrap(), 96);
    }

    #[test]
    fn the_beat_body_length_matches_its_subtype() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let packet = BeatPacket::new(model(), 2, sample_bodies()[0]);
        let len = packet.encode(&mut buf).unwrap();
        assert_eq!(len - HEADER_LEN, packet.subtype as usize);
    }

    #[test]
    fn a_track_with_no_tempo_round_trips_as_none() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let BeatBody::Beat { distances, .. } = sample_bodies()[0] else {
            unreachable!()
        };
        let packet = BeatPacket::new(
            model(),
            2,
            BeatBody::Beat {
                distances,
                pitch: Pitch::NORMAL,
                bpm: None,
                beat: 1,
                player_number: 2,
            },
        );
        let len = packet.encode(&mut buf).unwrap();
        let decoded = BeatPacket::decode(&buf[..len]).unwrap();
        assert!(matches!(decoded.body, BeatBody::Beat { bpm: None, .. }));
    }

    #[test]
    fn absolute_position_uses_its_own_tempo_scale() {
        let body = sample_bodies()[1];
        assert_eq!(body.absolute_bpm(), Some(Bpm(128.0)));
        assert_eq!(body.pitch_percent(), Some(100.0));
        // The normal beat body does not answer these.
        assert_eq!(sample_bodies()[0].absolute_bpm(), None);
    }

    #[test]
    fn unknown_fader_start_commands_survive() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let packet = BeatPacket::new(
            model(),
            33,
            BeatBody::FaderStart {
                commands: [FaderStartCommand::Unknown(9); 4],
            },
        );
        let len = packet.encode(&mut buf).unwrap();
        let decoded = BeatPacket::decode(&buf[..len]).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn unknown_packet_types_decode_the_header_and_stop() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let packet = BeatPacket::new(model(), 2, sample_bodies()[0]);
        let len = packet.encode(&mut buf).unwrap();
        buf[10] = 0x7f;

        let decoded = BeatPacket::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.player_number, 2);
        assert_eq!(decoded.body, BeatBody::Unknown);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let packet = BeatPacket::new(model(), 2, sample_bodies()[0]);
        let len = packet.encode(&mut buf).unwrap();
        buf[3] = b'X';
        assert_eq!(
            BeatPacket::decode(&buf[..len]),
            Err(CodecError::InvalidMagic)
        );
    }

    #[test]
    fn no_truncation_panics_or_silently_succeeds() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        for body in sample_bodies() {
            let packet = BeatPacket::new(model(), 2, body);
            let len = packet.encode(&mut buf).unwrap();
            for n in 0..len {
                assert!(
                    BeatPacket::decode(&buf[..n]).is_err(),
                    "{body:?} truncated to {n} of {len} bytes decoded successfully"
                );
            }
        }
    }
}
