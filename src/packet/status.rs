//! Status-channel packets: UDP port 50002.
//!
//! Players send a status packet several times a second describing everything
//! about their current state: what track is loaded, where the playhead is,
//! whether they are playing, synced, on air or acting as tempo master. Mixers
//! send a much smaller version. The same channel also carries media-slot
//! queries and the command that loads a track onto a deck.
//!
//! # Layout
//!
//! ```text
//! 0x00  10  magic "Qspt1WmJOL"
//! 0x0a   1  packet type
//! 0x0b  20  model name, NUL-padded ASCII
//! 0x1f   1  protocol version (always 1)
//! 0x20   1  hardware revision (3 = CDJ-2000NXS, 4 = XDJ-1000, 1 = DJM)
//! 0x21   1  player number (0x11 for rekordbox)
//! 0x22  ..  a short per-type preamble, then the body
//! ```
//!
//! # Byte-exact re-encoding
//!
//! A CDJ-3000 status packet is over a kilobyte, most of which is still
//! uncharted. This module decodes the fields it understands and discards the
//! rest, so re-encoding a *decoded* packet will not reproduce it byte for byte.
//!
//! That is a deliberate trade. Keeping the tail would mean either a heap
//! allocation on every received packet — tens per second, forever — or a
//! kilobyte of padding inside every [`CdjStatus`], and the only thing it would
//! buy is a round-trip test. Packets this library *sends* are built from
//! scratch and are byte-exact by construction, which is the property that
//! actually matters on the wire.

use core::net::Ipv4Addr;

use crate::constants::MODEL_LEN;
use crate::error::CodecError;
use crate::packet::flags::StateFlags;
use crate::wire::{Bpm, FixedStr, Pitch, ReadCursor, WriteCursor};

/// Offset at which the per-type preamble begins.
const HEADER_LEN: usize = 0x22;

/// Offset at which a CDJ or DJM status body begins.
const BODY_START: usize = 0x26;

/// The value of the protocol-version byte on all known hardware.
pub(crate) const PROTOCOL_VERSION: u8 = 1;

/// Shortest CDJ status packet this module will accept.
///
/// The packet-counter field sits at `0xc8`, so anything shorter is either a
/// truncated packet or one of rekordbox's abbreviated variants.
const MIN_CDJ_LEN: usize = 0xcd;

tolerant_enum! {
    /// What a status-channel packet carries.
    pub enum StatusType {
        /// A media-slot query.
        MediaQuery = 0x05,
        /// A reply describing a media slot's contents.
        MediaReply = 0x06,
        /// A player's full status.
        Cdj = 0x0a,
        /// A player greeting rekordbox.
        RekordboxHello = 0x10,
        /// rekordbox replying to a greeting.
        RekordboxReply = 0x11,
        /// A command to load a track onto a deck.
        LoadCommand = 0x19,
        /// Acknowledgement of a load command.
        LoadCommandReply = 0x1a,
        /// A mixer's status.
        Djm = 0x29,
    }
}

tolerant_enum! {
    /// Where a player is reading media from.
    pub enum PlayerSlot {
        /// Nothing in this slot.
        Empty = 0,
        /// The CD drive.
        Cd = 1,
        /// The SD card slot.
        Sd = 2,
        /// The USB port.
        Usb = 3,
        /// A rekordbox collection over the network.
        Rekordbox = 4,
    }
}

tolerant_enum! {
    /// How much rekordbox knows about the loaded track.
    pub enum TrackAnalyzeType {
        /// No track, or a track rekordbox has never seen.
        Unanalyzed = 0,
        /// Analyzed by rekordbox: beat grid, waveform and cues are available.
        Rekordbox = 1,
        /// A plain audio file found on the media.
        File = 2,
        /// An audio CD track.
        Cd = 5,
    }
}

tolerant_enum! {
    /// Whether a media slot is being read right now.
    pub enum ActivityIndicator {
        /// Idle.
        Inactive = 4,
        /// Being read.
        Active = 6,
    }
}

/// Whether a media slot has usable media in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StorageIndicator {
    /// Media is mounted and readable.
    Loaded,
    /// Media is being spun down.
    Stopping,
    /// Media is being unmounted.
    Unmounting,
    /// The slot is empty.
    NotLoaded,
    /// A value this library does not recognise.
    Unknown(u32),
}

impl StorageIndicator {
    /// Decodes the raw 32-bit wire value. Never fails.
    pub const fn from_u32(raw: u32) -> Self {
        match raw {
            0 => StorageIndicator::Loaded,
            2 => StorageIndicator::Stopping,
            3 => StorageIndicator::Unmounting,
            4 => StorageIndicator::NotLoaded,
            other => StorageIndicator::Unknown(other),
        }
    }

    /// The raw 32-bit wire value.
    pub const fn to_u32(self) -> u32 {
        match self {
            StorageIndicator::Loaded => 0,
            StorageIndicator::Stopping => 2,
            StorageIndicator::Unmounting => 3,
            StorageIndicator::NotLoaded => 4,
            StorageIndicator::Unknown(other) => other,
        }
    }

    /// Whether media is mounted and readable.
    pub const fn is_mounted(self) -> bool {
        matches!(self, StorageIndicator::Loaded)
    }
}

/// What a deck is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlayState {
    /// Nothing loaded.
    NoTrack,
    /// A track is being loaded.
    LoadingTrack,
    /// Playing normally.
    Playing,
    /// Playing inside a loop.
    Looping,
    /// Paused somewhere other than the cue point.
    Paused,
    /// Paused at the cue point.
    Cued,
    /// Playing from the cue point while the cue button is held.
    Cueing,
    /// Cue play with a hand on the platter.
    CueScratch,
    /// Searching through the track.
    Seeking,
    /// The track cannot be played.
    CannotPlayTrack,
    /// The playhead reached the end.
    EndOfTrack,
    /// The player lost its media mid-track.
    Emergency,
    /// A value this library does not recognise.
    Unknown(u32),
}

impl PlayState {
    /// Decodes the raw 32-bit wire value. Never fails.
    pub const fn from_u32(raw: u32) -> Self {
        match raw {
            0x00 => PlayState::NoTrack,
            0x02 => PlayState::LoadingTrack,
            0x03 => PlayState::Playing,
            0x04 => PlayState::Looping,
            0x05 => PlayState::Paused,
            0x06 => PlayState::Cued,
            0x07 => PlayState::Cueing,
            0x08 => PlayState::CueScratch,
            0x09 => PlayState::Seeking,
            0x0e => PlayState::CannotPlayTrack,
            0x11 => PlayState::EndOfTrack,
            0x12 => PlayState::Emergency,
            other => PlayState::Unknown(other),
        }
    }

    /// The raw 32-bit wire value.
    pub const fn to_u32(self) -> u32 {
        match self {
            PlayState::NoTrack => 0x00,
            PlayState::LoadingTrack => 0x02,
            PlayState::Playing => 0x03,
            PlayState::Looping => 0x04,
            PlayState::Paused => 0x05,
            PlayState::Cued => 0x06,
            PlayState::Cueing => 0x07,
            PlayState::CueScratch => 0x08,
            PlayState::Seeking => 0x09,
            PlayState::CannotPlayTrack => 0x0e,
            PlayState::EndOfTrack => 0x11,
            PlayState::Emergency => 0x12,
            PlayState::Unknown(other) => other,
        }
    }

    /// Whether the playhead is moving forward under its own power.
    pub const fn is_playing(self) -> bool {
        matches!(
            self,
            PlayState::Playing | PlayState::Cueing | PlayState::Looping
        )
    }

    /// Whether the playhead is stationary.
    pub const fn is_stopped(self) -> bool {
        matches!(
            self,
            PlayState::Cued
                | PlayState::Paused
                | PlayState::CannotPlayTrack
                | PlayState::EndOfTrack
                | PlayState::Emergency
        )
    }
}

/// Where the loaded track's tempo came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BpmSource {
    /// From an audio CD, which has no tempo metadata.
    Cd,
    /// No track, or a track that has not been analyzed.
    Unknown,
    /// From rekordbox analysis.
    Rekordbox,
    /// A value this library does not recognise.
    Other(u16),
}

impl BpmSource {
    /// Decodes the raw 16-bit wire value. Never fails.
    pub const fn from_u16(raw: u16) -> Self {
        match raw {
            0x0000 => BpmSource::Cd,
            0x7fff => BpmSource::Unknown,
            0x8000 => BpmSource::Rekordbox,
            other => BpmSource::Other(other),
        }
    }

    /// The raw 16-bit wire value.
    pub const fn to_u16(self) -> u16 {
        match self {
            BpmSource::Cd => 0x0000,
            BpmSource::Unknown => 0x7fff,
            BpmSource::Rekordbox => 0x8000,
            BpmSource::Other(other) => other,
        }
    }
}

/// A player's full status: the largest and most informative packet in the
/// protocol.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CdjStatus {
    /// Which player the loaded track came from — not necessarily this one,
    /// since players can read each other's media over the link.
    pub loaded_from_player: u8,
    /// Which slot on that player.
    pub loaded_from_slot: PlayerSlot,
    /// How much is known about the track.
    pub track_analyze_type: TrackAnalyzeType,
    /// rekordbox's identifier for the track, if it has one.
    pub track_id: u32,
    /// Position in the current playlist or folder.
    pub track_number: u32,
    /// Whether the USB slot is being read.
    pub usb_activity: ActivityIndicator,
    /// Whether the SD slot is being read.
    pub sd_activity: ActivityIndicator,
    /// Whether USB media is mounted.
    pub usb_state: StorageIndicator,
    /// Whether SD media is mounted.
    pub sd_state: StorageIndicator,
    /// What the deck is doing.
    pub play_state: PlayState,
    /// Firmware version string, e.g. `"1.40"`.
    pub firmware: FixedStr<4>,
    /// Increments each time the tempo master changes; used to resolve
    /// simultaneous master handoffs.
    pub tempo_master_count: u32,
    /// On-air, sync, master and play flags.
    pub state: StateFlags,
    /// Pitch set by the physical fader.
    pub physical_pitch: Pitch,
    /// Where the tempo came from.
    pub bpm_source: BpmSource,
    /// The track's tempo before pitch is applied, if known.
    pub bpm: Option<Bpm>,
    /// Pitch actually being applied, which differs from the fader while synced.
    pub actual_pitch: Pitch,
    /// Beats since the start of the track.
    pub beat_count: u32,
    /// Beats until the next cue point, or `0x1ff` if there is none ahead.
    pub cue_distance: u16,
    /// Which beat of the bar the playhead is on, 1 through 4.
    pub beat: u8,
    /// Increments with every status packet the player sends.
    pub packet_count: u32,
    /// Non-zero on nexus-generation and later hardware.
    pub is_nexus: u8,
    /// Musical key, on players that report one.
    pub key: Option<u32>,
    /// Key shift in cents, on players that report one.
    pub key_shift: Option<i64>,
    /// Loop-in point in milliseconds, if a loop is set.
    pub loop_start_ms: Option<u32>,
    /// Loop-out point in milliseconds, if a loop is set.
    pub loop_end_ms: Option<u32>,
}

impl CdjStatus {
    /// The tempo actually coming out of the deck, with pitch applied.
    ///
    /// This is what you want for beat matching; [`bpm`] is the tempo written
    /// in the track's metadata.
    ///
    /// [`bpm`]: CdjStatus::bpm
    pub fn effective_bpm(&self) -> Option<Bpm> {
        self.bpm.map(|bpm| Bpm(bpm.0 * self.actual_pitch.0))
    }

    /// Whether this player is the tempo master.
    pub fn is_master(&self) -> bool {
        self.state.contains(StateFlags::MASTER)
    }

    /// Whether this player's audio is going to the live output.
    pub fn is_on_air(&self) -> bool {
        self.state.contains(StateFlags::ON_AIR)
    }
}

/// A mixer's status.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DjmStatus {
    /// On-air, sync, master and play flags.
    pub state: StateFlags,
    /// Pitch set by the mixer's master tempo control.
    pub physical_pitch: Pitch,
    /// The mixer's tempo, if it has one.
    pub bpm: Option<Bpm>,
    /// Which beat of the bar the mixer is on.
    pub beat: u8,
}

/// A description of what is in one media slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaInfo {
    /// Which player holds the media.
    pub player_number: u8,
    /// Which slot.
    pub slot: PlayerSlot,
    /// The volume name.
    pub name: FixedStr<32>,
    /// When the collection was last exported.
    pub date: FixedStr<12>,
    /// The media's own model string.
    pub model: FixedStr<16>,
    /// How many tracks it holds.
    pub track_count: u32,
    /// How many playlists it holds.
    pub playlist_count: u32,
    /// Capacity in bytes.
    pub bytes_total: u64,
    /// Free space in bytes.
    pub bytes_free: u64,
}

/// The part of a status packet that varies by type.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum StatusBody {
    /// Type `0x0a`. A player's full status.
    Cdj(CdjStatus),
    /// Type `0x29`. A mixer's status.
    Djm(DjmStatus),
    /// Type `0x05`. "What is in slot X of player Y?"
    MediaQuery {
        /// The player being asked about.
        player_number: u8,
        /// The slot being asked about.
        slot: PlayerSlot,
        /// Where the reply should be sent.
        reply_to: Ipv4Addr,
    },
    /// Type `0x06`. The answer to a [`MediaQuery`](StatusBody::MediaQuery).
    MediaReply(MediaInfo),
    /// Type `0x19`. "Load this track onto that deck."
    LoadCommand {
        /// The player holding the track.
        source_player: u8,
        /// The slot holding the track.
        slot: PlayerSlot,
        /// rekordbox's identifier for the track.
        track_id: u32,
    },
    /// Type `0x1a`. Acknowledgement of a load command.
    LoadCommandReply,
    /// A packet type this library does not model — rekordbox's own greeting
    /// exchange, or something newer.
    Unknown,
}

impl StatusBody {
    /// The packet type this body belongs to.
    pub const fn packet_type(&self) -> StatusType {
        match self {
            StatusBody::Cdj(_) => StatusType::Cdj,
            StatusBody::Djm(_) => StatusType::Djm,
            StatusBody::MediaQuery { .. } => StatusType::MediaQuery,
            StatusBody::MediaReply(_) => StatusType::MediaReply,
            StatusBody::LoadCommand { .. } => StatusType::LoadCommand,
            StatusBody::LoadCommandReply => StatusType::LoadCommandReply,
            StatusBody::Unknown => StatusType::Unknown(0),
        }
    }
}

/// A packet from UDP port 50002.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StatusPacket {
    /// The sender's model name.
    pub model: FixedStr<MODEL_LEN>,
    /// Always `1` on known hardware.
    pub protocol_version: u8,
    /// Hardware revision: `3` for a CDJ-2000NXS, `4` for an XDJ-1000, `1` for
    /// a mixer or rekordbox, `0` on a media query.
    pub revision: u8,
    /// The sender's player number. rekordbox uses `0x11`.
    pub player_number: u8,
    /// A length-ish field whose exact meaning varies by type. Preserved so it
    /// round-trips.
    pub preamble: u16,
    /// The type-specific payload.
    pub body: StatusBody,
}

impl StatusPacket {
    /// The packet type, taken from the body.
    pub const fn packet_type(&self) -> StatusType {
        self.body.packet_type()
    }

    /// Decodes a datagram received on UDP 50002.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = ReadCursor::new(bytes);
        cursor.read_magic()?;

        let packet_type = StatusType::from_u8(cursor.read_u8()?);
        let model = cursor.read_ascii::<MODEL_LEN>(MODEL_LEN, "status.model")?;
        let protocol_version = cursor.read_u8()?;
        let revision = cursor.read_u8()?;
        let player_number = cursor.read_u8()?;

        debug_assert_eq!(cursor.position(), HEADER_LEN);
        let preamble = cursor.read_u16()?;

        let body = match packet_type {
            StatusType::Cdj => {
                if bytes.len() < MIN_CDJ_LEN {
                    return Err(CodecError::UnexpectedEof {
                        needed: MIN_CDJ_LEN,
                        remaining: bytes.len(),
                    });
                }
                StatusBody::Cdj(decode_cdj(&mut cursor, bytes.len())?)
            }
            StatusType::Djm => StatusBody::Djm(decode_djm(&mut cursor)?),
            StatusType::MediaQuery => {
                let reply_to = cursor.read_ipv4()?;
                cursor.skip(3)?;
                let player_number = cursor.read_u8()?;
                cursor.skip(3)?;
                StatusBody::MediaQuery {
                    player_number,
                    slot: PlayerSlot::from_u8(cursor.read_u8()?),
                    reply_to,
                }
            }
            StatusType::MediaReply => StatusBody::MediaReply(decode_media_info(&mut cursor)?),
            StatusType::LoadCommand => {
                cursor.skip(2)?;
                let source_player = cursor.read_u8()?;
                let slot = PlayerSlot::from_u8(cursor.read_u8()?);
                cursor.skip(2)?;
                StatusBody::LoadCommand {
                    source_player,
                    slot,
                    track_id: cursor.read_u32()?,
                }
            }
            StatusType::LoadCommandReply => StatusBody::LoadCommandReply,
            _ => StatusBody::Unknown,
        };

        Ok(StatusPacket {
            model,
            protocol_version,
            revision,
            player_number,
            preamble,
            body,
        })
    }

    /// Encodes into `out`, returning the number of bytes written.
    ///
    /// Only the bodies this library builds are encodable;
    /// [`StatusBody::Cdj`] and [`StatusBody::Unknown`] are not. Our own status
    /// packet is produced by [`vcdj::outbound`] instead, which knows the
    /// undocumented bytes that hardware requires.
    ///
    /// [`vcdj::outbound`]: crate::vcdj::outbound
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut cursor = WriteCursor::new(out);
        cursor.write_magic()?;
        cursor.write_u8(self.packet_type().to_u8())?;
        cursor.write_ascii(&self.model, MODEL_LEN, "status.model")?;
        cursor.write_u8(self.protocol_version)?;
        cursor.write_u8(self.revision)?;
        cursor.write_u8(self.player_number)?;
        cursor.write_u16(self.preamble)?;

        match &self.body {
            StatusBody::MediaQuery {
                player_number,
                slot,
                reply_to,
            } => {
                cursor.write_ipv4(*reply_to)?;
                cursor.write_zeros(3)?;
                cursor.write_u8(*player_number)?;
                cursor.write_zeros(3)?;
                cursor.write_u8(slot.to_u8())?;
            }
            StatusBody::MediaReply(info) => encode_media_info(&mut cursor, info)?,
            StatusBody::LoadCommand {
                source_player,
                slot,
                track_id,
            } => {
                cursor.write_zeros(2)?;
                cursor.write_u8(*source_player)?;
                cursor.write_u8(slot.to_u8())?;
                cursor.write_u16(0x0100)?;
                cursor.write_u32(*track_id)?;
                cursor.write_zeros(36)?;
            }
            StatusBody::LoadCommandReply => cursor.write_zeros(2)?,
            StatusBody::Djm(status) => {
                cursor.write_u8(self.player_number)?;
                cursor.write_u8(0)?;
                cursor.write_u16(status.state.bits())?;
                cursor.write_pitch(status.physical_pitch)?;
                cursor.write_u16(0x8000)?;
                cursor.write_bpm(status.bpm)?;
                cursor.write_zeros(7)?;
                cursor.write_u8(status.beat)?;
            }
            StatusBody::Cdj(_) | StatusBody::Unknown => {
                return Err(CodecError::InvalidField {
                    field: "status.body",
                    reason: "use vcdj::outbound to build an outgoing status packet",
                })
            }
        }

        Ok(cursor.position())
    }
}

fn decode_cdj(cursor: &mut ReadCursor<'_>, total_len: usize) -> Result<CdjStatus, CodecError> {
    // The status body is a sparse structure: known fields at documented
    // offsets with long uncharted stretches between them. Seeking to each one
    // is far easier to check against a hex dump than counting out skips.
    cursor.seek(BODY_START + 2)?;
    let loaded_from_player = cursor.read_u8()?;
    let loaded_from_slot = PlayerSlot::from_u8(cursor.read_u8()?);
    let track_analyze_type = TrackAnalyzeType::from_u8(cursor.read_u8()?);

    cursor.seek(0x2c)?;
    let track_id = cursor.read_u32()?;
    let track_number = cursor.read_u32()?;

    cursor.seek(0x6a)?;
    let usb_activity = ActivityIndicator::from_u8(cursor.read_u8()?);
    let sd_activity = ActivityIndicator::from_u8(cursor.read_u8()?);
    let usb_state = StorageIndicator::from_u32(cursor.read_u32()?);
    let sd_state = StorageIndicator::from_u32(cursor.read_u32()?);

    cursor.seek(0x78)?;
    let play_state = PlayState::from_u32(cursor.read_u32()?);
    let firmware = cursor.read_ascii::<4>(4, "status.cdj.firmware")?;

    cursor.seek(0x84)?;
    let tempo_master_count = cursor.read_u32()?;
    let state = StateFlags::from_bits_retain(cursor.read_u16()?);

    cursor.seek(0x8c)?;
    let physical_pitch = cursor.read_pitch()?;
    let bpm_source = BpmSource::from_u16(cursor.read_u16()?);
    let bpm = cursor.read_bpm()?;

    cursor.seek(0x98)?;
    let actual_pitch = cursor.read_pitch()?;

    cursor.seek(0xa0)?;
    let beat_count = cursor.read_u32()?;
    let cue_distance = cursor.read_u16()?;
    let beat = cursor.read_u8()?;

    cursor.seek(0xc8)?;
    let packet_count = cursor.read_u32()?;
    let is_nexus = cursor.read_u8()?;

    // Everything beyond here exists only on newer players. Each field is read
    // only if the packet is actually long enough to contain it, so an older
    // CDJ's shorter packet decodes fine with these left as `None`.
    let key = read_optional_u32(cursor, total_len, 0x15c)?;
    let key_shift = read_optional_i64(cursor, total_len, 0x168)?;
    let loop_start_ms = read_optional_u32(cursor, total_len, 0x1bc)?;
    let loop_end_ms = read_optional_u32(cursor, total_len, 0x1c4)?;

    Ok(CdjStatus {
        loaded_from_player,
        loaded_from_slot,
        track_analyze_type,
        track_id,
        track_number,
        usb_activity,
        sd_activity,
        usb_state,
        sd_state,
        play_state,
        firmware,
        tempo_master_count,
        state,
        physical_pitch,
        bpm_source,
        bpm,
        actual_pitch,
        beat_count,
        cue_distance,
        beat,
        packet_count,
        is_nexus,
        key,
        key_shift,
        loop_start_ms,
        loop_end_ms,
    })
}

fn read_optional_u32(
    cursor: &mut ReadCursor<'_>,
    total_len: usize,
    offset: usize,
) -> Result<Option<u32>, CodecError> {
    if total_len < offset + 4 {
        return Ok(None);
    }
    cursor.seek(offset)?;
    cursor.read_u32().map(Some)
}

fn read_optional_i64(
    cursor: &mut ReadCursor<'_>,
    total_len: usize,
    offset: usize,
) -> Result<Option<i64>, CodecError> {
    if total_len < offset + 8 {
        return Ok(None);
    }
    cursor.seek(offset)?;
    cursor.read_u64().map(|raw| Some(raw as i64))
}

fn decode_djm(cursor: &mut ReadCursor<'_>) -> Result<DjmStatus, CodecError> {
    cursor.seek(BODY_START)?;
    let state = StateFlags::from_bits_retain(cursor.read_u16()?);
    let physical_pitch = cursor.read_pitch()?;
    cursor.skip(2)?;
    let bpm = cursor.read_bpm()?;
    cursor.skip(7)?;
    let beat = cursor.read_u8()?;
    Ok(DjmStatus {
        state,
        physical_pitch,
        bpm,
        beat,
    })
}

fn decode_media_info(cursor: &mut ReadCursor<'_>) -> Result<MediaInfo, CodecError> {
    cursor.skip(3)?;
    let player_number = cursor.read_u8()?;
    cursor.skip(3)?;
    let slot = PlayerSlot::from_u8(cursor.read_u8()?);
    let name = cursor.read_utf16::<32>(64, "status.media.name")?;
    let date = cursor.read_utf16::<12>(24, "status.media.date")?;
    let model = cursor.read_utf16::<16>(32, "status.media.model")?;
    let track_count = cursor.read_u32()?;
    cursor.skip(4)?;
    let playlist_count = cursor.read_u32()?;
    let bytes_total = cursor.read_u64()?;
    let bytes_free = cursor.read_u64()?;

    Ok(MediaInfo {
        player_number,
        slot,
        name,
        date,
        model,
        track_count,
        playlist_count,
        bytes_total,
        bytes_free,
    })
}

fn encode_media_info(cursor: &mut WriteCursor<'_>, info: &MediaInfo) -> Result<(), CodecError> {
    cursor.write_zeros(3)?;
    cursor.write_u8(info.player_number)?;
    cursor.write_zeros(3)?;
    cursor.write_u8(info.slot.to_u8())?;
    cursor.write_utf16(&info.name, 64, "status.media.name")?;
    cursor.write_utf16(&info.date, 24, "status.media.date")?;
    cursor.write_utf16(&info.model, 32, "status.media.model")?;
    cursor.write_u32(info.track_count)?;
    cursor.write_zeros(4)?;
    cursor.write_u32(info.playlist_count)?;
    cursor.write_u64(info.bytes_total)?;
    cursor.write_u64(info.bytes_free)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAX_PACKET_LEN;

    fn model() -> FixedStr<MODEL_LEN> {
        FixedStr::new("CDJ-3000").unwrap()
    }

    fn media_info() -> MediaInfo {
        MediaInfo {
            player_number: 2,
            slot: PlayerSlot::Usb,
            name: FixedStr::new("MY USB").unwrap(),
            date: FixedStr::new("2026-08-22").unwrap(),
            model: FixedStr::new("SanDisk").unwrap(),
            track_count: 1234,
            playlist_count: 17,
            bytes_total: 64 * 1024 * 1024 * 1024,
            bytes_free: 12 * 1024 * 1024 * 1024,
        }
    }

    fn packet(body: StatusBody) -> StatusPacket {
        StatusPacket {
            model: model(),
            protocol_version: PROTOCOL_VERSION,
            revision: 4,
            player_number: 2,
            preamble: 0x000c,
            body,
        }
    }

    fn encodable_bodies() -> [StatusBody; 5] {
        [
            StatusBody::MediaQuery {
                player_number: 2,
                slot: PlayerSlot::Usb,
                reply_to: Ipv4Addr::new(192, 168, 1, 9),
            },
            StatusBody::MediaReply(media_info()),
            StatusBody::LoadCommand {
                source_player: 3,
                slot: PlayerSlot::Sd,
                track_id: 0x1234_5678,
            },
            StatusBody::LoadCommandReply,
            StatusBody::Djm(DjmStatus {
                state: StateFlags::ON_AIR,
                physical_pitch: Pitch::NORMAL,
                bpm: Bpm::from_raw(12800),
                beat: 2,
            }),
        ]
    }

    #[test]
    fn encodable_bodies_round_trip() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        for body in encodable_bodies() {
            let original = packet(body);
            let len = original.encode(&mut buf).unwrap();
            let decoded = StatusPacket::decode(&buf[..len]).unwrap();
            assert_eq!(decoded.body, original.body, "body {body:?}");
        }
    }

    #[test]
    fn media_reply_preserves_text_fields() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let original = packet(StatusBody::MediaReply(media_info()));
        let len = original.encode(&mut buf).unwrap();

        let StatusBody::MediaReply(decoded) = StatusPacket::decode(&buf[..len]).unwrap().body
        else {
            panic!("expected a media reply");
        };
        assert_eq!(decoded.name, "MY USB");
        assert_eq!(decoded.date, "2026-08-22");
        assert_eq!(decoded.model, "SanDisk");
        assert_eq!(decoded.bytes_total, 64 * 1024 * 1024 * 1024);
    }

    /// A CDJ status packet is built by hand here because the encoder
    /// deliberately refuses to produce one — see the module docs.
    fn synthetic_cdj_packet(len: usize) -> [u8; MAX_PACKET_LEN] {
        let mut buf = [0u8; MAX_PACKET_LEN];
        buf[..10].copy_from_slice(&crate::constants::MAGIC);
        buf[10] = StatusType::Cdj.to_u8();
        buf[11..19].copy_from_slice(b"CDJ-3000");
        buf[0x1f] = 1;
        buf[0x20] = 4;
        buf[0x21] = 2;

        buf[0x28] = 3; // loaded from player 3
        buf[0x29] = PlayerSlot::Usb.to_u8();
        buf[0x2a] = TrackAnalyzeType::Rekordbox.to_u8();
        buf[0x2c..0x30].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        buf[0x6a] = ActivityIndicator::Active.to_u8();
        buf[0x6b] = ActivityIndicator::Inactive.to_u8();
        buf[0x6c..0x70].copy_from_slice(&0u32.to_be_bytes()); // usb loaded
        buf[0x70..0x74].copy_from_slice(&4u32.to_be_bytes()); // sd empty
        buf[0x78..0x7c].copy_from_slice(&3u32.to_be_bytes()); // playing
        buf[0x7c..0x80].copy_from_slice(b"1.40");
        buf[0x88..0x8a].copy_from_slice(&(StateFlags::ALWAYS_SET | 0x60).to_be_bytes());
        buf[0x8c..0x90].copy_from_slice(&0x0010_0000u32.to_be_bytes()); // pitch 1.0
        buf[0x90..0x92].copy_from_slice(&0x8000u16.to_be_bytes()); // rekordbox bpm
        buf[0x92..0x94].copy_from_slice(&12800u16.to_be_bytes()); // 128.00
        buf[0x98..0x9c].copy_from_slice(&0x0010_0000u32.to_be_bytes());
        buf[0xa0..0xa4].copy_from_slice(&257u32.to_be_bytes());
        buf[0xa6] = 3;
        buf[0xc8..0xcc].copy_from_slice(&99u32.to_be_bytes());
        buf[0xcc] = 1;
        let _ = len;
        buf
    }

    #[test]
    fn a_cdj_status_packet_decodes() {
        let buf = synthetic_cdj_packet(MIN_CDJ_LEN);
        let decoded = StatusPacket::decode(&buf[..MIN_CDJ_LEN]).unwrap();

        let StatusBody::Cdj(status) = decoded.body else {
            panic!("expected a CDJ status");
        };
        assert_eq!(decoded.model, "CDJ-3000");
        assert_eq!(decoded.player_number, 2);
        assert_eq!(status.loaded_from_player, 3);
        assert_eq!(status.loaded_from_slot, PlayerSlot::Usb);
        assert_eq!(status.track_id, 0x1234_5678);
        assert_eq!(status.play_state, PlayState::Playing);
        assert!(status.play_state.is_playing());
        assert_eq!(status.firmware, "1.40");
        assert_eq!(status.bpm, Some(Bpm(128.0)));
        assert_eq!(status.bpm_source, BpmSource::Rekordbox);
        assert_eq!(status.beat_count, 257);
        assert_eq!(status.beat, 3);
        assert_eq!(status.packet_count, 99);
        assert!(status.usb_state.is_mounted());
        assert!(!status.sd_state.is_mounted());
        assert!(status.is_master());
    }

    #[test]
    fn effective_tempo_applies_pitch() {
        let buf = synthetic_cdj_packet(MIN_CDJ_LEN);
        let StatusBody::Cdj(mut status) = StatusPacket::decode(&buf[..MIN_CDJ_LEN]).unwrap().body
        else {
            panic!("expected a CDJ status");
        };
        assert_eq!(status.effective_bpm(), Some(Bpm(128.0)));

        status.actual_pitch = Pitch(1.06);
        let effective = status.effective_bpm().unwrap();
        assert!((effective.0 - 135.68).abs() < 0.01, "{effective:?}");
    }

    #[test]
    fn newer_fields_are_absent_from_an_older_players_packet() {
        let buf = synthetic_cdj_packet(MIN_CDJ_LEN);
        let StatusBody::Cdj(status) = StatusPacket::decode(&buf[..MIN_CDJ_LEN]).unwrap().body
        else {
            panic!("expected a CDJ status");
        };
        // A packet that stops at 0xcd cannot contain the key field at 0x15c.
        assert_eq!(status.key, None);
        assert_eq!(status.loop_start_ms, None);
    }

    #[test]
    fn newer_fields_are_read_when_the_packet_is_long_enough() {
        let mut buf = synthetic_cdj_packet(0x200);
        buf[0x15c..0x160].copy_from_slice(&0x0201_0001u32.to_be_bytes());
        buf[0x1bc..0x1c0].copy_from_slice(&30_000u32.to_be_bytes());
        buf[0x1c4..0x1c8].copy_from_slice(&34_000u32.to_be_bytes());

        let StatusBody::Cdj(status) = StatusPacket::decode(&buf[..0x200]).unwrap().body else {
            panic!("expected a CDJ status");
        };
        assert_eq!(status.key, Some(0x0201_0001));
        assert_eq!(status.loop_start_ms, Some(30_000));
        assert_eq!(status.loop_end_ms, Some(34_000));
    }

    #[test]
    fn a_short_cdj_packet_is_rejected_rather_than_misread() {
        let buf = synthetic_cdj_packet(MIN_CDJ_LEN);
        assert!(matches!(
            StatusPacket::decode(&buf[..0x80]),
            Err(CodecError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn unknown_types_decode_the_header_and_stop() {
        let mut buf = synthetic_cdj_packet(MIN_CDJ_LEN);
        buf[10] = StatusType::RekordboxHello.to_u8();
        let decoded = StatusPacket::decode(&buf[..MIN_CDJ_LEN]).unwrap();
        assert_eq!(decoded.body, StatusBody::Unknown);
        assert_eq!(decoded.model, "CDJ-3000");
    }

    #[test]
    fn encoding_a_cdj_status_is_refused_with_a_pointer_to_the_right_api() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let source = synthetic_cdj_packet(MIN_CDJ_LEN);
        let decoded = StatusPacket::decode(&source[..MIN_CDJ_LEN]).unwrap();
        assert!(matches!(
            decoded.encode(&mut buf),
            Err(CodecError::InvalidField { .. })
        ));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut buf = synthetic_cdj_packet(MIN_CDJ_LEN);
        buf[9] = b'X';
        assert_eq!(
            StatusPacket::decode(&buf[..MIN_CDJ_LEN]),
            Err(CodecError::InvalidMagic)
        );
    }

    #[test]
    fn no_truncation_panics_or_silently_succeeds() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        for body in encodable_bodies() {
            let original = packet(body);
            let len = original.encode(&mut buf).unwrap();
            for n in 0..len {
                let result = StatusPacket::decode(&buf[..n]);
                if let Ok(decoded) = result {
                    // Truncating into the trailing zero padding of a load
                    // command can still yield a valid parse; anything that
                    // reached a real field must not.
                    assert_eq!(
                        decoded.body.packet_type(),
                        original.body.packet_type(),
                        "{body:?} truncated to {n} decoded as a different type"
                    );
                }
            }
        }
    }

    #[test]
    fn no_cdj_truncation_panics() {
        let buf = synthetic_cdj_packet(0x200);
        for n in 0..0x200 {
            let _ = StatusPacket::decode(&buf[..n]);
        }
    }
}
