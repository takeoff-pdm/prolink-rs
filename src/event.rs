//! What a [`Session`](crate::session::Session) tells you about.

use core::net::Ipv4Addr;

use crate::adapter::Channel;
use crate::constants::MODEL_LEN;
use crate::error::CodecError;
use crate::packet::status::{MediaInfo, PlayerSlot, StorageIndicator};
use crate::packet::{DeviceType, FaderStartCommand};
use crate::vcdj::NegotiationFailure;
use crate::wire::{Bpm, FixedStr, MacAddr, Pitch};

/// Something worth knowing about, produced by [`Session::poll`].
///
/// These are semantic changes, not raw packets. A CDJ sends status several
/// times a second and most of those packets say nothing new; turning each one
/// into an event would bury the two or three that matter. Raw packets remain
/// available through [`Packet::decode`] for anyone who wants them.
///
/// [`Session::poll`]: crate::session::Session::poll
/// [`Packet::decode`]: crate::packet::Packet::decode
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum Event {
    // ---- our own lifecycle -------------------------------------------------
    /// Negotiation finished; we hold a player number and are visible to other
    /// devices.
    Online {
        /// The number we ended up with.
        player_number: u8,
    },

    /// Negotiation failed. The session is inert until
    /// [`start`](crate::session::Session::start) is called again.
    NegotiationFailed(NegotiationFailure),

    /// Someone tried to claim our player number and we pushed back.
    NumberDefended {
        /// The number we are holding.
        player_number: u8,
        /// Who tried to take it.
        challenger: Ipv4Addr,
    },

    // ---- other devices -----------------------------------------------------
    /// A device appeared on the network.
    DeviceAppeared {
        /// Its player number.
        player_number: u8,
        /// What kind of hardware it is.
        device_type: DeviceType,
        /// Its model name.
        model: FixedStr<MODEL_LEN>,
        /// Its address.
        ip: Ipv4Addr,
        /// Its hardware address, if the keepalive carried one.
        mac: Option<MacAddr>,
    },

    /// A known device is now at a different address.
    DeviceReaddressed {
        /// Its player number.
        player_number: u8,
        /// Where it was.
        previous_ip: Ipv4Addr,
        /// Where it is now.
        ip: Ipv4Addr,
    },

    /// A device stopped sending keepalives and has been dropped.
    DeviceLost {
        /// The number it held.
        player_number: u8,
    },

    /// A device appeared but the registry was already full, so it is not being
    /// tracked. [`MAX_DEVICES`](crate::constants::MAX_DEVICES) slots are more
    /// than a real network needs, so this means something unusual.
    RegistryFull {
        /// The number the untracked device claims.
        player_number: u8,
    },

    // ---- realtime ----------------------------------------------------------
    /// A player crossed a beat.
    Beat {
        /// Which player.
        player_number: u8,
        /// Which beat of the bar, 1 through 4.
        beat: u8,
        /// Its effective tempo, pitch included.
        bpm: Option<Bpm>,
        /// Its current pitch.
        pitch: Pitch,
        /// Milliseconds until the next beat — the field that makes it possible
        /// to schedule ahead rather than react.
        next_beat_ms: u32,
    },

    /// A CDJ-3000 reported its exact playhead position.
    Position {
        /// Which player.
        player_number: u8,
        /// Where the playhead is, in milliseconds.
        playhead_ms: u32,
        /// How long the track is, in milliseconds.
        track_length_ms: u32,
    },

    /// The mixer changed which channels are routed to the live output.
    OnAirChanged {
        /// Which player occupies each channel, `0` for an empty channel.
        channels: [u8; 4],
    },

    /// A mixer issued a fader-start command.
    FaderStart {
        /// One command per mixer channel.
        commands: [FaderStartCommand; 4],
    },

    // ---- status ------------------------------------------------------------
    /// A player's status changed. Read the current values from
    /// [`Session::device`](crate::session::Session::device).
    DeviceStatus {
        /// Which player.
        player_number: u8,
        /// Which fields differ from the last packet.
        changed: StatusChange,
    },

    /// Media was inserted or removed.
    MediaChanged {
        /// Which player.
        player_number: u8,
        /// Which slot.
        slot: PlayerSlot,
        /// What is in it now.
        state: StorageIndicator,
    },

    /// A reply to [`Session::query_media`].
    ///
    /// [`Session::query_media`]: crate::session::Session::query_media
    MediaInfo(MediaInfo),

    /// A different track was loaded onto a deck.
    TrackLoaded {
        /// Which player.
        player_number: u8,
        /// Which player the track came from.
        source_player: u8,
        /// Which slot on that player.
        slot: PlayerSlot,
        /// The track's identifier.
        track_id: u32,
    },

    /// The tempo master moved to a different device.
    MasterChanged {
        /// The new master.
        player_number: u8,
    },

    // ---- diagnostics -------------------------------------------------------
    /// A datagram could not be decoded.
    ///
    /// Informational, never fatal. Unfamiliar hardware and new firmware both
    /// produce these, and neither is a reason to stop.
    DecodeError {
        /// Which channel it arrived on.
        channel: Channel,
        /// Who sent it.
        source: Ipv4Addr,
        /// What went wrong.
        error: CodecError,
    },

    /// A packet decoded but this library has no model for its type. The raw
    /// type byte is included so unfamiliar traffic can be investigated.
    Unhandled {
        /// Which channel it arrived on.
        channel: Channel,
        /// Who sent it.
        source: Ipv4Addr,
        /// Its type byte.
        packet_type: u8,
    },

    /// The internal event queue overflowed and events were discarded.
    ///
    /// Means the caller is not draining [`Session::poll`] to `None` before
    /// doing other work.
    ///
    /// [`Session::poll`]: crate::session::Session::poll
    EventsDropped {
        /// How many were lost.
        count: u16,
    },
}

bitflags::bitflags! {
    /// Which parts of a player's status changed.
    ///
    /// A bitmask rather than one event per field: a CDJ emits status about
    /// five times a second per deck and a typical packet changes several
    /// fields at once, so six devices would otherwise produce a hundred-odd
    /// events a second to sift through.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct StatusChange: u16 {
        /// Playing, paused, cued, and so on.
        const PLAY_STATE = 0x0001;
        /// The track's tempo.
        const BPM = 0x0002;
        /// The pitch being applied.
        const PITCH = 0x0004;
        /// The beat within the bar.
        const BEAT = 0x0008;
        /// Beats elapsed since the start of the track.
        const BEAT_COUNT = 0x0010;
        /// Whether the deck is routed to the live output.
        const ON_AIR = 0x0020;
        /// Whether the deck is following the tempo master.
        const SYNC = 0x0040;
        /// Whether the deck *is* the tempo master.
        const MASTER = 0x0080;
        /// Which track is loaded.
        const TRACK = 0x0100;
        /// Distance to the next cue point.
        const CUE = 0x0200;
        /// Whether media is mounted.
        const MEDIA = 0x0400;
    }
}

impl StatusChange {
    /// Whether anything changed at all.
    pub fn is_meaningful(self) -> bool {
        !self.is_empty()
    }
}
