//! What this library knows about one device on the network.

use core::net::Ipv4Addr;

use crate::constants::MODEL_LEN;
use crate::packet::status::{CdjStatus, DjmStatus, PlayState, PlayerSlot, StorageIndicator};
use crate::packet::{DeviceType, StateFlags};
use crate::time::Millis;
use crate::wire::{Bpm, FixedStr, MacAddr, Pitch};

/// A device seen on the Pro DJ Link network.
///
/// Assembled from all three channels: identity and liveness come from
/// keepalives, tempo and beat position from beat packets, everything else from
/// status packets. A device is present in the registry as soon as its first
/// keepalive arrives, long before it has said anything else, so most of these
/// fields start out empty.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Device {
    /// The device's player number, `1` through `6`. This is its identity as
    /// far as the rest of the protocol is concerned.
    pub player_number: u8,
    /// What kind of hardware it is.
    pub device_type: DeviceType,
    /// Its model name, e.g. `"CDJ-3000"`.
    pub model: FixedStr<MODEL_LEN>,
    /// Its address.
    pub ip: Ipv4Addr,
    /// Its hardware address, once a keepalive carrying one has arrived.
    pub mac: Option<MacAddr>,
    /// When its most recent keepalive arrived. Drives expiry.
    pub last_keepalive: Millis,
    /// Deck state, on devices that are players.
    pub player: Option<PlayerState>,
    /// Mixer state, on devices that are mixers.
    pub mixer: Option<MixerState>,
}

impl Device {
    /// A device known only from its first keepalive.
    pub fn new(
        player_number: u8,
        device_type: DeviceType,
        model: FixedStr<MODEL_LEN>,
        ip: Ipv4Addr,
        now: Millis,
    ) -> Self {
        Device {
            player_number,
            device_type,
            model,
            ip,
            mac: None,
            last_keepalive: now,
            player: None,
            mixer: None,
        }
    }

    /// Whether this device has gone silent for longer than `ttl_ms`.
    pub fn is_expired(&self, now: Millis, ttl_ms: u64) -> bool {
        now.since(self.last_keepalive) > ttl_ms
    }

    /// Whether this device is the tempo master.
    pub fn is_master(&self) -> bool {
        self.player
            .is_some_and(|p| p.state.contains(StateFlags::MASTER))
            || self
                .mixer
                .is_some_and(|m| m.state.contains(StateFlags::MASTER))
    }

    /// The tempo this device is currently producing, pitch included.
    pub fn effective_bpm(&self) -> Option<Bpm> {
        if let Some(player) = self.player {
            return player.effective_bpm();
        }
        self.mixer.and_then(|mixer| mixer.bpm)
    }

    /// The playhead position in milliseconds, extrapolated to `now`.
    ///
    /// Status packets arrive a handful of times a second, which is far too
    /// coarse to drive anything time-sensitive. Between them the position is
    /// estimated by advancing the last reported position at the deck's current
    /// pitch — the same trick every Pro DJ Link implementation uses.
    ///
    /// Returns `None` when the deck is not playing, since a stationary
    /// playhead needs no extrapolation and reporting a moving one would be a
    /// lie.
    pub fn position_ms(&self, now: Millis) -> Option<u64> {
        let player = self.player?;
        let position = player.position_ms?;
        if !player.play_state.is_playing() {
            return Some(position);
        }
        let elapsed = now.since(player.position_at) as f32;
        let advanced = elapsed * player.actual_pitch.0;
        Some(position.saturating_add(advanced as u64))
    }
}

/// The state of a device that is a player.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlayerState {
    /// What the deck is doing.
    pub play_state: PlayState,
    /// On-air, sync, master and play flags.
    pub state: StateFlags,
    /// The loaded track's identifier, or `0` if nothing is loaded.
    pub track_id: u32,
    /// Which player the loaded track came from.
    pub loaded_from_player: u8,
    /// Which slot on that player.
    pub loaded_from_slot: PlayerSlot,
    /// The track's tempo before pitch, if known.
    pub bpm: Option<Bpm>,
    /// The pitch actually being applied.
    pub actual_pitch: Pitch,
    /// Beats since the start of the track.
    pub beat_count: u32,
    /// Which beat of the bar, 1 through 4.
    pub beat: u8,
    /// Whether USB media is mounted.
    pub usb_state: StorageIndicator,
    /// Whether SD media is mounted.
    pub sd_state: StorageIndicator,
    /// Last reported playhead position, from a CDJ-3000 position packet.
    pub position_ms: Option<u64>,
    /// When that position was reported, so it can be extrapolated forward.
    pub position_at: Millis,
    /// Track length in milliseconds, from a CDJ-3000 position packet.
    pub track_length_ms: Option<u32>,
}

impl PlayerState {
    /// Builds player state from a status packet.
    pub fn from_status(status: &CdjStatus, now: Millis) -> Self {
        PlayerState {
            play_state: status.play_state,
            state: status.state,
            track_id: status.track_id,
            loaded_from_player: status.loaded_from_player,
            loaded_from_slot: status.loaded_from_slot,
            bpm: status.bpm,
            actual_pitch: status.actual_pitch,
            beat_count: status.beat_count,
            beat: status.beat,
            usb_state: status.usb_state,
            sd_state: status.sd_state,
            position_ms: None,
            position_at: now,
            track_length_ms: None,
        }
    }

    /// Folds a new status packet in, preserving the position fields, which
    /// come from a different packet on a different channel.
    pub fn apply_status(&mut self, status: &CdjStatus) {
        let position = (self.position_ms, self.position_at, self.track_length_ms);
        *self = PlayerState {
            position_ms: position.0,
            position_at: position.1,
            track_length_ms: position.2,
            ..PlayerState::from_status(status, position.1)
        };
    }

    /// The tempo this deck is producing, pitch included.
    pub fn effective_bpm(&self) -> Option<Bpm> {
        self.bpm.map(|bpm| Bpm(bpm.0 * self.actual_pitch.0))
    }

    /// How far through the track the playhead is, from `0.0` to `1.0`.
    pub fn progress(&self) -> Option<f32> {
        let length = self.track_length_ms?;
        if length == 0 {
            return None;
        }
        Some(self.position_ms? as f32 / length as f32)
    }
}

/// The state of a device that is a mixer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MixerState {
    /// On-air, sync, master and play flags.
    pub state: StateFlags,
    /// The mixer's tempo, if it has one.
    pub bpm: Option<Bpm>,
    /// Which beat of the bar.
    pub beat: u8,
    /// Which player occupies each channel, or `0` for an empty channel.
    ///
    /// A player is on air when its number appears here.
    pub channels_on_air: [u8; 4],
}

impl MixerState {
    /// Builds mixer state from a status packet.
    pub fn from_status(status: &DjmStatus) -> Self {
        MixerState {
            state: status.state,
            bpm: status.bpm,
            beat: status.beat,
            channels_on_air: [0; 4],
        }
    }

    /// Whether a given player is routed to the live output.
    pub fn is_on_air(&self, player_number: u8) -> bool {
        player_number != 0 && self.channels_on_air.contains(&player_number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn player(pitch: f32, play_state: PlayState) -> PlayerState {
        PlayerState {
            play_state,
            state: StateFlags::empty(),
            track_id: 1,
            loaded_from_player: 1,
            loaded_from_slot: PlayerSlot::Usb,
            bpm: Bpm::from_raw(12800),
            actual_pitch: Pitch(pitch),
            beat_count: 0,
            beat: 1,
            usb_state: StorageIndicator::Loaded,
            sd_state: StorageIndicator::NotLoaded,
            position_ms: Some(10_000),
            position_at: Millis(1_000),
            track_length_ms: Some(240_000),
        }
    }

    fn device_with(player_state: PlayerState) -> Device {
        Device {
            player: Some(player_state),
            ..Device::new(
                2,
                DeviceType::Cdj,
                FixedStr::new("CDJ-3000").unwrap(),
                Ipv4Addr::new(192, 168, 1, 5),
                Millis(0),
            )
        }
    }

    #[test]
    fn a_playing_deck_has_its_position_extrapolated() {
        let device = device_with(player(1.0, PlayState::Playing));
        // Half a second after the last report, at normal speed.
        assert_eq!(device.position_ms(Millis(1_500)), Some(10_500));
    }

    #[test]
    fn extrapolation_follows_the_pitch_fader() {
        let device = device_with(player(1.06, PlayState::Playing));
        assert_eq!(device.position_ms(Millis(2_000)), Some(11_060));
    }

    #[test]
    fn a_paused_deck_reports_where_it_stopped() {
        let device = device_with(player(1.0, PlayState::Paused));
        assert_eq!(device.position_ms(Millis(60_000)), Some(10_000));
    }

    #[test]
    fn a_device_with_no_position_report_has_none_to_give() {
        let mut state = player(1.0, PlayState::Playing);
        state.position_ms = None;
        assert_eq!(device_with(state).position_ms(Millis(5_000)), None);
    }

    #[test]
    fn effective_tempo_multiplies_by_pitch() {
        let state = player(1.06, PlayState::Playing);
        let effective = state.effective_bpm().unwrap();
        assert!((effective.0 - 135.68).abs() < 0.01, "{effective:?}");
    }

    #[test]
    fn expiry_is_measured_from_the_last_keepalive() {
        let device = Device::new(
            2,
            DeviceType::Cdj,
            FixedStr::new("CDJ-3000").unwrap(),
            Ipv4Addr::LOCALHOST,
            Millis(1_000),
        );
        assert!(!device.is_expired(Millis(6_000), 5_000));
        assert!(device.is_expired(Millis(6_001), 5_000));
    }

    #[test]
    fn a_status_update_does_not_discard_the_playhead() {
        let mut state = player(1.0, PlayState::Playing);
        let status = CdjStatus {
            loaded_from_player: 3,
            loaded_from_slot: PlayerSlot::Sd,
            track_analyze_type: crate::packet::TrackAnalyzeType::Rekordbox,
            track_id: 99,
            track_number: 1,
            usb_activity: crate::packet::ActivityIndicator::Inactive,
            sd_activity: crate::packet::ActivityIndicator::Active,
            usb_state: StorageIndicator::NotLoaded,
            sd_state: StorageIndicator::Loaded,
            play_state: PlayState::Playing,
            firmware: FixedStr::new("1.40").unwrap(),
            tempo_master_count: 0,
            state: StateFlags::PLAY,
            physical_pitch: Pitch::NORMAL,
            bpm_source: crate::packet::BpmSource::Rekordbox,
            bpm: Bpm::from_raw(13000),
            actual_pitch: Pitch::NORMAL,
            beat_count: 500,
            cue_distance: 0,
            beat: 2,
            packet_count: 1,
            is_nexus: 1,
            key: None,
            key_shift: None,
            loop_start_ms: None,
            loop_end_ms: None,
        };

        state.apply_status(&status);

        assert_eq!(state.track_id, 99);
        assert_eq!(state.beat_count, 500);
        // The position came from a beat-channel packet and must survive.
        assert_eq!(state.position_ms, Some(10_000));
        assert_eq!(state.track_length_ms, Some(240_000));
    }

    #[test]
    fn a_mixer_reports_which_players_are_live() {
        let mut mixer = MixerState {
            state: StateFlags::empty(),
            bpm: None,
            beat: 1,
            channels_on_air: [1, 0, 3, 0],
        };
        assert!(mixer.is_on_air(1));
        assert!(mixer.is_on_air(3));
        assert!(!mixer.is_on_air(2));
        // An empty channel must not read as "player 0 is on air".
        assert!(!mixer.is_on_air(0));

        mixer.channels_on_air = [0; 4];
        assert!(!mixer.is_on_air(1));
    }
}
