//! Being a device on the network rather than just watching it.
//!
//! To be visible to CDJs — and to be allowed to ask them questions — this
//! library has to behave like a player: claim a number nobody else is using,
//! then keep saying so every 1.5 seconds for as long as it is running. That is
//! what this module does.

use core::net::Ipv4Addr;

use crate::constants::{Timing, MODEL_LEN};
use crate::packet::{DeviceType, StatusFeatureFlags};
use crate::wire::{Bpm, FixedStr, MacAddr, Pitch};

pub mod negotiate;
pub mod outbound;

pub use negotiate::{NegotiationFailure, Negotiator, NumberRequest, VcdjState};

/// How this library presents itself to the network.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VcdjConfig {
    /// The model name to advertise. CDJs display this.
    pub model: FixedStr<MODEL_LEN>,
    /// What kind of device to claim to be.
    pub device_type: DeviceType,
    /// What capabilities to advertise.
    pub flags: StatusFeatureFlags,
    /// Which player number to ask for.
    pub number: NumberRequest,
    /// Our address, as advertised in keepalives.
    pub ip: Option<Ipv4Addr>,
    /// Our hardware address, as advertised in keepalives.
    pub mac: Option<MacAddr>,
    /// Whether to send our own status packets on the status channel.
    ///
    /// Defaults to `true` and should stay that way. Some players will not
    /// report metadata for unanalyzed files unless they have seen a status
    /// packet from the asker, and older firmware treats a silent device as
    /// obsolete.
    pub publish_status: bool,
    /// Whether to unicast each keepalive to every known device in addition to
    /// broadcasting it, as real players do.
    ///
    /// Off by default: broadcast alone is enough on every network tested, and
    /// this multiplies outbound traffic by the device count.
    pub unicast_keepalives: bool,
    /// Every interval the session schedules against.
    pub timing: Timing,
}

impl VcdjConfig {
    /// A configuration advertising `model`, asking for an automatically
    /// assigned player number.
    ///
    /// The model name is truncated at [`MODEL_LEN`] bytes if it is longer,
    /// since a name that does not fit is not worth refusing to start over.
    pub fn new(model: &str) -> Self {
        let model = FixedStr::new(model).unwrap_or_else(|_| {
            let mut end = MODEL_LEN;
            while end > 0 && !model.is_char_boundary(end) {
                end -= 1;
            }
            FixedStr::new(&model[..end]).unwrap_or(FixedStr::EMPTY)
        });

        VcdjConfig {
            model,
            device_type: DeviceType::Cdj,
            flags: StatusFeatureFlags::IS_PLAYER_OR_MIXER,
            number: NumberRequest::default(),
            ip: None,
            mac: None,
            publish_status: true,
            unicast_keepalives: false,
            timing: Timing::DEFAULT,
        }
    }

    /// Sets the address and hardware address to advertise.
    ///
    /// Required: without them there is nothing to put in a keepalive, and
    /// [`Session::start`] fails with
    /// [`SessionError::MissingIdentity`].
    ///
    /// [`Session::start`]: crate::session::Session::start
    /// [`SessionError::MissingIdentity`]: crate::error::SessionError::MissingIdentity
    pub fn with_identity(mut self, ip: Ipv4Addr, mac: MacAddr) -> Self {
        self.ip = Some(ip);
        self.mac = Some(mac);
        self
    }

    /// Sets which player number to ask for.
    pub fn with_number(mut self, number: NumberRequest) -> Self {
        self.number = number;
        self
    }

    /// Sets what kind of device to claim to be.
    pub fn with_device_type(mut self, device_type: DeviceType) -> Self {
        self.device_type = device_type;
        self
    }

    /// Replaces the timing table. Useful in tests to compress a negotiation
    /// that would otherwise take nearly two seconds.
    pub fn with_timing(mut self, timing: Timing) -> Self {
        self.timing = timing;
        self
    }

    /// Turns our own status packets off. See [`publish_status`].
    ///
    /// [`publish_status`]: VcdjConfig::publish_status
    pub fn without_status_publishing(mut self) -> Self {
        self.publish_status = false;
        self
    }

    /// Also unicasts keepalives to every known device. See
    /// [`unicast_keepalives`].
    ///
    /// [`unicast_keepalives`]: VcdjConfig::unicast_keepalives
    pub fn with_unicast_keepalives(mut self) -> Self {
        self.unicast_keepalives = true;
        self
    }

    /// Fills in any missing identity from what the adapter can discover.
    pub fn resolve_identity(&mut self, ip: Option<Ipv4Addr>, mac: Option<MacAddr>) {
        self.ip = self.ip.or(ip);
        self.mac = self.mac.or(mac);
    }

    /// Both halves of the identity, if both are present.
    pub fn identity(&self) -> Option<(Ipv4Addr, MacAddr)> {
        Some((self.ip?, self.mac?))
    }
}

/// The state this library advertises about itself in its own status packets.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OwnStatus {
    /// Whether to claim to be playing.
    pub playing: bool,
    /// Whether to claim to be routed to the live output.
    pub on_air: bool,
    /// Whether to claim to be following the tempo master.
    pub synced: bool,
    /// Whether to claim to *be* the tempo master.
    pub master: bool,
    /// The tempo to report.
    pub bpm: Option<Bpm>,
    /// The pitch to report.
    pub pitch: Pitch,
    /// Which beat of the bar to report, 1 through 4.
    pub beat: u8,
}

impl Default for OwnStatus {
    fn default() -> Self {
        OwnStatus {
            playing: false,
            on_air: false,
            synced: false,
            master: false,
            bpm: None,
            pitch: Pitch::NORMAL,
            beat: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overlong_model_name_is_truncated_rather_than_refused() {
        let config = VcdjConfig::new("a name far longer than twenty bytes");
        assert_eq!(config.model.len(), MODEL_LEN);
        assert_eq!(config.model.as_str(), "a name far longer th");
    }

    #[test]
    fn truncation_does_not_split_a_character() {
        // 'é' is two bytes; truncating at 20 would land in the middle of one.
        let config = VcdjConfig::new("ééééééééééééééééééééééé");
        assert!(config.model.len() <= MODEL_LEN);
        assert!(config.model.as_str().chars().all(|c| c == 'é'));
    }

    #[test]
    fn identity_needs_both_halves() {
        let mut config = VcdjConfig::new("Virtual CDJ");
        assert_eq!(config.identity(), None);

        config.resolve_identity(Some(Ipv4Addr::LOCALHOST), None);
        assert_eq!(config.identity(), None, "an IP alone is not an identity");

        config.resolve_identity(None, Some(MacAddr::ZERO));
        assert!(config.identity().is_some());
    }

    #[test]
    fn explicit_identity_wins_over_what_the_adapter_reports() {
        let chosen = Ipv4Addr::new(10, 0, 0, 1);
        let mut config = VcdjConfig::new("Virtual CDJ").with_identity(chosen, MacAddr::ZERO);
        config.resolve_identity(Some(Ipv4Addr::new(192, 168, 1, 5)), None);
        assert_eq!(config.ip, Some(chosen));
    }

    #[test]
    fn status_publishing_is_on_by_default() {
        assert!(VcdjConfig::new("Virtual CDJ").publish_status);
    }
}
