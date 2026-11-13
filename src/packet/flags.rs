//! Bit flags carried by keepalive and status packets.

use bitflags::bitflags;

bitflags! {
    /// What a device says it is, advertised in every keepalive.
    ///
    /// Constructed with `from_bits_retain`, so bits this library does not know
    /// about are kept rather than rejected — a newer device setting a ninth
    /// flag must not make its keepalives undecodable.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct StatusFeatureFlags: u8 {
        /// Set by anything that is a player or a mixer.
        const IS_PLAYER_OR_MIXER = 0x01;
        /// Set by mixers. A DJM sends `0x03`: mixer *and* player-or-mixer.
        const IS_MIXER = 0x02;
        /// Set by rekordbox acting as a device.
        const IS_REKORDBOX = 0x04;
        /// Set by an NXS gateway.
        const IS_NXS_GATEWAY = 0x08;
    }
}

bitflags! {
    /// Play, sync, master and on-air state, carried in CDJ status packets.
    ///
    /// Also `from_bits_retain`: the surrounding byte has bits whose meaning is
    /// still unknown, and discarding them would break byte-exact re-encoding.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    pub struct StateFlags: u16 {
        /// The player's audio is routed through the mixer's live output.
        const ON_AIR = 0x0008;
        /// The player is following the tempo master.
        const SYNC = 0x0010;
        /// The player *is* the tempo master.
        const MASTER = 0x0020;
        /// The player is playing rather than paused or cued.
        const PLAY = 0x0040;
    }
}

impl StateFlags {
    /// Bits hardware sets on every status packet regardless of state.
    ///
    /// Omitting them from a packet we send makes some players ignore it, so
    /// the encoder ORs them in unconditionally.
    pub const ALWAYS_SET: u16 = 0x0084;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_bits_survive_a_round_trip() {
        // Bit 0x80 has no documented meaning; it must not be discarded.
        let flags = StatusFeatureFlags::from_bits_retain(0x81);
        assert!(flags.contains(StatusFeatureFlags::IS_PLAYER_OR_MIXER));
        assert_eq!(flags.bits(), 0x81);
    }

    #[test]
    fn a_djm_advertises_mixer_and_player() {
        let flags = StatusFeatureFlags::from_bits_retain(0x03);
        assert!(flags.contains(StatusFeatureFlags::IS_MIXER));
        assert!(flags.contains(StatusFeatureFlags::IS_PLAYER_OR_MIXER));
    }
}
