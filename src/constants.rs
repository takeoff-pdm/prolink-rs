//! Wire constants and the tunable timing table.

/// Every Pro DJ Link UDP datagram starts with these ten ASCII bytes.
pub const MAGIC: [u8; 10] = *b"Qspt1WmJOL";

/// UDP port carrying keepalives, announcements and player-number negotiation.
pub const ANNOUNCE_PORT: u16 = 50000;

/// UDP port carrying beat, absolute-position, on-air and fader-start packets.
pub const BEAT_PORT: u16 = 50001;

/// UDP port carrying CDJ/DJM status, media queries and load commands.
pub const STATUS_PORT: u16 = 50002;

/// Largest datagram this library will receive or build.
///
/// The biggest packet in the protocol is the CDJ-3000 status packet at 1158
/// bytes; 1500 covers it with room for future firmware to append fields.
pub const MAX_PACKET_LEN: usize = 1500;

/// Number of device slots the registry tracks.
///
/// A Pro DJ Link network tops out at six players plus a mixer plus rekordbox,
/// so eight is enough to hold a full booth without allocating.
pub const MAX_DEVICES: usize = 8;

/// Width of the fixed `model` field present in every packet header.
pub const MODEL_LEN: usize = 20;

/// Every interval the library schedules against, in milliseconds.
///
/// Kept in one struct so tests can compress time and so corrections to the
/// reverse-engineered negotiation timing are a one-line change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Gap between successive negotiation packets.
    pub claim_interval_ms: u64,
    /// How many times each negotiation claim is repeated.
    pub claim_iterations: u8,
    /// Gap between steady-state keepalives once online.
    pub keepalive_interval_ms: u64,
    /// Gap between our own outgoing CDJ status packets.
    pub status_interval_ms: u64,
    /// Silence after which a device is considered gone.
    pub device_ttl_ms: u64,
    /// How often the registry is swept for expired devices.
    pub expiry_sweep_ms: u64,
}

impl Timing {
    /// The values real hardware uses.
    pub const DEFAULT: Timing = Timing {
        claim_interval_ms: 300,
        claim_iterations: 3,
        keepalive_interval_ms: 1500,
        status_interval_ms: 200,
        device_ttl_ms: 5000,
        expiry_sweep_ms: 1000,
    };
}

impl Default for Timing {
    fn default() -> Self {
        Timing::DEFAULT
    }
}
