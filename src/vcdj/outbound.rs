//! Building the packets this library sends.
//!
//! Each function writes into a caller-supplied buffer and returns how many
//! bytes it wrote, so nothing here allocates and every one of them can be
//! tested against a hex dump without a socket in sight.

use core::net::Ipv4Addr;

use crate::constants::{MAGIC, MODEL_LEN};
use crate::error::CodecError;
use crate::packet::keepalive::{KeepAliveBody, KeepAlivePacket, PlayerNumberAssignment};
use crate::packet::status::{PlayerSlot, StatusBody, StatusPacket, StatusType};
use crate::packet::{BeatPacket, FaderStartCommand, StateFlags};
use crate::vcdj::{OwnStatus, VcdjConfig};
use crate::wire::{FixedStr, WriteCursor};

/// Length of the status packet this library sends.
///
/// Real players send a much longer one; 0xd0 covers every field that matters
/// to a receiver and is comfortably past the 0xc8 minimum a CDJ will accept.
const OWN_STATUS_LEN: usize = 0xd0;

/// How many devices to claim to see in a keepalive.
///
/// A CDJ-3000 ignores devices that report fewer than two, so this is always at
/// least two regardless of what is actually out there.
const MIN_DEVICE_COUNT: u8 = 2;

/// What to put in the byte at `0x25` of a keepalive.
///
/// Its meaning is unknown. Every reference implementation sends a constant `1`
/// there — beat-link's announcement template and python-prodj-link's `u2`
/// default — and sending our own player number instead appears to make players
/// re-run their tempo-master election on every heartbeat.
const RELATED_PLAYER_NUMBER: u8 = 1;

/// Builds a greeting: "who else is on this network?"
pub fn hello(config: &VcdjConfig, out: &mut [u8]) -> Result<usize, CodecError> {
    KeepAlivePacket::new(
        config.model,
        config.device_type,
        KeepAliveBody::Hello { counter: 1 },
    )
    .encode(out)
}

/// Builds the first claim: "this hardware address is joining."
pub fn claim_mac(config: &VcdjConfig, iteration: u8, out: &mut [u8]) -> Result<usize, CodecError> {
    let (_, mac) = config.identity().ok_or(MISSING_IDENTITY)?;
    KeepAlivePacket::new(
        config.model,
        config.device_type,
        KeepAliveBody::ClaimMac {
            iteration,
            flags: config.flags,
            mac,
        },
    )
    .encode(out)
}

/// Builds the second claim: "this address wants this player number."
pub fn claim_ip(
    config: &VcdjConfig,
    number: u8,
    iteration: u8,
    out: &mut [u8],
) -> Result<usize, CodecError> {
    let (ip, mac) = config.identity().ok_or(MISSING_IDENTITY)?;
    let assignment = match config.number {
        crate::vcdj::NumberRequest::Fixed(_) => PlayerNumberAssignment::Manual,
        crate::vcdj::NumberRequest::Auto { .. } => PlayerNumberAssignment::Auto,
    };
    KeepAlivePacket::new(
        config.model,
        config.device_type,
        KeepAliveBody::ClaimIp {
            ip,
            mac,
            player_number: number,
            iteration,
            flags: config.flags,
            assignment,
        },
    )
    .encode(out)
}

/// Builds the final claim, and the packet used to defend a number already held.
pub fn claim_number(
    config: &VcdjConfig,
    number: u8,
    iteration: u8,
    out: &mut [u8],
) -> Result<usize, CodecError> {
    KeepAlivePacket::new(
        config.model,
        config.device_type,
        KeepAliveBody::ClaimNumber {
            player_number: number,
            iteration,
        },
    )
    .encode(out)
}

/// Builds the steady-state heartbeat, sent every 1.5 seconds.
///
/// Stopping these is how a device leaves the network: after five seconds of
/// silence everyone else drops it.
pub fn keepalive(
    config: &VcdjConfig,
    number: u8,
    device_count: u8,
    out: &mut [u8],
) -> Result<usize, CodecError> {
    let (ip, mac) = config.identity().ok_or(MISSING_IDENTITY)?;
    KeepAlivePacket::new(
        config.model,
        config.device_type,
        KeepAliveBody::Status {
            player_number: number,
            related_player_number: RELATED_PLAYER_NUMBER,
            mac,
            ip,
            device_count: device_count.max(MIN_DEVICE_COUNT),
            flags: config.flags,
            extra_flags: 0,
        },
    )
    .encode(out)
}

/// Builds a media-slot query: "what is in slot X of player Y?"
///
/// The reply arrives asynchronously on the status channel as a
/// [`MediaReply`](StatusBody::MediaReply).
pub fn media_query(
    config: &VcdjConfig,
    own_number: u8,
    target: u8,
    slot: PlayerSlot,
    out: &mut [u8],
) -> Result<usize, CodecError> {
    let (ip, _) = config.identity().ok_or(MISSING_IDENTITY)?;
    StatusPacket {
        model: config.model,
        protocol_version: crate::packet::status::PROTOCOL_VERSION,
        // Media queries carry revision 0; players ignore other values.
        revision: 0,
        player_number: own_number,
        preamble: 0x000c,
        body: StatusBody::MediaQuery {
            player_number: target,
            slot,
            reply_to: ip,
        },
    }
    .encode(out)
}

/// Builds a load command: "player X, load track Z from player Y's slot S."
pub fn load_track(
    config: &VcdjConfig,
    own_number: u8,
    source_player: u8,
    slot: PlayerSlot,
    track_id: u32,
    out: &mut [u8],
) -> Result<usize, CodecError> {
    StatusPacket {
        model: config.model,
        protocol_version: crate::packet::status::PROTOCOL_VERSION,
        revision: 1,
        player_number: own_number,
        preamble: 0x0034,
        body: StatusBody::LoadCommand {
            source_player,
            slot,
            track_id,
        },
    }
    .encode(out)
}

/// Builds a fader-start command, one instruction per mixer channel.
pub fn fader_start(
    config: &VcdjConfig,
    own_number: u8,
    commands: [FaderStartCommand; 4],
    out: &mut [u8],
) -> Result<usize, CodecError> {
    BeatPacket::new(
        config.model,
        own_number,
        crate::packet::BeatBody::FaderStart { commands },
    )
    .encode(out)
}

/// Builds this library's own status packet.
///
/// Hand-assembled rather than routed through [`StatusPacket::encode`] because
/// several bytes here have no known meaning but are nonetheless load-bearing:
/// some players will not report metadata for unanalyzed files unless `0x68`
/// and `0x75` are `1`, and treat us as obsolete firmware unless `0xb6` is `1`.
/// Those constants are the whole reason this function exists.
pub fn own_status(
    config: &VcdjConfig,
    own_number: u8,
    status: &OwnStatus,
    packet_count: u32,
    out: &mut [u8],
) -> Result<usize, CodecError> {
    if out.len() < OWN_STATUS_LEN {
        return Err(CodecError::BufferOverflow {
            needed: OWN_STATUS_LEN,
            capacity: out.len(),
        });
    }
    let out = &mut out[..OWN_STATUS_LEN];
    out.fill(0);

    let mut cursor = WriteCursor::new(out);
    cursor.write_bytes(&MAGIC)?;
    cursor.write_u8(StatusType::Cdj.to_u8())?;
    cursor.write_ascii(&config.model, MODEL_LEN, "status.model")?;
    cursor.write_u8(crate::packet::status::PROTOCOL_VERSION)?;
    cursor.write_u8(3)?; // revision: pose as a CDJ-2000NXS
    cursor.write_u8(own_number)?;
    cursor.write_u16(0x00b0)?; // payload length as a nexus player reports it

    cursor.pad_to(0x24)?;
    cursor.write_u8(own_number)?; // player number, mirrored
    cursor.write_u8(0)?;

    // Uncharted, but observed to be 0x0100 on real hardware. The 1 at 0x68 is
    // one of the bytes players check before answering metadata requests.
    cursor.pad_to(0x68)?;
    cursor.write_u16(0x0100)?;

    // Likewise the 1 at 0x75, inside the link-availability field.
    cursor.pad_to(0x74)?;
    cursor.write_u32(0x0001_0000)?;

    cursor.pad_to(0x7c)?;
    cursor.write_ascii(&FIRMWARE, 4, "status.firmware")?;

    cursor.pad_to(0x88)?;
    cursor.write_u16(state_flags(status).bits() | StateFlags::ALWAYS_SET)?;

    cursor.pad_to(0x8c)?;
    cursor.write_pitch(status.pitch)?;
    cursor.write_u16(0x8000)?; // tempo came from rekordbox
    cursor.write_bpm(status.bpm)?;

    cursor.pad_to(0x98)?;
    cursor.write_pitch(status.pitch)?;

    cursor.pad_to(0xa6)?;
    cursor.write_u8(status.beat)?;

    // And the 1 at 0xb6, without which older players think we are obsolete.
    cursor.pad_to(0xb6)?;
    cursor.write_u8(1)?;

    cursor.pad_to(0xc8)?;
    cursor.write_u32(packet_count)?;
    cursor.write_u8(1)?; // claim nexus-generation capabilities

    cursor.pad_to(OWN_STATUS_LEN)?;
    Ok(cursor.position())
}

/// The firmware version this library reports for itself.
const FIRMWARE: FixedStr<4> = match FixedStr::from_ascii_const(*b"1.40") {
    Some(value) => value,
    None => panic!("the firmware string is four ASCII bytes"),
};

fn state_flags(status: &OwnStatus) -> StateFlags {
    let mut flags = StateFlags::empty();
    flags.set(StateFlags::PLAY, status.playing);
    flags.set(StateFlags::ON_AIR, status.on_air);
    flags.set(StateFlags::SYNC, status.synced);
    flags.set(StateFlags::MASTER, status.master);
    flags
}

const MISSING_IDENTITY: CodecError = CodecError::InvalidField {
    field: "vcdj.identity",
    reason: "no IP or MAC configured; call VcdjConfig::with_identity",
};

/// Where a media query's reply should be sent, for callers that need it.
pub fn reply_address(config: &VcdjConfig) -> Option<Ipv4Addr> {
    config.ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAX_PACKET_LEN;
    use crate::packet::keepalive::KeepAliveType;
    use crate::wire::MacAddr;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 200);
    const MAC: MacAddr = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);

    fn config() -> VcdjConfig {
        VcdjConfig::new("Virtual CDJ").with_identity(IP, MAC)
    }

    #[test]
    fn a_keepalive_is_the_fifty_four_bytes_hardware_expects() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = keepalive(&config(), 5, 3, &mut buf).unwrap();
        assert_eq!(len, 0x36);

        let decoded = KeepAlivePacket::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.packet_type(), KeepAliveType::Status);
        assert_eq!(decoded.model, "Virtual CDJ");

        let KeepAliveBody::Status {
            player_number,
            ip,
            mac,
            device_count,
            ..
        } = decoded.body
        else {
            panic!("expected a status body");
        };
        assert_eq!(player_number, 5);
        assert_eq!(ip, IP);
        assert_eq!(mac, MAC);
        assert_eq!(device_count, 3);
    }

    /// Byte 0x25 is a constant in every reference implementation. Sending our
    /// own player number there made the players' master indicator jump around.
    #[test]
    fn a_keepalive_puts_a_constant_in_the_byte_after_the_player_number() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = keepalive(&config(), 5, 3, &mut buf).unwrap();
        assert_eq!(buf[0x24], 5, "0x24 is our player number");
        assert_eq!(buf[0x25], 1, "0x25 is not a second copy of it");

        let KeepAliveBody::Status {
            related_player_number,
            ..
        } = KeepAlivePacket::decode(&buf[..len]).unwrap().body
        else {
            panic!("expected a status body");
        };
        assert_eq!(related_player_number, 1);
    }

    #[test]
    fn a_keepalive_never_claims_to_see_fewer_than_two_devices() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = keepalive(&config(), 5, 0, &mut buf).unwrap();
        let KeepAliveBody::Status { device_count, .. } =
            KeepAlivePacket::decode(&buf[..len]).unwrap().body
        else {
            panic!("expected a status body");
        };
        // A CDJ-3000 ignores devices reporting fewer than two.
        assert_eq!(device_count, MIN_DEVICE_COUNT);
    }

    #[test]
    fn every_claim_carries_its_iteration() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        for iteration in 1..=3 {
            let len = claim_mac(&config(), iteration, &mut buf).unwrap();
            let KeepAliveBody::ClaimMac { iteration: got, .. } =
                KeepAlivePacket::decode(&buf[..len]).unwrap().body
            else {
                panic!("expected a MAC claim");
            };
            assert_eq!(got, iteration);
        }
    }

    #[test]
    fn an_automatic_number_is_advertised_as_automatic() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = claim_ip(&config(), 5, 1, &mut buf).unwrap();
        let KeepAliveBody::ClaimIp { assignment, .. } =
            KeepAlivePacket::decode(&buf[..len]).unwrap().body
        else {
            panic!("expected an IP claim");
        };
        assert_eq!(assignment, PlayerNumberAssignment::Auto);
    }

    #[test]
    fn a_demanded_number_is_advertised_as_manual() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let config = config().with_number(crate::vcdj::NumberRequest::Fixed(3));
        let len = claim_ip(&config, 3, 1, &mut buf).unwrap();
        let KeepAliveBody::ClaimIp { assignment, .. } =
            KeepAlivePacket::decode(&buf[..len]).unwrap().body
        else {
            panic!("expected an IP claim");
        };
        assert_eq!(assignment, PlayerNumberAssignment::Manual);
    }

    #[test]
    fn building_a_claim_without_an_identity_is_refused() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let config = VcdjConfig::new("Virtual CDJ");
        assert_eq!(claim_mac(&config, 1, &mut buf), Err(MISSING_IDENTITY));
        assert_eq!(keepalive(&config, 5, 2, &mut buf), Err(MISSING_IDENTITY));
        // A greeting carries no identity, so it works regardless.
        assert!(hello(&config, &mut buf).is_ok());
    }

    #[test]
    fn a_media_query_asks_the_right_slot_and_says_where_to_reply() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = media_query(&config(), 5, 2, PlayerSlot::Usb, &mut buf).unwrap();
        let decoded = StatusPacket::decode(&buf[..len]).unwrap();

        assert_eq!(decoded.player_number, 5);
        assert_eq!(
            decoded.body,
            StatusBody::MediaQuery {
                player_number: 2,
                slot: PlayerSlot::Usb,
                reply_to: IP,
            }
        );
    }

    #[test]
    fn a_load_command_names_the_track_and_its_source() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = load_track(&config(), 5, 2, PlayerSlot::Sd, 0x0000_0457, &mut buf).unwrap();
        let decoded = StatusPacket::decode(&buf[..len]).unwrap();

        assert_eq!(
            decoded.body,
            StatusBody::LoadCommand {
                source_player: 2,
                slot: PlayerSlot::Sd,
                track_id: 0x0000_0457,
            }
        );
    }

    #[test]
    fn a_fader_start_carries_one_command_per_channel() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let commands = [
            FaderStartCommand::Start,
            FaderStartCommand::Ignore,
            FaderStartCommand::Stop,
            FaderStartCommand::Ignore,
        ];
        let len = fader_start(&config(), 5, commands, &mut buf).unwrap();
        let decoded = BeatPacket::decode(&buf[..len]).unwrap();

        assert_eq!(decoded.player_number, 5);
        assert_eq!(
            decoded.body,
            crate::packet::BeatBody::FaderStart { commands }
        );
    }

    #[test]
    fn our_status_packet_carries_the_bytes_players_insist_on() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = own_status(&config(), 5, &OwnStatus::default(), 42, &mut buf).unwrap();

        assert_eq!(len, OWN_STATUS_LEN);
        // Without these three, some players refuse to answer metadata
        // requests or treat us as obsolete firmware.
        assert_eq!(
            buf[0x68], 1,
            "byte 0x68 gates metadata for unanalyzed files"
        );
        assert_eq!(
            buf[0x75], 1,
            "byte 0x75 gates metadata for unanalyzed files"
        );
        assert_eq!(buf[0xb6], 1, "byte 0xb6 signals current firmware");
    }

    #[test]
    fn our_status_packet_is_long_enough_for_a_player_to_parse() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = own_status(&config(), 5, &OwnStatus::default(), 0, &mut buf).unwrap();
        // Players read the packet counter at 0xc8 and reject anything shorter.
        assert!(len > 0xcc, "packet must extend past the counter at 0xc8");

        let decoded = StatusPacket::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.player_number, 5);
        let StatusBody::Cdj(status) = decoded.body else {
            panic!("our own status must decode as a CDJ status");
        };
        assert_eq!(status.packet_count, 0);
    }

    #[test]
    fn our_advertised_state_reaches_the_wire() {
        let mut buf = [0u8; MAX_PACKET_LEN];
        let status = OwnStatus {
            playing: true,
            on_air: true,
            master: true,
            synced: false,
            bpm: crate::wire::Bpm::from_raw(12800),
            ..OwnStatus::default()
        };
        let len = own_status(&config(), 5, &status, 7, &mut buf).unwrap();

        let StatusBody::Cdj(decoded) = StatusPacket::decode(&buf[..len]).unwrap().body else {
            panic!("expected a CDJ status");
        };
        assert!(decoded.state.contains(StateFlags::PLAY));
        assert!(decoded.state.contains(StateFlags::ON_AIR));
        assert!(decoded.state.contains(StateFlags::MASTER));
        assert!(!decoded.state.contains(StateFlags::SYNC));
        assert_eq!(decoded.bpm, crate::wire::Bpm::from_raw(12800));
        assert_eq!(decoded.packet_count, 7);
    }

    #[test]
    fn a_short_buffer_is_refused_rather_than_truncating_a_packet() {
        let mut buf = [0u8; 64];
        assert!(matches!(
            own_status(&config(), 5, &OwnStatus::default(), 0, &mut buf),
            Err(CodecError::BufferOverflow { .. })
        ));
    }
}
