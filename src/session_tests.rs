//! Behavioural tests for [`Session`], driven entirely through
//! [`MockTransport`] and an explicit clock.

use core::net::Ipv4Addr;

use crate::adapter::loopback::MockTransport;
use crate::adapter::{Channel, Destination};
use crate::constants::{Timing, MAX_PACKET_LEN, MODEL_LEN};
use crate::error::{CodecError, SessionError};
use crate::event::Event;
use crate::packet::keepalive::{KeepAliveBody, KeepAlivePacket, KeepAliveType};
use crate::packet::status::{StatusBody, StatusPacket};
use crate::packet::{BeatBody, BeatDistances, BeatPacket, DeviceType};
use crate::packet::{FaderStartCommand, PlayerSlot, StateFlags};
use crate::session::Session;
use crate::time::Millis;
use crate::vcdj::NumberRequest;
use crate::vcdj::{NegotiationFailure, OwnStatus, VcdjConfig, VcdjState};
use crate::wire::{Bpm, FixedStr, MacAddr, Pitch};

const OUR_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 200);
const OUR_MAC: MacAddr = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
const THEIR_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);
const THEIR_MAC: MacAddr = MacAddr([0x74, 0x5e, 0x1c, 0x0a, 0xbb, 0x03]);

fn model(name: &str) -> FixedStr<MODEL_LEN> {
    FixedStr::new(name).unwrap()
}

fn config() -> VcdjConfig {
    VcdjConfig::new("Virtual CDJ").with_identity(OUR_IP, OUR_MAC)
}

fn session() -> Session<MockTransport> {
    Session::new(MockTransport::with_identity(OUR_IP, OUR_MAC), config())
}

/// Encodes a steady-state keepalive as if it came from a real player.
fn their_keepalive(player_number: u8, name: &str) -> Vec<u8> {
    let packet = KeepAlivePacket::new(
        model(name),
        DeviceType::Cdj,
        KeepAliveBody::Status {
            player_number,
            related_player_number: player_number,
            mac: THEIR_MAC,
            ip: THEIR_IP,
            device_count: 2,
            flags: crate::packet::StatusFeatureFlags::IS_PLAYER_OR_MIXER,
            extra_flags: 0,
        },
    );
    let mut buf = [0u8; MAX_PACKET_LEN];
    let len = packet.encode(&mut buf).unwrap();
    buf[..len].to_vec()
}

/// Encodes another device claiming `player_number`.
fn their_claim(player_number: u8) -> Vec<u8> {
    let packet = KeepAlivePacket::new(
        model("CDJ-3000"),
        DeviceType::Cdj,
        KeepAliveBody::ClaimNumber {
            player_number,
            iteration: 1,
        },
    );
    let mut buf = [0u8; MAX_PACKET_LEN];
    let len = packet.encode(&mut buf).unwrap();
    buf[..len].to_vec()
}

fn their_beat(player_number: u8, beat: u8) -> Vec<u8> {
    let packet = BeatPacket::new(
        model("CDJ-3000"),
        player_number,
        BeatBody::Beat {
            distances: BeatDistances {
                next_beat: 468,
                ..BeatDistances::default()
            },
            pitch: Pitch::NORMAL,
            bpm: Bpm::from_raw(12800),
            beat,
            player_number,
        },
    );
    let mut buf = [0u8; MAX_PACKET_LEN];
    let len = packet.encode(&mut buf).unwrap();
    buf[..len].to_vec()
}

/// Drains `poll` at `now`, returning every event it produced.
fn drain(session: &mut Session<MockTransport>, now: u64) -> Vec<Event> {
    let mut events = Vec::new();
    while let Some(event) = session.poll(Millis(now)).unwrap() {
        events.push(event);
        assert!(events.len() < 1000, "poll did not settle");
    }
    events
}

/// Runs the clock from `start` to `end` in `step` increments, draining as it
/// goes.
fn run(session: &mut Session<MockTransport>, start: u64, end: u64, step: u64) -> Vec<Event> {
    let mut events = Vec::new();
    let mut now = start;
    while now <= end {
        events.extend(drain(session, now));
        now += step;
    }
    events
}

/// Runs from zero, for tests that begin at the start.
fn run_until(session: &mut Session<MockTransport>, end: u64, step: u64) -> Vec<Event> {
    run(session, 0, end, step)
}

/// How long the full claim sequence takes with the default timings: three
/// greetings and three of each of the three claims, 300 ms apart, with the
/// first going out immediately.
const NEGOTIATION_MS: u64 = 12 * Timing::DEFAULT.claim_interval_ms;

/// Runs a session to the point where it holds a player number.
fn bring_online(session: &mut Session<MockTransport>) -> Vec<Event> {
    let events = run_until(session, NEGOTIATION_MS, 50);
    assert!(
        session.state().is_online(),
        "expected to be online by {NEGOTIATION_MS} ms, state is {:?}",
        session.state()
    );
    events
}

fn decoded_keepalives(session: &Session<MockTransport>) -> Vec<KeepAlivePacket> {
    session
        .transport()
        .sent_on(Channel::Announce)
        .filter_map(|d| KeepAlivePacket::decode(&d.payload).ok())
        .collect()
}

// ---- the contract that matters most ---------------------------------------

#[test]
fn a_malformed_packet_is_an_event_not_an_error() {
    let mut session = session();
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, b"not a prolink packet at all");

    let events = drain(&mut session, 0);
    assert!(
        matches!(
            events.as_slice(),
            [Event::DecodeError {
                error: CodecError::InvalidMagic,
                ..
            }]
        ),
        "{events:?}"
    );
}

#[test]
fn garbage_does_not_stop_the_session_from_working() {
    let mut session = session();
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &[0xff; 64]);
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &their_keepalive(1, "CDJ-3000"));

    let events = drain(&mut session, 0);
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::DecodeError { .. })));
    assert!(events.iter().any(|e| matches!(
        e,
        Event::DeviceAppeared {
            player_number: 1,
            ..
        }
    )));
    assert!(session.device(1).is_some());
}

#[test]
fn a_truncated_packet_of_every_length_is_survivable() {
    let full = their_keepalive(1, "CDJ-3000");
    for n in 0..full.len() {
        let mut session = session();
        session
            .transport_mut()
            .push(Channel::Announce, THEIR_IP, &full[..n]);
        // Must not panic, and must not return Err.
        let _ = drain(&mut session, 0);
    }
}

// ---- device tracking -------------------------------------------------------

#[test]
fn a_keepalive_makes_a_device_appear() {
    let mut session = session();
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &their_keepalive(2, "CDJ-3000"));

    let events = drain(&mut session, 0);
    let [Event::DeviceAppeared {
        player_number,
        model: name,
        ip,
        mac,
        ..
    }] = events.as_slice()
    else {
        panic!("{events:?}");
    };
    assert_eq!(*player_number, 2);
    assert_eq!(*name, "CDJ-3000");
    assert_eq!(*ip, THEIR_IP);
    assert_eq!(*mac, Some(THEIR_MAC));
}

#[test]
fn a_device_appears_only_once_however_many_keepalives_it_sends() {
    let mut session = session();
    for t in 0..5 {
        session
            .transport_mut()
            .push(Channel::Announce, THEIR_IP, &their_keepalive(2, "CDJ-3000"));
        drain(&mut session, t * 100);
    }

    let appearances = run_until(&mut session, 400, 100)
        .iter()
        .filter(|e| matches!(e, Event::DeviceAppeared { .. }))
        .count();
    assert_eq!(appearances, 0, "already counted above");
    assert_eq!(session.devices().count(), 1);
}

#[test]
fn a_device_that_goes_quiet_is_dropped_after_the_ttl() {
    let mut session = session();
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &their_keepalive(2, "CDJ-3000"));
    drain(&mut session, 0);
    assert!(session.device(2).is_some());

    // Still within the five-second window.
    let events = run_until(&mut session, 4_000, 1_000);
    assert!(!events.iter().any(|e| matches!(e, Event::DeviceLost { .. })));
    assert!(session.device(2).is_some());

    // Past it.
    let events = drain(&mut session, 6_000);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::DeviceLost { player_number: 2 })),
        "{events:?}"
    );
    assert!(session.device(2).is_none());
}

#[test]
fn a_device_that_keeps_talking_is_never_dropped() {
    let mut session = session();
    let mut now = 0;
    while now < 20_000 {
        session
            .transport_mut()
            .push(Channel::Announce, THEIR_IP, &their_keepalive(2, "CDJ-3000"));
        let events = drain(&mut session, now);
        assert!(
            !events.iter().any(|e| matches!(e, Event::DeviceLost { .. })),
            "dropped a device that was still sending keepalives at t={now}"
        );
        now += 1_500;
    }
    assert!(session.device(2).is_some());
}

#[test]
fn our_own_keepalive_echoing_back_does_not_create_a_phantom_device() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);
    assert!(session.state().is_online());

    // Replay our own keepalive back at ourselves, as a switch would.
    let ours = session
        .transport()
        .sent_on(Channel::Announce)
        .filter_map(|d| {
            KeepAlivePacket::decode(&d.payload)
                .ok()
                .map(|p| (p, d.payload.clone()))
        })
        .find(|(p, _)| p.packet_type() == KeepAliveType::Status)
        .expect("we should have sent a keepalive")
        .1;

    session
        .transport_mut()
        .push(Channel::Announce, OUR_IP, &ours);
    let events = drain(&mut session, 4_100);

    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::DeviceAppeared { .. })),
        "we must not appear on our own network as another device: {events:?}"
    );
    assert!(session.devices().next().is_none());
}

#[test]
fn a_device_changing_address_is_reported_not_duplicated() {
    let mut session = session();
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &their_keepalive(2, "CDJ-3000"));
    drain(&mut session, 0);

    // Same player, new lease.
    let mut moved = KeepAlivePacket::decode(&their_keepalive(2, "CDJ-3000")).unwrap();
    if let KeepAliveBody::Status { ref mut ip, .. } = moved.body {
        *ip = Ipv4Addr::new(192, 168, 1, 77);
    }
    let mut buf = [0u8; MAX_PACKET_LEN];
    let len = moved.encode(&mut buf).unwrap();
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &buf[..len]);

    let events = drain(&mut session, 100);
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::DeviceReaddressed {
                player_number: 2,
                previous_ip,
                ..
            } if *previous_ip == THEIR_IP
        )),
        "{events:?}"
    );
    assert_eq!(session.devices().count(), 1);
}

#[test]
fn a_device_still_negotiating_does_not_occupy_a_number() {
    let mut session = session();
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &their_claim(3));
    drain(&mut session, 0);

    assert!(
        session.device(3).is_none(),
        "a number under negotiation is not yet held by anyone"
    );
}

// ---- negotiation -----------------------------------------------------------

#[test]
fn starting_without_an_identity_is_refused_up_front() {
    let mut session = Session::new(MockTransport::new(), VcdjConfig::new("Virtual CDJ"));
    assert_eq!(session.start(Millis(0)), Err(SessionError::MissingIdentity));
}

#[test]
fn the_adapters_identity_is_used_when_the_config_omits_one() {
    let session = Session::new(
        MockTransport::with_identity(OUR_IP, OUR_MAC),
        VcdjConfig::new("Virtual CDJ"),
    );
    assert_eq!(session.config().ip, Some(OUR_IP));
    assert_eq!(session.config().mac, Some(OUR_MAC));
}

#[test]
fn negotiation_walks_the_full_claim_sequence_then_goes_online() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    let events = bring_online(&mut session);

    let types: Vec<KeepAliveType> = decoded_keepalives(&session)
        .iter()
        .map(|p| p.packet_type())
        .collect();

    assert_eq!(&types[0..3], &[KeepAliveType::Hello; 3]);
    assert_eq!(&types[3..6], &[KeepAliveType::Mac; 3]);
    assert_eq!(&types[6..9], &[KeepAliveType::Ip; 3]);
    assert_eq!(&types[9..12], &[KeepAliveType::Number; 3]);
    assert_eq!(types[12], KeepAliveType::Status);

    assert!(events
        .iter()
        .any(|e| matches!(e, Event::Online { player_number: 5 })));
    assert_eq!(session.player_number(), Some(5));
}

#[test]
fn negotiation_avoids_numbers_already_on_the_network() {
    let mut session = session();
    session.start(Millis(0)).unwrap();

    // Player 5 announces itself during our listening phase.
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &their_keepalive(5, "CDJ-3000"));
    bring_online(&mut session);

    assert_eq!(
        session.player_number(),
        Some(6),
        "5 was taken, so we should have moved on"
    );
}

#[test]
fn an_objection_mid_claim_moves_us_to_the_next_number() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    run_until(&mut session, 1_000, 100); // now claiming 5

    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &their_claim(5));
    run_until(&mut session, 5_000, 100);

    assert_eq!(session.player_number(), Some(6));
}

#[test]
fn our_own_claim_number_echoing_back_is_not_an_objection() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    // Through the MAC and IP claims, into the final number claim. Each of the
    // four phases is three packets 300 ms apart, so the number claim begins at
    // 2700 ms.
    run_until(&mut session, 2_800, 100);
    assert!(matches!(
        session.state(),
        VcdjState::ClaimNumber { number: 5, .. }
    ));

    // The kernel hands our own broadcast claim back to us. It carries no MAC,
    // so only its source address says it is ours.
    let ours = session
        .transport()
        .sent_on(Channel::Announce)
        .filter_map(|d| {
            KeepAlivePacket::decode(&d.payload)
                .ok()
                .map(|p| (p, d.payload.clone()))
        })
        .find(|(p, _)| p.packet_type() == KeepAliveType::Number)
        .expect("we should have claimed a number")
        .1;
    session
        .transport_mut()
        .push(Channel::Announce, OUR_IP, &ours);
    run_until(&mut session, NEGOTIATION_MS + 100, 100);

    assert_eq!(session.player_number(), Some(5));
}

#[test]
fn a_demanded_number_fails_loudly_rather_than_moving() {
    let mut session = Session::new(
        MockTransport::with_identity(OUR_IP, OUR_MAC),
        config().with_number(NumberRequest::Fixed(3)),
    );
    session.start(Millis(0)).unwrap();
    // Far enough in to be claiming, not far enough to be online.
    run_until(&mut session, 1_000, 100);
    assert!(matches!(
        session.state(),
        VcdjState::ClaimMac { number: 3, .. }
    ));

    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &their_claim(3));
    let events = run(&mut session, 1_100, NEGOTIATION_MS, 100);

    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::NegotiationFailed(NegotiationFailure::NumberTaken(3))
        )),
        "{events:?}"
    );
    assert_eq!(session.player_number(), None);
}

#[test]
fn a_negotiation_failure_is_reported_once_not_on_every_poll() {
    let mut session = Session::new(
        MockTransport::with_identity(OUR_IP, OUR_MAC),
        config().with_number(NumberRequest::Fixed(3)),
    );
    session.start(Millis(0)).unwrap();
    run_until(&mut session, 1_000, 100);

    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &their_claim(3));
    let events = run(&mut session, 1_100, 20_000, 100);

    let failures = events
        .iter()
        .filter(|e| matches!(e, Event::NegotiationFailed(_)))
        .count();
    assert_eq!(failures, 1, "a failure should be announced once");
}

#[test]
fn once_online_a_challenge_is_answered_not_conceded() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);
    assert_eq!(session.player_number(), Some(5));

    session.transport_mut().clear_sent();
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &their_claim(5));
    let events = drain(&mut session, 4_100);

    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::NumberDefended {
                player_number: 5,
                challenger,
            } if *challenger == THEIR_IP
        )),
        "{events:?}"
    );
    assert_eq!(session.player_number(), Some(5), "we must not give it up");

    let defence = session
        .transport()
        .last_sent()
        .expect("a defence should have been sent");
    assert_eq!(defence.dest, Destination::Unicast(THEIR_IP));
}

// ---- the heartbeat ---------------------------------------------------------

#[test]
fn the_heartbeat_fires_on_schedule_and_not_before() {
    let mut session = Session::new(
        MockTransport::with_identity(OUR_IP, OUR_MAC),
        // Silence our own status packets so only heartbeats are in play.
        config().without_status_publishing(),
    );
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);

    fn heartbeats(session: &Session<MockTransport>) -> usize {
        session
            .transport()
            .sent_on(Channel::Announce)
            .filter(|d| {
                KeepAlivePacket::decode(&d.payload)
                    .is_ok_and(|p| p.packet_type() == KeepAliveType::Status)
            })
            .count()
    }

    let VcdjState::Online { next_keepalive, .. } = session.state() else {
        panic!("expected to be online");
    };
    let before = heartbeats(&session);

    // One millisecond short of the deadline.
    drain(&mut session, next_keepalive.0 - 1);
    assert_eq!(heartbeats(&session), before, "the heartbeat fired early");

    // On the deadline.
    drain(&mut session, next_keepalive.0);
    assert_eq!(
        heartbeats(&session),
        before + 1,
        "the heartbeat did not fire"
    );
}

#[test]
fn a_late_poll_does_not_produce_a_burst_of_backdated_heartbeats() {
    let mut session = Session::new(
        MockTransport::with_identity(OUR_IP, OUR_MAC),
        config().without_status_publishing(),
    );
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);

    session.transport_mut().clear_sent();
    // A caller that was blocked for a minute.
    drain(&mut session, 64_000);

    let sent = session.transport().sent_on(Channel::Announce).count();
    assert_eq!(
        sent, 1,
        "missed deadlines must not accumulate into a flood, sent {sent}"
    );
}

#[test]
fn our_heartbeat_carries_our_identity_and_number() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);

    let keepalive = decoded_keepalives(&session)
        .into_iter()
        .find(|p| p.packet_type() == KeepAliveType::Status)
        .expect("expected a heartbeat");

    let KeepAliveBody::Status {
        player_number,
        ip,
        mac,
        ..
    } = keepalive.body
    else {
        panic!("expected a status body");
    };
    assert_eq!(player_number, 5);
    assert_eq!(ip, OUR_IP);
    assert_eq!(mac, OUR_MAC);
    assert_eq!(keepalive.model, "Virtual CDJ");
}

#[test]
fn heartbeats_are_broadcast_not_unicast_by_default() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);

    assert!(session
        .transport()
        .sent_on(Channel::Announce)
        .all(|d| d.dest == Destination::Broadcast));
}

#[test]
fn stopping_ends_the_heartbeat() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);

    session.stop();
    session.transport_mut().clear_sent();
    run_until(&mut session, 20_000, 500);

    assert_eq!(
        session.transport().sent.len(),
        0,
        "a stopped session must go silent"
    );
    assert_eq!(session.player_number(), None);
}

// ---- realtime --------------------------------------------------------------

#[test]
fn a_beat_packet_becomes_a_beat_event() {
    let mut session = session();
    session
        .transport_mut()
        .push(Channel::Beat, THEIR_IP, &their_beat(2, 3));

    let events = drain(&mut session, 0);
    let beat = events
        .iter()
        .find_map(|e| match e {
            Event::Beat {
                player_number,
                beat,
                bpm,
                next_beat_ms,
                ..
            } => Some((*player_number, *beat, *bpm, *next_beat_ms)),
            _ => None,
        })
        .expect("expected a beat event");

    assert_eq!(beat.0, 2);
    assert_eq!(beat.1, 3);
    assert_eq!(beat.2, Some(Bpm(128.0)));
    assert_eq!(beat.3, 468);
}

#[test]
fn the_reported_tempo_includes_pitch() {
    let mut session = session();
    let mut packet = BeatPacket::decode(&their_beat(2, 1)).unwrap();
    if let BeatBody::Beat { ref mut pitch, .. } = packet.body {
        *pitch = Pitch(1.06);
    }
    let mut buf = [0u8; MAX_PACKET_LEN];
    let len = packet.encode(&mut buf).unwrap();
    session
        .transport_mut()
        .push(Channel::Beat, THEIR_IP, &buf[..len]);

    let events = drain(&mut session, 0);
    let Some(Event::Beat { bpm: Some(bpm), .. }) =
        events.iter().find(|e| matches!(e, Event::Beat { .. }))
    else {
        panic!("{events:?}");
    };
    assert!(
        (bpm.0 - 135.68).abs() < 0.1,
        "a deck at +6% on a 128 BPM track produces ~135.7, got {bpm:?}"
    );
}

#[test]
fn on_air_changes_are_reported_once_not_on_every_packet() {
    let mut session = session();
    let packet = BeatPacket::new(
        model("DJM-900NXS2"),
        33,
        BeatBody::MixerOnAir {
            channels: [1, 0, 2, 0],
        },
    );
    let mut buf = [0u8; MAX_PACKET_LEN];
    let len = packet.encode(&mut buf).unwrap();

    // The mixer has to exist before its channel state can be remembered.
    let mixer_keepalive = {
        let ka = KeepAlivePacket::new(
            model("DJM-900NXS2"),
            DeviceType::Djm,
            KeepAliveBody::Status {
                player_number: 33,
                related_player_number: 33,
                mac: THEIR_MAC,
                ip: THEIR_IP,
                device_count: 2,
                flags: crate::packet::StatusFeatureFlags::IS_MIXER,
                extra_flags: 0,
            },
        );
        let mut b = [0u8; MAX_PACKET_LEN];
        let n = ka.encode(&mut b).unwrap();
        b[..n].to_vec()
    };
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &mixer_keepalive);
    drain(&mut session, 0);

    for _ in 0..5 {
        session
            .transport_mut()
            .push(Channel::Beat, THEIR_IP, &buf[..len]);
    }
    let events = drain(&mut session, 100);

    let changes = events
        .iter()
        .filter(|e| matches!(e, Event::OnAirChanged { .. }))
        .count();
    assert_eq!(
        changes, 1,
        "five identical mixer packets should mean one change, got {changes}"
    );
}

// ---- sending ---------------------------------------------------------------

#[test]
fn send_methods_refuse_before_we_have_a_number() {
    let mut session = session();
    assert_eq!(
        session.query_media(2, PlayerSlot::Usb),
        Err(SessionError::NotOnline)
    );
    assert_eq!(
        session.load_track(2, 2, PlayerSlot::Usb, 1),
        Err(SessionError::NotOnline)
    );
}

#[test]
fn a_media_query_goes_to_the_right_device() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    session
        .transport_mut()
        .push(Channel::Announce, THEIR_IP, &their_keepalive(2, "CDJ-3000"));
    bring_online(&mut session);

    session.transport_mut().clear_sent();
    session.query_media(2, PlayerSlot::Usb).unwrap();

    let sent = session.transport().last_sent().unwrap();
    assert_eq!(sent.channel, Channel::Status);
    assert_eq!(sent.dest, Destination::Unicast(THEIR_IP));

    let decoded = StatusPacket::decode(&sent.payload).unwrap();
    assert_eq!(
        decoded.body,
        StatusBody::MediaQuery {
            player_number: 2,
            slot: PlayerSlot::Usb,
            reply_to: OUR_IP,
        }
    );
}

#[test]
fn addressing_an_absent_device_is_refused() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);

    assert!(matches!(
        session.query_media(4, PlayerSlot::Usb),
        Err(SessionError::Encode(CodecError::InvalidField { .. }))
    ));
}

#[test]
fn a_fader_start_for_one_player_leaves_the_others_alone() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);

    session.transport_mut().clear_sent();
    session
        .fader_start_one(2, FaderStartCommand::Start)
        .unwrap();

    let sent = session.transport().last_sent().unwrap();
    assert_eq!(sent.channel, Channel::Beat);
    assert_eq!(sent.dest, Destination::Broadcast);

    let BeatBody::FaderStart { commands } = BeatPacket::decode(&sent.payload).unwrap().body else {
        panic!("expected a fader-start packet");
    };
    assert_eq!(
        commands,
        [
            FaderStartCommand::Ignore,
            FaderStartCommand::Start,
            FaderStartCommand::Ignore,
            FaderStartCommand::Ignore,
        ]
    );
}

#[test]
fn a_fader_start_beyond_four_channels_is_refused() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);

    assert!(matches!(
        session.fader_start_one(6, FaderStartCommand::Start),
        Err(SessionError::Encode(CodecError::InvalidField { .. }))
    ));
}

#[test]
fn our_status_packets_carry_an_incrementing_counter() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    run_until(&mut session, 6_000, 100);

    let counters: Vec<u32> = session
        .transport()
        .sent_on(Channel::Status)
        .filter_map(|d| StatusPacket::decode(&d.payload).ok())
        .filter_map(|p| match p.body {
            StatusBody::Cdj(status) => Some(status.packet_count),
            _ => None,
        })
        .collect();

    assert!(counters.len() > 3, "expected several status packets");
    assert!(
        counters.windows(2).all(|w| w[1] == w[0] + 1),
        "counters must increment by one: {counters:?}"
    );
}

#[test]
fn status_publishing_can_be_turned_off() {
    let mut session = Session::new(
        MockTransport::with_identity(OUR_IP, OUR_MAC),
        config().without_status_publishing(),
    );
    session.start(Millis(0)).unwrap();
    run_until(&mut session, 6_000, 100);

    assert_eq!(session.transport().sent_on(Channel::Status).count(), 0);
}

#[test]
fn what_we_advertise_about_ourselves_reaches_the_wire() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);

    session.set_own_status(OwnStatus {
        playing: true,
        on_air: true,
        master: true,
        bpm: Bpm::from_raw(12800),
        ..OwnStatus::default()
    });
    session.transport_mut().clear_sent();
    run_until(&mut session, 5_000, 100);

    let status = session
        .transport()
        .sent_on(Channel::Status)
        .filter_map(|d| StatusPacket::decode(&d.payload).ok())
        .find_map(|p| match p.body {
            StatusBody::Cdj(status) => Some(status),
            _ => None,
        })
        .expect("expected a status packet");

    assert!(status.state.contains(StateFlags::PLAY));
    assert!(status.state.contains(StateFlags::MASTER));
    assert_eq!(status.bpm, Some(Bpm(128.0)));
}

// ---- scheduling ------------------------------------------------------------

#[test]
fn a_transport_failure_is_reported_as_an_error() {
    let mut session = session();
    session.transport_mut().fail_next_recv = true;
    assert!(matches!(
        session.poll(Millis(0)),
        Err(SessionError::Transport(_))
    ));
}

#[test]
fn poll_settles_at_none_when_there_is_nothing_to_do() {
    let mut session = session();
    assert_eq!(session.poll(Millis(0)).unwrap(), None);
    assert_eq!(session.poll(Millis(0)).unwrap(), None);
}

#[test]
fn the_next_deadline_is_never_in_the_past() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);

    for now in [0u64, 4_000, 100_000] {
        let deadline = session.next_deadline(Millis(now));
        assert!(
            deadline.0 >= now,
            "deadline {deadline:?} is behind now={now}"
        );
    }
}

#[test]
fn an_idle_session_schedules_only_the_expiry_sweep() {
    let mut session = session();
    session.start(Millis(0)).unwrap();
    bring_online(&mut session);

    let deadline = session.next_deadline(Millis(4_000));
    // Whatever it is, it must be soon enough to keep the heartbeat on time.
    assert!(
        deadline.since(Millis(4_000)) <= Timing::DEFAULT.keepalive_interval_ms,
        "a session must never sleep through its own heartbeat"
    );
}

#[test]
fn a_backlog_of_packets_loses_nothing() {
    let mut session = session();
    // Far more packets than the event queue holds. Because `poll` returns one
    // event per call and only reads another packet once the queue is empty,
    // the queue cannot build up — every beat should come through.
    for beat in 0..64u8 {
        session
            .transport_mut()
            .push(Channel::Beat, THEIR_IP, &their_beat(2, (beat % 4) + 1));
    }

    let events = drain(&mut session, 0);
    let beats = events
        .iter()
        .filter(|e| matches!(e, Event::Beat { .. }))
        .count();
    assert_eq!(beats, 64, "a backlog must not cost us events");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::EventsDropped { .. })),
        "nothing should have been dropped: {events:?}"
    );
}
