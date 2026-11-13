//! Simulates two CDJs on localhost so a Pro DJ Link consumer can be tested
//! without hardware.
//!
//! Sends, from an ephemeral port to 127.0.0.1, exactly what real players
//! broadcast: a keepalive every 1.5 s, a status packet every 200 ms and a beat
//! packet on every beat. Player 1 plays at 128 BPM and is tempo master, player
//! 2 plays at 126 BPM with +2 % pitch and is synced.
//!
//! ```console
//! $ cargo run --example simulate [target-ip]
//! ```

use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

use prolink::adapter::Channel;
use prolink::packet::{BeatBody, BeatDistances, BeatPacket};
use prolink::prelude::*;
use prolink::vcdj::outbound;

struct Deck {
    number: u8,
    model: &'static str,
    ip: Ipv4Addr,
    bpm: f32,
    pitch: f32,
    master: bool,
    synced: bool,
    beat: u8,
    next_beat: Instant,
}

impl Deck {
    fn config(&self) -> VcdjConfig {
        VcdjConfig::new(self.model)
            .with_identity(self.ip, MacAddr([0x74, 0x5e, 0x1c, 0, 0, self.number]))
    }

    fn beat_len(&self) -> Duration {
        Duration::from_secs_f32(60.0 / (self.bpm * self.pitch))
    }
}

fn main() {
    let target: Ipv4Addr = std::env::args()
        .nth(1)
        .map(|a| a.parse().expect("target must be an IPv4 address"))
        .unwrap_or(Ipv4Addr::LOCALHOST);
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind");
    socket.set_broadcast(true).expect("broadcast");

    let start = Instant::now();
    let mut decks = vec![
        Deck { number: 1, model: "CDJ-3000", ip: Ipv4Addr::new(192, 168, 1, 11), bpm: 128.0, pitch: 1.0, master: true, synced: false, beat: 1, next_beat: start },
        Deck { number: 2, model: "CDJ-2000NXS2", ip: Ipv4Addr::new(192, 168, 1, 12), bpm: 126.0, pitch: 1.02, master: false, synced: true, beat: 3, next_beat: start },
    ];

    let mut buf = [0u8; MAX_PACKET_LEN];
    let mut next_keepalive = start;
    let mut next_status = start;
    let mut packet_count = 0u32;
    let send = |socket: &UdpSocket, channel: Channel, bytes: &[u8]| {
        socket
            .send_to(bytes, (target, channel.port()))
            .expect("send");
    };

    println!("simulating {} decks towards {target}", decks.len());
    loop {
        let now = Instant::now();

        if now >= next_keepalive {
            for deck in &decks {
                let len = outbound::keepalive(&deck.config(), deck.number, decks.len() as u8, &mut buf).unwrap();
                send(&socket, Channel::Announce, &buf[..len]);
            }
            next_keepalive = now + Duration::from_millis(1500);
        }

        if now >= next_status {
            for deck in &decks {
                packet_count += 1;
                let status = OwnStatus {
                    playing: true,
                    on_air: deck.master,
                    synced: deck.synced,
                    master: deck.master,
                    bpm: Some(Bpm(deck.bpm)),
                    pitch: Pitch(deck.pitch),
                    beat: deck.beat,
                };
                let len = outbound::own_status(&deck.config(), deck.number, &status, packet_count, &mut buf).unwrap();
                send(&socket, Channel::Status, &buf[..len]);
            }
            next_status = now + Duration::from_millis(200);
        }

        for deck in &mut decks {
            if now >= deck.next_beat {
                deck.beat = deck.beat % 4 + 1;
                let ms = deck.beat_len().as_millis() as u32;
                let to_bar = (5 - deck.beat as u32) % 4 * ms + ms;
                let body = BeatBody::Beat {
                    distances: BeatDistances {
                        next_beat: ms,
                        second_beat: 2 * ms,
                        next_bar: to_bar,
                        fourth_beat: 4 * ms,
                        second_bar: to_bar + 4 * ms,
                        eighth_beat: 8 * ms,
                    },
                    pitch: Pitch(deck.pitch),
                    bpm: Some(Bpm(deck.bpm)),
                    beat: deck.beat,
                    player_number: deck.number,
                };
                let packet = BeatPacket::new(FixedStr::new(deck.model).unwrap(), deck.number, body);
                let len = packet.encode(&mut buf).unwrap();
                send(&socket, Channel::Beat, &buf[..len]);
                deck.next_beat += deck.beat_len();
            }
        }

        std::thread::sleep(Duration::from_millis(5));
    }
}
