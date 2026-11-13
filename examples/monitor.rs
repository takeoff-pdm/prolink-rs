//! Watches a Pro DJ Link network and prints what happens.
//!
//! This one only listens — it never claims a player number, so it is invisible
//! to the CDJs and safe to run at a gig.
//!
//! ```console
//! $ cargo run --example monitor
//! ```

use std::time::Duration;

use prolink::adapter::std_udp::StdUdpTransport;
use prolink::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = StdUdpTransport::bind_auto()?;
    let clock = StdClock::new();

    println!("listening on 50000/50001/50002 — Ctrl-C to stop");

    // No `start()` call: without it the session never transmits.
    let mut session = Session::new(transport, VcdjConfig::new("Monitor"));

    loop {
        let now = clock.now();

        while let Some(event) = session.poll(now)? {
            match event {
                Event::DeviceAppeared {
                    player_number,
                    model,
                    ip,
                    device_type,
                    ..
                } => println!("+ player {player_number}: {model} ({device_type:?}) at {ip}"),

                Event::DeviceLost { player_number } => println!("- player {player_number}"),

                Event::Beat {
                    player_number,
                    beat,
                    bpm,
                    ..
                } => {
                    let tempo = bpm.map_or_else(|| "--".into(), |bpm| format!("{bpm:.1}"));
                    println!("  player {player_number}  beat {beat}/4  {tempo} BPM");
                }

                Event::TrackLoaded {
                    player_number,
                    track_id,
                    slot,
                    ..
                } => println!("  player {player_number} loaded track {track_id} from {slot:?}"),

                Event::MasterChanged { player_number } => {
                    println!("  player {player_number} is now tempo master")
                }

                Event::MediaChanged {
                    player_number,
                    slot,
                    state,
                } => println!("  player {player_number} {slot:?}: {state:?}"),

                Event::OnAirChanged { channels } => {
                    let live: Vec<String> = channels
                        .iter()
                        .filter(|n| **n != 0)
                        .map(|n| n.to_string())
                        .collect();
                    println!("  on air: {}", live.join(", "));
                }

                Event::DecodeError { source, error, .. } => {
                    eprintln!("  ? undecodable packet from {source}: {error}")
                }

                // Status arrives several times a second per deck; printing it
                // all would drown out everything above.
                Event::DeviceStatus { .. } | Event::Position { .. } => {}

                other => println!("  {other:?}"),
            }
        }

        // Sleep until either a datagram arrives or the session has something
        // scheduled, whichever comes first.
        let timeout = Duration::from_millis(session.next_deadline(now).since(now));
        session.transport_mut().wait_readable(timeout)?;
    }
}
