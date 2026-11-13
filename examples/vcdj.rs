//! Joins the network as a virtual CDJ.
//!
//! Unlike `monitor`, this one claims a player number and starts sending
//! keepalives, so the CDJs will show it as an extra player. Once online it
//! queries every device's USB slot.
//!
//! ```console
//! $ cargo run --example vcdj -- 192.168.1.200 02:11:22:33:44:55
//! ```
//!
//! The address and MAC have to be supplied because Rust's standard library
//! cannot enumerate network interfaces. `ip addr` or `ifconfig` will tell you
//! both.

use std::time::Duration;

use prolink::adapter::std_udp::StdUdpTransport;
use prolink::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(ip), Some(mac)) = (args.next(), args.next()) else {
        eprintln!("usage: vcdj <our-ip> <our-mac>");
        eprintln!("   eg: vcdj 192.168.1.200 02:11:22:33:44:55");
        std::process::exit(2);
    };
    let ip = ip.parse()?;
    let mac: MacAddr = mac.parse()?;

    let transport = StdUdpTransport::bind_auto()?.with_identity(ip, mac);
    let clock = StdClock::new();

    let config = VcdjConfig::new("Virtual CDJ")
        .with_identity(ip, mac)
        // 1 through 4 are the physical decks; start looking above them.
        .with_number(NumberRequest::Auto { first: 5 });

    let mut session = Session::new(transport, config);
    session.start(clock.now())?;
    println!("negotiating a player number...");

    let mut queried = Vec::new();

    loop {
        let now = clock.now();

        while let Some(event) = session.poll(now)? {
            match event {
                Event::Online { player_number } => {
                    println!("online as player {player_number}");
                }

                Event::NegotiationFailed(reason) => {
                    eprintln!("could not join the network: {reason:?}");
                    return Ok(());
                }

                Event::NumberDefended {
                    player_number,
                    challenger,
                } => println!("{challenger} tried to take player {player_number}; refused"),

                Event::DeviceAppeared {
                    player_number,
                    model,
                    ip,
                    ..
                } => println!("+ player {player_number}: {model} at {ip}"),

                Event::DeviceLost { player_number } => {
                    println!("- player {player_number}");
                    queried.retain(|n| *n != player_number);
                }

                Event::MediaInfo(info) => println!(
                    "  player {} {:?}: \"{}\", {} tracks, {} GB free",
                    info.player_number,
                    info.slot,
                    info.name,
                    info.track_count,
                    info.bytes_free / 1_000_000_000,
                ),

                Event::MasterChanged { player_number } => {
                    println!("  player {player_number} is now tempo master")
                }

                _ => {}
            }
        }

        // Once online, ask each device what is in its USB slot. Replies come
        // back asynchronously as MediaInfo events.
        if session.state().is_online() {
            let targets: Vec<u8> = session
                .devices()
                .map(|device| device.player_number)
                .filter(|n| !queried.contains(n))
                .collect();

            for target in targets {
                queried.push(target);
                if let Err(error) = session.query_media(target, PlayerSlot::Usb) {
                    eprintln!("  query to player {target} failed: {error}");
                }
            }
        }

        let timeout = Duration::from_millis(session.next_deadline(now).since(now));
        session.transport_mut().wait_readable(timeout)?;
    }
}
