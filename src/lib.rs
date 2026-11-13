//! Pioneer Pro DJ Link — a `no_std`-capable protocol library with a pluggable
//! network adapter.
//!
//! The core of this crate never touches a socket. Everything that talks to the
//! network goes through the [`Transport`] trait, so the same [`Session`] logic
//! runs on a desktop, inside an async embedded executor, or against a recorded
//! capture in a unit test.
//!
//! # Using it with `std`
//!
//! Enable the `std` feature (on by default) and you get [`StdUdpTransport`], a
//! ready-made adapter that binds the three Pro DJ Link UDP ports directly:
//!
//! ```no_run
//! use prolink::prelude::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let transport = StdUdpTransport::bind_auto()?;
//! let clock = StdClock::new();
//!
//! let config = VcdjConfig::new("Virtual CDJ")
//!     .with_identity(transport.local_ipv4().unwrap(), transport.local_mac().unwrap());
//!
//! let mut session = Session::new(transport, config);
//! session.start(clock.now())?;
//!
//! loop {
//!     let now = clock.now();
//!     while let Some(event) = session.poll(now)? {
//!         println!("{event:?}");
//!     }
//!     let timeout = std::time::Duration::from_millis(session.next_deadline(now).since(now));
//!     session.transport_mut().wait_readable(timeout)?;
//! }
//! # }
//! ```
//!
//! # Using it without `std`
//!
//! Build with `default-features = false` and implement [`Transport`] yourself.
//! The trait is deliberately small, synchronous and non-blocking, which makes it
//! implementable on top of smoltcp, embassy-net, a raw Ethernet driver, or a
//! canned byte stream:
//!
//! ```
//! use prolink::adapter::{Channel, Destination, Received, Transport};
//! use prolink::wire::MacAddr;
//! use core::net::Ipv4Addr;
//!
//! struct MyTransport { /* your socket handles */ }
//!
//! #[derive(Debug)]
//! struct MyError;
//!
//! impl Transport for MyTransport {
//!     type Error = MyError;
//!
//!     fn send(&mut self, channel: Channel, dest: Destination, payload: &[u8])
//!         -> Result<(), Self::Error>
//!     {
//!         let _ = (channel.port(), dest, payload);
//!         Ok(())
//!     }
//!
//!     fn poll_recv(&mut self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error> {
//!         let _ = buf;
//!         Ok(None) // nothing pending right now — never block here
//!     }
//! }
//! ```
//!
//! The rest of the crate — packet codecs, the device registry, the virtual-CDJ
//! state machine, [`Session`] itself — is identical in both builds.
//!
//! [`Transport`]: crate::adapter::Transport
//! [`Session`]: crate::session::Session
//! [`StdUdpTransport`]: crate::adapter::std_udp::StdUdpTransport

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod adapter;
pub mod constants;
pub mod device;
pub mod error;
pub mod event;
pub mod packet;
pub mod registry;
pub mod session;
pub mod time;
pub mod vcdj;
pub mod wire;

#[cfg(test)]
mod session_tests;

/// The types most users need, in one `use`.
pub mod prelude {
    pub use crate::adapter::{Channel, Destination, Received, Transport};
    pub use crate::constants::{Timing, MAX_PACKET_LEN};
    pub use crate::device::{Device, MixerState, PlayerState};
    pub use crate::error::{CodecError, SessionError};
    pub use crate::event::{Event, StatusChange};
    pub use crate::packet::{
        DeviceType, FaderStartCommand, Packet, PlayState, PlayerSlot, StorageIndicator,
    };
    pub use crate::session::Session;
    pub use crate::time::{Clock, Millis};
    pub use crate::vcdj::{NegotiationFailure, NumberRequest, OwnStatus, VcdjConfig, VcdjState};
    pub use crate::wire::{Bpm, FixedStr, MacAddr, Pitch};

    #[cfg(feature = "std")]
    pub use crate::adapter::std_udp::StdUdpTransport;
    #[cfg(feature = "std")]
    pub use crate::time::StdClock;
}
