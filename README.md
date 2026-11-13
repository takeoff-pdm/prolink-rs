# prolink

A Rust library for the Pioneer Pro DJ Link protocol — the network CDJs, XDJs
and DJM mixers use to talk to each other — where **the network itself is a
trait**.

Point it at real UDP sockets, at an embedded network stack, or at a recorded
capture, without changing a line of protocol code.

```rust
use prolink::prelude::*;

let transport = StdUdpTransport::bind_auto()?;
let clock = StdClock::new();

let mut session = Session::new(transport, VcdjConfig::new("Virtual CDJ"));
session.start(clock.now())?;

loop {
    let now = clock.now();
    while let Some(event) = session.poll(now)? {
        match event {
            Event::Online { player_number } => println!("we are player {player_number}"),
            Event::Beat { player_number, beat, bpm, .. } => {
                println!("player {player_number}: beat {beat}, {bpm:?}")
            }
            _ => {}
        }
    }
    let timeout = std::time::Duration::from_millis(session.next_deadline(now).since(now));
    session.transport_mut().wait_readable(timeout)?;
}
```

## Two ways to use it

**With `std`** (the default), [`StdUdpTransport`] binds ports 50000–50002 for
you and you never see the trait at all.

**Without `std`**, implement [`Transport`] over whatever your hardware offers.
It has two required methods:

```rust
pub trait Transport {
    type Error: core::fmt::Debug;

    fn send(&mut self, channel: Channel, dest: Destination, payload: &[u8])
        -> Result<(), Self::Error>;

    fn poll_recv(&mut self, buf: &mut [u8])
        -> Result<Option<Received>, Self::Error>;
}
```

That is the entire seam. `examples/custom_adapter.rs` is a complete
`core`-only implementation — no allocator, no async, no `dyn` — running the
same `Session` the `std` examples use.

```toml
[dependencies]
prolink = { version = "0.1", default-features = false }            # no_std, no alloc
prolink = { version = "0.1", default-features = false, features = ["alloc"] }
prolink = "0.1"                                                     # std, the default
```

| Feature   | Default | What it adds                                          |
|-----------|---------|-------------------------------------------------------|
| `std`     | yes     | `StdUdpTransport`, `StdClock`, `std::error::Error`     |
| `alloc`   | via std | `ReplayTransport` for recorded captures                |
| `testing` | no      | `MockTransport`, for testing *your* code               |

## Why synchronous and non-blocking

`poll_recv` returns `Ok(None)` rather than waiting. That single decision is
what lets one `Session` implementation run under a `std` thread, under an async
embedded executor, and over a canned byte stream:

- a **blocking** trait would need a thread, which bare metal does not have;
- an **async** trait would force every caller into a runtime and make the
  replay adapter absurd.

Waiting is therefore not part of the trait. Adapters that *can* wait offer it
as their own inherent method — `StdUdpTransport::wait_readable` blocks on the
three sockets; an embassy adapter would expose `async fn wait_recv_ready`. It
is the same split `embedded-io` draws between `Read` and `ReadReady`.

Time works the same way: `poll` takes the current instant as an argument rather
than owning a clock, so the replay adapter can drive a virtual clock from
capture timestamps and tests can simply say `session.poll(Millis(1500))`.

## What it does

- **Announce channel (50000)** — device discovery, liveness, and the full
  four-stage player-number negotiation, including defending a number once held.
- **Beat channel (50001)** — beat packets with look-ahead timing, CDJ-3000
  absolute position, mixer on-air state, fader start.
- **Status channel (50002)** — full CDJ status, mixer status, media-slot
  queries and replies, load-track commands.
- **Device tracking** — a fixed-capacity registry with TTL expiry and
  pitch-based playhead extrapolation between status packets.
- **Virtual CDJ** — claim a number, hold it with a 1.5-second heartbeat, and
  publish status so players will answer metadata requests.

Not included: the RemoteDB metadata/artwork protocol (TCP) and NFS track-file
fetching. Both need an ordered byte stream and multi-megabyte buffers, so they
belong behind a separate trait rather than bolted onto this one.

## Design notes

**Decoding is permissive.** This protocol is reverse-engineered from hardware
nobody here controls, and firmware updates ship without warning. Unknown enum
discriminants decode to `Unknown(u8)`; unknown flag bits are preserved; trailing
bytes are ignored. A packet is rejected only when it is too short for a field
that is needed, or carries no Pro DJ Link magic at all.

**Decode failures are events, not errors.** `Event::DecodeError` rather than
`Err`. Unfamiliar hardware on the network must never be able to stop your main
loop; only a broken socket returns `Err`.

**The receive path does not allocate.** Every string field in the protocol is
fixed-width, so `FixedStr<N>` stores them inline. Six CDJ-3000s produce tens of
packets a second, forever — putting that on a heap-constrained device's
allocator would eventually fragment it.

**Timing is self-correcting.** Deadlines are recomputed from the current
instant, never accumulated, so a caller that was blocked for a minute sends one
heartbeat when it comes back, not forty.

## Caveats

**Negotiation timing is unverified.** Neither reference implementation this was
built from performs the claim sequence at all — both start broadcasting a
heartbeat with a hard-coded number. The four-stage sequence and its 300 ms
spacing come from published analysis of captured traffic rather than from
working code. Everything lives in `Timing` so correcting it is a one-line
change.

**Byte-exact re-encoding is not offered for CDJ status packets.** A CDJ-3000
status packet is over a kilobyte, most of it uncharted; keeping the tail would
mean either an allocation per packet or a kilobyte of padding per struct.
Packets this library *sends* are built from scratch and are byte-exact by
construction, which is the property that matters on the wire.

**Port sharing.** Sockets are bound with `SO_REUSEADDR` and `SO_REUSEPORT` so
this can run alongside rekordbox or a second instance. Without that it would
fail to bind the moment anything else on the machine is listening.

## Examples

```console
cargo run --example monitor           # listen only — invisible to the CDJs
cargo run --example vcdj -- <ip> <mac>  # join the network as a player
cargo run --example custom_adapter    # implement Transport yourself
```

`monitor` never calls `start()`, so it transmits nothing and is safe to run at
a gig.

## Testing

```console
cargo test --all-features                                          # 166 tests
cargo build --no-default-features --target thumbv7em-none-eabihf   # bare metal
```

The bare-metal cross-build is part of CI, not an afterthought: a `#![no_std]`
attribute alone will not catch a `std::` path that sneaks in through a
dependency. Tests themselves run with `std`, because the test harness requires
it — the protocol code is identical either way, and the cross-build is what
proves the `no_std` build is real.

Beyond round-trip tests, every packet module asserts that **every truncation of
every packet** returns an error rather than panicking or decoding into
plausible nonsense — cheap insurance on code that parses untrusted network
input. Session behaviour is tested through `MockTransport` with an explicit
clock, so timing tests read as plainly as "nothing at 1.4 s, one heartbeat at
1.6 s".

## Prior art

The wire format was derived from
[python-prodj-link](https://github.com/flesniak/python-prodj-link),
[prolink-connect](https://github.com/evanpurkhiser/prolink-connect), and
Deep Symmetry's [dysentery](https://github.com/Deep-Symmetry/dysentery)
analysis. This library owes all three a great deal.

## License

MIT OR Apache-2.0.

[`StdUdpTransport`]: https://docs.rs/prolink/latest/prolink/adapter/std_udp/struct.StdUdpTransport.html
[`Transport`]: https://docs.rs/prolink/latest/prolink/adapter/trait.Transport.html
# prolink-rs
