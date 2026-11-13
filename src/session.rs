//! The driver: transport in, events out.

use core::net::Ipv4Addr;

use crate::adapter::{Channel, Destination, Transport};
use crate::constants::MAX_PACKET_LEN;
use crate::device::{Device, MixerState, PlayerState};
use crate::error::{CodecError, SessionError};
use crate::event::{Event, StatusChange};
use crate::packet::beat::{BeatBody, BeatPacket};
use crate::packet::keepalive::{KeepAliveBody, KeepAlivePacket};
use crate::packet::status::{CdjStatus, PlayerSlot, StatusBody, StatusPacket};
use crate::packet::{FaderStartCommand, StateFlags};
use crate::registry::{DeviceRegistry, RegistryChange};
use crate::time::{Clock, Millis};
use crate::vcdj::negotiate::Action;
use crate::vcdj::{outbound, Negotiator, OwnStatus, VcdjConfig, VcdjState};

/// How many events can be queued before the oldest are discarded.
///
/// One inbound packet can produce several events, so a queue is needed; eight
/// is comfortably more than any single packet generates. Overflowing it means
/// the caller is not draining [`Session::poll`], which is reported rather than
/// hidden.
const EVENT_QUEUE_LEN: usize = 8;

/// Ties a [`Transport`] to the protocol state machines.
///
/// A session is driven entirely by [`poll`](Session::poll), which never blocks.
/// The usual shape is:
///
/// ```no_run
/// # use prolink::prelude::*;
/// # fn run<T: Transport>(mut session: Session<T>, clock: impl Clock) -> Result<(), SessionError<T::Error>> {
/// loop {
///     let now = clock.now();
///     while let Some(event) = session.poll(now)? {
///         // handle it
///     }
///     // nothing left to do until this instant
///     let _sleep_for = session.next_deadline(now).since(now);
/// }
/// # }
/// ```
#[derive(Debug)]
pub struct Session<T: Transport> {
    transport: T,
    config: VcdjConfig,
    negotiator: Negotiator,
    devices: DeviceRegistry,
    own_status: OwnStatus,
    packet_count: u32,
    rx: [u8; MAX_PACKET_LEN],
    tx: [u8; MAX_PACKET_LEN],
    queue: EventQueue,
    next_expiry_sweep: Millis,
    master: Option<u8>,
    started: bool,
    reported_failure: bool,
}

impl<T: Transport> Session<T> {
    /// Builds a session over `transport`.
    ///
    /// Any identity the adapter can report fills in what `config` left out, so
    /// a `std` caller usually does not have to supply an address at all.
    /// Nothing is transmitted until [`start`](Session::start) is called.
    pub fn new(transport: T, mut config: VcdjConfig) -> Self {
        config.resolve_identity(transport.local_ipv4(), transport.local_mac());
        let mac = config.mac.unwrap_or_default();

        Session {
            negotiator: Negotiator::new(config.number, config.timing, mac),
            transport,
            config,
            devices: DeviceRegistry::new(),
            own_status: OwnStatus::default(),
            packet_count: 0,
            rx: [0; MAX_PACKET_LEN],
            tx: [0; MAX_PACKET_LEN],
            queue: EventQueue::new(),
            next_expiry_sweep: Millis::ZERO,
            master: None,
            started: false,
            reported_failure: false,
        }
    }

    /// Begins claiming a player number.
    ///
    /// Until this is called the session only listens — which is a perfectly
    /// good way to use it if all you want is to watch the network.
    pub fn start(&mut self, now: Millis) -> Result<(), SessionError<T::Error>> {
        if self.config.identity().is_none() {
            return Err(SessionError::MissingIdentity);
        }
        self.started = true;
        self.reported_failure = false;
        self.next_expiry_sweep = now.add(self.config.timing.expiry_sweep_ms);
        if let Some(action) = self.negotiator.start(now) {
            self.perform(action, now)?;
        }
        Ok(())
    }

    /// Stops claiming a player number and gives up the one we hold.
    ///
    /// There is no goodbye packet in this protocol: other devices notice when
    /// the heartbeat stops, about five seconds later.
    pub fn stop(&mut self) {
        self.negotiator.stop();
        self.started = false;
    }

    /// Does at most one unit of work and returns at most one event.
    ///
    /// Returns `Ok(None)` once nothing is waiting to be received and no
    /// deadline is due — that is the signal to stop looping and sleep until
    /// [`next_deadline`](Session::next_deadline).
    ///
    /// A packet that fails to decode comes back as
    /// [`Event::DecodeError`], not as `Err`. Unfamiliar hardware on the
    /// network is not a reason to stop the caller's loop; only a broken
    /// transport is.
    pub fn poll(&mut self, now: Millis) -> Result<Option<Event>, SessionError<T::Error>> {
        loop {
            // 0. Anything already queued goes out first, so no event is lost
            //    for want of a return slot.
            if let Some(event) = self.queue.pop() {
                return Ok(Some(event));
            }

            // 0.5. Negotiation can fail either from a deadline (nowhere left
            //      to go) or from a packet (someone objected to a number we
            //      demanded), so the check lives here rather than next to
            //      either one.
            if let VcdjState::Failed(failure) = self.negotiator.state() {
                self.started = false;
                if !self.reported_failure {
                    self.reported_failure = true;
                    return Ok(Some(Event::NegotiationFailed(failure)));
                }
            }

            // 1. Expire silent devices. Ahead of receiving so that a flood of
            //    status traffic cannot keep a departed device alive.
            if now.reached(self.next_expiry_sweep) {
                self.next_expiry_sweep = now.add(self.config.timing.expiry_sweep_ms);
                let queue = &mut self.queue;
                let removed =
                    self.devices
                        .expire(now, self.config.timing.device_ttl_ms, |player_number| {
                            queue.push(Event::DeviceLost { player_number })
                        });
                if removed > 0 {
                    if self.master.is_some_and(|m| self.devices.get(m).is_none()) {
                        self.master = None;
                    }
                    continue;
                }
            }

            // 2. Send whatever the negotiator says is due. Also ahead of
            //    receiving: missing our own heartbeat deadline because six
            //    players are talking would drop us off the network.
            if self.started && self.negotiator.is_due(now) {
                if let Some(action) = self.negotiator.step(now, &self.devices) {
                    self.perform(action, now)?;
                }
                continue;
            }

            // 3. Receive.
            let received = self
                .transport
                .poll_recv(&mut self.rx)
                .map_err(SessionError::Transport)?;
            let Some(received) = received else {
                return Ok(None);
            };

            let payload_len = received.len.min(self.rx.len());
            match self.decode(received.channel, payload_len) {
                Ok(()) => {}
                Err(error) => {
                    return Ok(Some(Event::DecodeError {
                        channel: received.channel,
                        source: received.source,
                        error,
                    }))
                }
            }
            self.dispatch(received.channel, received.source, payload_len, now)?;
        }
    }

    /// [`poll`](Session::poll), taking the time from a [`Clock`].
    pub fn poll_clocked<C: Clock>(
        &mut self,
        clock: &C,
    ) -> Result<Option<Event>, SessionError<T::Error>> {
        self.poll(clock.now())
    }

    /// When this session next has something scheduled to do.
    ///
    /// Sleeping until this instant is safe: nothing will be missed, and
    /// nothing needs doing before then except receiving, which the transport
    /// will still have waiting.
    pub fn next_deadline(&self, now: Millis) -> Millis {
        let sweep = self.next_expiry_sweep;
        let negotiation = if self.started {
            self.negotiator.next_deadline()
        } else {
            Millis::NEVER
        };
        let deadline = sweep.min(negotiation);
        if deadline.0 < now.0 {
            now
        } else {
            deadline
        }
    }

    // ---- introspection -----------------------------------------------------

    /// Where we are in the process of joining the network.
    pub fn state(&self) -> VcdjState {
        self.negotiator.state()
    }

    /// Our player number, once negotiation has finished.
    pub fn player_number(&self) -> Option<u8> {
        self.negotiator.player_number()
    }

    /// Every device currently on the network.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter()
    }

    /// One device, by player number.
    pub fn device(&self, player_number: u8) -> Option<&Device> {
        self.devices.get(player_number)
    }

    /// The device currently acting as tempo master.
    pub fn master(&self) -> Option<&Device> {
        self.master.and_then(|number| self.devices.get(number))
    }

    /// A player's playhead position, extrapolated to `now`.
    ///
    /// See [`Device::position_ms`] for what "extrapolated" means here.
    pub fn position_ms(&self, player_number: u8, now: Millis) -> Option<u64> {
        self.devices.get(player_number)?.position_ms(now)
    }

    /// The transport, for adapter-specific operations such as
    /// [`StdUdpTransport::wait_readable`].
    ///
    /// [`StdUdpTransport::wait_readable`]: crate::adapter::std_udp::StdUdpTransport::wait_readable
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// The transport, by reference.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Takes the transport back, consuming the session.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// The configuration in use.
    pub fn config(&self) -> &VcdjConfig {
        &self.config
    }

    // ---- sending -----------------------------------------------------------

    /// Asks a player what is in one of its media slots.
    ///
    /// The answer arrives asynchronously as [`Event::MediaInfo`]; there is no
    /// request identifier in the protocol, so a caller with several queries in
    /// flight must match replies by their contents.
    pub fn query_media(
        &mut self,
        target: u8,
        slot: PlayerSlot,
    ) -> Result<(), SessionError<T::Error>> {
        let own = self.require_online()?;
        let ip = self.address_of(target)?;
        let len = outbound::media_query(&self.config, own, target, slot, &mut self.tx)?;
        self.transmit(Channel::Status, Destination::Unicast(ip), len)
    }

    /// Tells a player to load a track.
    ///
    /// `source_player` is whichever device holds the media, which need not be
    /// `target` — players read each other's USB sticks over the link.
    pub fn load_track(
        &mut self,
        target: u8,
        source_player: u8,
        slot: PlayerSlot,
        track_id: u32,
    ) -> Result<(), SessionError<T::Error>> {
        let own = self.require_online()?;
        let ip = self.address_of(target)?;
        let len = outbound::load_track(
            &self.config,
            own,
            source_player,
            slot,
            track_id,
            &mut self.tx,
        )?;
        self.transmit(Channel::Status, Destination::Unicast(ip), len)
    }

    /// Broadcasts a fader-start command for all four mixer channels.
    pub fn fader_start(
        &mut self,
        commands: [FaderStartCommand; 4],
    ) -> Result<(), SessionError<T::Error>> {
        let own = self.require_online()?;
        let len = outbound::fader_start(&self.config, own, commands, &mut self.tx)?;
        self.transmit(Channel::Beat, Destination::Broadcast, len)
    }

    /// Sends a fader-start command for one player, leaving the others alone.
    pub fn fader_start_one(
        &mut self,
        player_number: u8,
        command: FaderStartCommand,
    ) -> Result<(), SessionError<T::Error>> {
        let mut commands = [FaderStartCommand::Ignore; 4];
        // Mixer channels are numbered from one, as are players.
        let index = player_number.saturating_sub(1) as usize;
        if index >= commands.len() {
            return Err(SessionError::Encode(CodecError::InvalidField {
                field: "fader_start.player_number",
                reason: "a mixer has only four channels",
            }));
        }
        commands[index] = command;
        self.fader_start(commands)
    }

    /// Changes what this library advertises about itself.
    ///
    /// Takes effect on the next outgoing status packet.
    pub fn set_own_status(&mut self, status: OwnStatus) {
        self.own_status = status;
    }

    /// What this library is currently advertising about itself.
    pub fn own_status(&self) -> &OwnStatus {
        &self.own_status
    }

    // ---- internals ---------------------------------------------------------

    fn require_online(&self) -> Result<u8, SessionError<T::Error>> {
        self.player_number().ok_or(SessionError::NotOnline)
    }

    fn address_of(&self, player_number: u8) -> Result<Ipv4Addr, SessionError<T::Error>> {
        self.devices
            .get(player_number)
            .map(|device| device.ip)
            .ok_or(SessionError::Encode(CodecError::InvalidField {
                field: "target",
                reason: "no device with that player number is on the network",
            }))
    }

    fn transmit(
        &mut self,
        channel: Channel,
        dest: Destination,
        len: usize,
    ) -> Result<(), SessionError<T::Error>> {
        self.transport
            .send(channel, dest, &self.tx[..len])
            .map_err(SessionError::Transport)
    }

    fn perform(&mut self, action: Action, _now: Millis) -> Result<(), SessionError<T::Error>> {
        let (channel, dest, len) = match action {
            Action::SendHello => (
                Channel::Announce,
                Destination::Broadcast,
                outbound::hello(&self.config, &mut self.tx)?,
            ),
            Action::SendClaimMac { iteration } => (
                Channel::Announce,
                Destination::Broadcast,
                outbound::claim_mac(&self.config, iteration, &mut self.tx)?,
            ),
            Action::SendClaimIp { number, iteration } => (
                Channel::Announce,
                Destination::Broadcast,
                outbound::claim_ip(&self.config, number, iteration, &mut self.tx)?,
            ),
            Action::SendClaimNumber { number, iteration } => (
                Channel::Announce,
                Destination::Broadcast,
                outbound::claim_number(&self.config, number, iteration, &mut self.tx)?,
            ),
            Action::SendKeepAlive { number } => {
                let count = self.devices.len().saturating_add(1).min(u8::MAX as usize) as u8;
                let len = outbound::keepalive(&self.config, number, count, &mut self.tx)?;

                // Reaching Online is worth announcing exactly once.
                if !self.queue.announced_online {
                    self.queue.announced_online = true;
                    self.queue.push(Event::Online {
                        player_number: number,
                    });
                }

                if self.config.unicast_keepalives {
                    // Collect first: sending borrows `self` mutably.
                    let mut targets = [None; crate::constants::MAX_DEVICES];
                    for (slot, device) in targets.iter_mut().zip(self.devices.iter()) {
                        *slot = Some(device.ip);
                    }
                    for ip in targets.into_iter().flatten() {
                        self.transmit(Channel::Announce, Destination::Unicast(ip), len)?;
                    }
                }

                (Channel::Announce, Destination::Broadcast, len)
            }
            Action::SendStatus { number } => {
                if !self.config.publish_status {
                    return Ok(());
                }
                let len = outbound::own_status(
                    &self.config,
                    number,
                    &self.own_status,
                    self.packet_count,
                    &mut self.tx,
                )?;
                self.packet_count = self.packet_count.wrapping_add(1);
                (Channel::Status, Destination::Broadcast, len)
            }
            Action::DefendNumber { number, challenger } => {
                let len = outbound::claim_number(&self.config, number, 1, &mut self.tx)?;
                self.queue.push(Event::NumberDefended {
                    player_number: number,
                    challenger,
                });
                (Channel::Announce, Destination::Unicast(challenger), len)
            }
        };

        self.transmit(channel, dest, len)
    }

    /// Decodes into a scratch value, keeping the borrow of `self.rx` short.
    fn decode(&mut self, channel: Channel, len: usize) -> Result<(), CodecError> {
        match channel {
            Channel::Announce => KeepAlivePacket::decode(&self.rx[..len]).map(|_| ()),
            Channel::Beat => BeatPacket::decode(&self.rx[..len]).map(|_| ()),
            Channel::Status => StatusPacket::decode(&self.rx[..len]).map(|_| ()),
        }
    }

    fn dispatch(
        &mut self,
        channel: Channel,
        source: Ipv4Addr,
        len: usize,
        now: Millis,
    ) -> Result<(), SessionError<T::Error>> {
        match channel {
            Channel::Announce => {
                let packet = KeepAlivePacket::decode(&self.rx[..len]).expect("just decoded");
                self.on_keepalive(packet, source, now)
            }
            Channel::Beat => {
                let packet = BeatPacket::decode(&self.rx[..len]).expect("just decoded");
                self.on_beat(packet, source, now);
                Ok(())
            }
            Channel::Status => {
                let packet = StatusPacket::decode(&self.rx[..len]).expect("just decoded");
                self.on_status(packet, source, now);
                Ok(())
            }
        }
    }

    fn on_keepalive(
        &mut self,
        packet: KeepAlivePacket,
        source: Ipv4Addr,
        now: Millis,
    ) -> Result<(), SessionError<T::Error>> {
        // Somebody staking a claim may be staking a claim on us. Unless it is
        // us: broadcasts come back to the sender on most stacks, and a
        // `ClaimNumber` carries neither MAC nor IP, so the only way to
        // recognise our own echo is the datagram's source address.
        let from_ourselves = self.config.ip == Some(source)
            || (packet.body.mac().is_some() && packet.body.mac() == self.config.mac);
        if let Some(claimed) = claimed_number(&packet.body).filter(|_| !from_ourselves) {
            if let Some(action) = self.negotiator.observe_claim(
                claimed,
                packet.body.mac(),
                source,
                now,
                &self.devices,
            ) {
                self.perform(action, now)?;
            }
        }

        // Only the steady heartbeat establishes presence. A device that is
        // still negotiating does not have a number yet, and recording one
        // would let it block the number it is about to lose.
        let KeepAliveBody::Status {
            player_number,
            mac,
            ip,
            ..
        } = packet.body
        else {
            return Ok(());
        };

        // Ignore our own broadcast echoing back.
        if self.config.mac == Some(mac) {
            return Ok(());
        }

        match self.devices.observe(
            player_number,
            packet.device_type,
            packet.model,
            ip,
            Some(mac),
            now,
        ) {
            RegistryChange::Added => self.queue.push(Event::DeviceAppeared {
                player_number,
                device_type: packet.device_type,
                model: packet.model,
                ip,
                mac: Some(mac),
            }),
            RegistryChange::Readdressed { previous_ip } => {
                self.queue.push(Event::DeviceReaddressed {
                    player_number,
                    previous_ip,
                    ip,
                })
            }
            RegistryChange::Full => self.queue.push(Event::RegistryFull { player_number }),
            RegistryChange::Refreshed => {}
        }

        Ok(())
    }

    fn on_beat(&mut self, packet: BeatPacket, _source: Ipv4Addr, now: Millis) {
        match packet.body {
            BeatBody::Beat {
                distances,
                pitch,
                bpm,
                beat,
                ..
            } => {
                if let Some(device) = self.devices.get_mut(packet.player_number) {
                    if let Some(player) = device.player.as_mut() {
                        player.beat = beat;
                        player.actual_pitch = pitch;
                    }
                }
                self.queue.push(Event::Beat {
                    player_number: packet.player_number,
                    beat,
                    bpm: bpm.map(|bpm| crate::wire::Bpm(bpm.0 * pitch.0)),
                    pitch,
                    next_beat_ms: distances.next_beat,
                });
            }

            BeatBody::AbsolutePosition {
                track_length_ms,
                playhead_ms,
                ..
            } => {
                if let Some(device) = self.devices.get_mut(packet.player_number) {
                    if let Some(player) = device.player.as_mut() {
                        player.position_ms = Some(playhead_ms as u64);
                        player.position_at = now;
                        player.track_length_ms = Some(track_length_ms);
                    }
                }
                self.queue.push(Event::Position {
                    player_number: packet.player_number,
                    playhead_ms,
                    track_length_ms,
                });
            }

            BeatBody::MixerOnAir { channels } => {
                if let Some(device) = self.devices.get_mut(packet.player_number) {
                    let mixer = device.mixer.get_or_insert(MixerState {
                        state: StateFlags::empty(),
                        bpm: None,
                        beat: 0,
                        channels_on_air: [0; 4],
                    });
                    if mixer.channels_on_air == channels {
                        return;
                    }
                    mixer.channels_on_air = channels;
                }
                self.queue.push(Event::OnAirChanged { channels });
            }

            BeatBody::FaderStart { commands } => self.queue.push(Event::FaderStart { commands }),

            BeatBody::MixerUnknown { .. } | BeatBody::Unknown => {}
        }
    }

    fn on_status(&mut self, packet: StatusPacket, source: Ipv4Addr, now: Millis) {
        match packet.body {
            StatusBody::Cdj(status) => self.on_cdj_status(packet.player_number, status, now),

            StatusBody::Djm(status) => {
                if let Some(device) = self.devices.get_mut(packet.player_number) {
                    let channels = device
                        .mixer
                        .map(|mixer| mixer.channels_on_air)
                        .unwrap_or([0; 4]);
                    let mut mixer = MixerState::from_status(&status);
                    mixer.channels_on_air = channels;
                    device.mixer = Some(mixer);
                }
            }

            StatusBody::MediaReply(info) => self.queue.push(Event::MediaInfo(info)),

            StatusBody::Unknown => self.queue.push(Event::Unhandled {
                channel: Channel::Status,
                source,
                packet_type: packet.packet_type().to_u8(),
            }),

            StatusBody::MediaQuery { .. } | StatusBody::LoadCommand { .. } => {
                // Commands aimed at players. We are not a player, so there is
                // nothing to do, but seeing them is not an error either.
            }
            StatusBody::LoadCommandReply => {}
        }
    }

    fn on_cdj_status(&mut self, player_number: u8, status: CdjStatus, now: Millis) {
        let Some(device) = self.devices.get_mut(player_number) else {
            // A status packet from a device that has not sent a keepalive yet.
            // It will appear properly in a moment; ignoring this one avoids
            // inventing a device with no address.
            return;
        };

        let previous = device.player;
        match device.player.as_mut() {
            Some(player) => player.apply_status(&status),
            None => device.player = Some(PlayerState::from_status(&status, now)),
        }
        let current = device.player.expect("just set");

        // Media changes are reported separately because they are the trigger
        // for asking what is on the newly inserted stick.
        if let Some(before) = previous {
            if before.usb_state != current.usb_state {
                self.queue.push(Event::MediaChanged {
                    player_number,
                    slot: PlayerSlot::Usb,
                    state: current.usb_state,
                });
            }
            if before.sd_state != current.sd_state {
                self.queue.push(Event::MediaChanged {
                    player_number,
                    slot: PlayerSlot::Sd,
                    state: current.sd_state,
                });
            }
            if before.track_id != current.track_id && current.track_id != 0 {
                self.queue.push(Event::TrackLoaded {
                    player_number,
                    source_player: current.loaded_from_player,
                    slot: current.loaded_from_slot,
                    track_id: current.track_id,
                });
            }
        } else {
            report_initial_media(&mut self.queue, player_number, &current);
        }

        if status.is_master() && self.master != Some(player_number) {
            self.master = Some(player_number);
            self.queue.push(Event::MasterChanged { player_number });
        }

        let changed = diff_status(previous.as_ref(), &current);
        if changed.is_meaningful() {
            self.queue.push(Event::DeviceStatus {
                player_number,
                changed,
            });
        }
    }
}

fn report_initial_media(queue: &mut EventQueue, player_number: u8, state: &PlayerState) {
    for (slot, indicator) in [
        (PlayerSlot::Usb, state.usb_state),
        (PlayerSlot::Sd, state.sd_state),
    ] {
        if indicator.is_mounted() {
            queue.push(Event::MediaChanged {
                player_number,
                slot,
                state: indicator,
            });
        }
    }
}

/// The number a keepalive is staking a claim on, if it is staking one.
fn claimed_number(body: &KeepAliveBody) -> Option<u8> {
    match body {
        KeepAliveBody::ClaimIp { player_number, .. }
        | KeepAliveBody::ClaimNumber { player_number, .. } => Some(*player_number),
        _ => None,
    }
}

fn diff_status(before: Option<&PlayerState>, after: &PlayerState) -> StatusChange {
    let Some(before) = before else {
        // Everything is new the first time we hear from a device.
        return StatusChange::all();
    };

    let mut changed = StatusChange::empty();
    changed.set(
        StatusChange::PLAY_STATE,
        before.play_state != after.play_state,
    );
    changed.set(StatusChange::BPM, before.bpm != after.bpm);
    changed.set(
        StatusChange::PITCH,
        before.actual_pitch != after.actual_pitch,
    );
    changed.set(StatusChange::BEAT, before.beat != after.beat);
    changed.set(
        StatusChange::BEAT_COUNT,
        before.beat_count != after.beat_count,
    );
    changed.set(StatusChange::TRACK, before.track_id != after.track_id);
    changed.set(
        StatusChange::MEDIA,
        before.usb_state != after.usb_state || before.sd_state != after.sd_state,
    );

    for (flag, bit) in [
        (StateFlags::ON_AIR, StatusChange::ON_AIR),
        (StateFlags::SYNC, StatusChange::SYNC),
        (StateFlags::MASTER, StatusChange::MASTER),
    ] {
        changed.set(
            bit,
            before.state.contains(flag) != after.state.contains(flag),
        );
    }

    changed
}

/// A small ring of pending events.
#[derive(Debug)]
struct EventQueue {
    items: [Option<Event>; EVENT_QUEUE_LEN],
    head: usize,
    len: usize,
    dropped: u16,
    announced_online: bool,
}

impl EventQueue {
    const fn new() -> Self {
        EventQueue {
            items: [None; EVENT_QUEUE_LEN],
            head: 0,
            len: 0,
            dropped: 0,
            announced_online: false,
        }
    }

    fn push(&mut self, event: Event) {
        if self.len == EVENT_QUEUE_LEN {
            // Drop the oldest: a stale event is less useful than a fresh one,
            // and the loss is reported rather than hidden.
            self.head = (self.head + 1) % EVENT_QUEUE_LEN;
            self.len -= 1;
            self.dropped = self.dropped.saturating_add(1);
        }
        let index = (self.head + self.len) % EVENT_QUEUE_LEN;
        self.items[index] = Some(event);
        self.len += 1;
    }

    fn pop(&mut self) -> Option<Event> {
        if self.dropped > 0 {
            let count = core::mem::take(&mut self.dropped);
            return Some(Event::EventsDropped { count });
        }
        if self.len == 0 {
            return None;
        }
        let event = self.items[self.head].take();
        self.head = (self.head + 1) % EVENT_QUEUE_LEN;
        self.len -= 1;
        event
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;

    fn beat(n: u8) -> Event {
        Event::Beat {
            player_number: n,
            beat: 1,
            bpm: None,
            pitch: crate::wire::Pitch::NORMAL,
            next_beat_ms: 0,
        }
    }

    #[test]
    fn events_come_back_in_the_order_they_went_in() {
        let mut queue = EventQueue::new();
        for n in 1..=3 {
            queue.push(beat(n));
        }
        for n in 1..=3 {
            assert_eq!(queue.pop(), Some(beat(n)));
        }
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn the_ring_wraps_without_losing_anything() {
        let mut queue = EventQueue::new();
        for round in 0..4 {
            for n in 0..EVENT_QUEUE_LEN as u8 {
                queue.push(beat(n));
            }
            for n in 0..EVENT_QUEUE_LEN as u8 {
                assert_eq!(queue.pop(), Some(beat(n)), "round {round}");
            }
        }
    }

    /// The session drains the queue between packets, so this should never
    /// happen in practice — but if it ever does, it must be visible rather
    /// than silent.
    #[test]
    fn overflowing_is_reported_not_hidden() {
        let mut queue = EventQueue::new();
        for n in 0..(EVENT_QUEUE_LEN as u8 + 3) {
            queue.push(beat(n));
        }
        assert_eq!(queue.pop(), Some(Event::EventsDropped { count: 3 }));
        // The three oldest went; the newest survived.
        assert_eq!(queue.pop(), Some(beat(3)));
    }
}
