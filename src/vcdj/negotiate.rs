//! Claiming a player number.
//!
//! A device joining a Pro DJ Link network cannot simply announce itself. It
//! has to listen first, then stake a claim in four escalating steps, each
//! repeated three times, watching throughout for another device objecting.
//! Only then may it start sending the steady heartbeat that keeps it visible.
//!
//! ```text
//!   Idle
//!    │ start()
//!    ▼
//!   Hello        ×3   "who's out there?"        listen for existing keepalives
//!    ▼
//!   ClaimMac     ×3   "this MAC is joining"
//!    ▼
//!   ClaimIp      ×3   "this IP wants number N"  ─┐ another device claiming N
//!    ▼                                           │ sends us type 0x04 here
//!   ClaimNumber  ×3   "number N is mine"        ─┘
//!    ▼
//!   Online            heartbeat every 1.5 s      defend N against latecomers
//! ```
//!
//! # A caveat worth knowing
//!
//! Neither reference implementation this was built from performs the
//! negotiation at all — both simply start broadcasting a heartbeat with a
//! hard-coded number and hope nothing else is using it. The sequence and its
//! 300 ms spacing come from published analysis of captured traffic rather than
//! from working code, so treat the timings as good but unconfirmed. They live
//! in [`Timing`] precisely so that correcting them is a one-line change.
//!
//! [`Timing`]: crate::constants::Timing

use core::net::Ipv4Addr;

use crate::constants::Timing;
use crate::registry::DeviceRegistry;
use crate::time::Millis;
use crate::wire::MacAddr;

/// The lowest and highest player numbers a device may hold.
pub const MIN_PLAYER_NUMBER: u8 = 1;
/// The highest player number a Pro DJ Link network supports.
pub const MAX_PLAYER_NUMBER: u8 = 6;

/// The player number to start looking from when asking for one automatically.
///
/// Numbers 1 through 4 correspond to the physical decks in a standard booth,
/// so a virtual device starts at 5 to stay out of their way.
pub const DEFAULT_FIRST_NUMBER: u8 = 5;

/// Which player number to ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberRequest {
    /// Take the first free number at or above `first`.
    Auto {
        /// Where to start looking.
        first: u8,
    },
    /// Insist on this number, failing if another device already holds it.
    Fixed(u8),
}

impl Default for NumberRequest {
    fn default() -> Self {
        NumberRequest::Auto {
            first: DEFAULT_FIRST_NUMBER,
        }
    }
}

/// Why negotiation could not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationFailure {
    /// Every number in range is already taken.
    NoFreeNumber,
    /// A [`Fixed`](NumberRequest::Fixed) number is held by another device.
    NumberTaken(u8),
    /// No IP or MAC address was configured, so there is nothing to claim with.
    MissingIdentity,
}

/// Where we are in the process of joining the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VcdjState {
    /// Not started.
    Idle,
    /// Asking who else is present, and listening to the answers.
    Hello {
        /// How many greetings have gone out, 1 through 3.
        sent: u8,
        /// When the next one is due.
        next_at: Millis,
    },
    /// Publishing our hardware address.
    ClaimMac {
        /// The number we intend to claim.
        number: u8,
        /// Which repeat this is, 1 through 3.
        iteration: u8,
        /// When the next one is due.
        next_at: Millis,
    },
    /// Publishing our address together with the number we want.
    ClaimIp {
        /// The number we are claiming.
        number: u8,
        /// Which repeat this is, 1 through 3.
        iteration: u8,
        /// When the next one is due.
        next_at: Millis,
    },
    /// Asserting the number outright.
    ClaimNumber {
        /// The number we are claiming.
        number: u8,
        /// Which repeat this is, 1 through 3.
        iteration: u8,
        /// When the next one is due.
        next_at: Millis,
    },
    /// Joined. Sending heartbeats and defending our number.
    Online {
        /// The number we hold.
        number: u8,
        /// When the next heartbeat is due.
        next_keepalive: Millis,
        /// When our next status packet is due.
        next_status: Millis,
    },
    /// Could not join.
    Failed(NegotiationFailure),
}

impl VcdjState {
    /// The number we hold, but only once we actually hold it.
    ///
    /// Deliberately `None` mid-negotiation: a number we are still arguing over
    /// is not ours to use, and treating it as ours is how two devices end up
    /// sharing one.
    pub const fn player_number(&self) -> Option<u8> {
        match self {
            VcdjState::Online { number, .. } => Some(*number),
            _ => None,
        }
    }

    /// Whether negotiation has completed successfully.
    pub const fn is_online(&self) -> bool {
        matches!(self, VcdjState::Online { .. })
    }

    /// When this state next needs attention.
    pub const fn next_deadline(&self) -> Millis {
        match self {
            VcdjState::Idle | VcdjState::Failed(_) => Millis::NEVER,
            VcdjState::Hello { next_at, .. }
            | VcdjState::ClaimMac { next_at, .. }
            | VcdjState::ClaimIp { next_at, .. }
            | VcdjState::ClaimNumber { next_at, .. } => *next_at,
            VcdjState::Online {
                next_keepalive,
                next_status,
                ..
            } => (*next_keepalive).min(*next_status),
        }
    }
}

/// What the session should transmit as a result of a negotiation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Broadcast a greeting.
    SendHello,
    /// Broadcast a MAC claim.
    SendClaimMac {
        /// Which repeat.
        iteration: u8,
    },
    /// Broadcast an IP claim carrying the number we want.
    SendClaimIp {
        /// The number being claimed.
        number: u8,
        /// Which repeat.
        iteration: u8,
    },
    /// Broadcast a bare number claim.
    SendClaimNumber {
        /// The number being claimed.
        number: u8,
        /// Which repeat.
        iteration: u8,
    },
    /// Broadcast the steady-state heartbeat.
    SendKeepAlive {
        /// Our number.
        number: u8,
    },
    /// Send our own status packet.
    SendStatus {
        /// Our number.
        number: u8,
    },
    /// Tell a device trying to take our number that it is ours.
    DefendNumber {
        /// Our number.
        number: u8,
        /// Who to tell.
        challenger: Ipv4Addr,
    },
}

/// Drives the claim sequence.
///
/// Holds no transport and no clock: every method takes the current time and
/// returns what should be sent, which makes the whole state machine testable
/// without a network or a mock.
#[derive(Debug, Clone)]
pub struct Negotiator {
    state: VcdjState,
    request: NumberRequest,
    timing: Timing,
    mac: MacAddr,
}

impl Negotiator {
    /// A negotiator that has not started.
    pub const fn new(request: NumberRequest, timing: Timing, mac: MacAddr) -> Self {
        Negotiator {
            state: VcdjState::Idle,
            request,
            timing,
            mac,
        }
    }

    /// The current state.
    pub const fn state(&self) -> VcdjState {
        self.state
    }

    /// Our player number, once we hold one.
    pub const fn player_number(&self) -> Option<u8> {
        self.state.player_number()
    }

    /// When [`step`](Negotiator::step) next has something to do.
    pub const fn next_deadline(&self) -> Millis {
        self.state.next_deadline()
    }

    /// Whether a step is due.
    pub const fn is_due(&self, now: Millis) -> bool {
        now.0 >= self.next_deadline().0
    }

    /// Begins the sequence.
    ///
    /// Returns the first greeting to send, or `None` if the state machine has
    /// already been started.
    pub fn start(&mut self, now: Millis) -> Option<Action> {
        if !matches!(self.state, VcdjState::Idle | VcdjState::Failed(_)) {
            return None;
        }
        self.state = VcdjState::Hello {
            sent: 1,
            next_at: now.add(self.timing.claim_interval_ms),
        };
        Some(Action::SendHello)
    }

    /// Returns to the un-started state.
    pub fn stop(&mut self) {
        self.state = VcdjState::Idle;
    }

    /// Advances the sequence if something is due.
    ///
    /// Returns the packet to send, or `None` if nothing is due yet. Consults
    /// `registry` when choosing a number, which is why the greeting phase
    /// exists: it buys nearly a second of listening first.
    pub fn step(&mut self, now: Millis, registry: &DeviceRegistry) -> Option<Action> {
        if !self.is_due(now) {
            return None;
        }

        let interval = self.timing.claim_interval_ms;
        let iterations = self.timing.claim_iterations;

        match self.state {
            VcdjState::Idle | VcdjState::Failed(_) => None,

            VcdjState::Hello { sent, .. } if sent < iterations => {
                self.state = VcdjState::Hello {
                    sent: sent + 1,
                    next_at: now.add(interval),
                };
                Some(Action::SendHello)
            }
            VcdjState::Hello { .. } => {
                // Everyone who was going to answer has answered by now.
                let number = match self.choose_number(registry) {
                    Ok(number) => number,
                    Err(failure) => {
                        self.state = VcdjState::Failed(failure);
                        return None;
                    }
                };
                self.state = VcdjState::ClaimMac {
                    number,
                    iteration: 1,
                    next_at: now.add(interval),
                };
                Some(Action::SendClaimMac { iteration: 1 })
            }

            VcdjState::ClaimMac {
                number, iteration, ..
            } if iteration < iterations => {
                self.state = VcdjState::ClaimMac {
                    number,
                    iteration: iteration + 1,
                    next_at: now.add(interval),
                };
                Some(Action::SendClaimMac {
                    iteration: iteration + 1,
                })
            }
            VcdjState::ClaimMac { number, .. } => {
                self.state = VcdjState::ClaimIp {
                    number,
                    iteration: 1,
                    next_at: now.add(interval),
                };
                Some(Action::SendClaimIp {
                    number,
                    iteration: 1,
                })
            }

            VcdjState::ClaimIp {
                number, iteration, ..
            } if iteration < iterations => {
                self.state = VcdjState::ClaimIp {
                    number,
                    iteration: iteration + 1,
                    next_at: now.add(interval),
                };
                Some(Action::SendClaimIp {
                    number,
                    iteration: iteration + 1,
                })
            }
            VcdjState::ClaimIp { number, .. } => {
                self.state = VcdjState::ClaimNumber {
                    number,
                    iteration: 1,
                    next_at: now.add(interval),
                };
                Some(Action::SendClaimNumber {
                    number,
                    iteration: 1,
                })
            }

            VcdjState::ClaimNumber {
                number, iteration, ..
            } if iteration < iterations => {
                self.state = VcdjState::ClaimNumber {
                    number,
                    iteration: iteration + 1,
                    next_at: now.add(interval),
                };
                Some(Action::SendClaimNumber {
                    number,
                    iteration: iteration + 1,
                })
            }
            VcdjState::ClaimNumber { number, .. } => {
                self.state = VcdjState::Online {
                    number,
                    next_keepalive: now.add(self.timing.keepalive_interval_ms),
                    next_status: now.add(self.timing.status_interval_ms),
                };
                Some(Action::SendKeepAlive { number })
            }

            VcdjState::Online {
                number,
                next_keepalive,
                next_status,
            } => {
                // Keepalives take priority: they are what keeps us visible.
                if now.reached(next_keepalive) {
                    self.state = VcdjState::Online {
                        number,
                        next_keepalive: now.add(self.timing.keepalive_interval_ms),
                        next_status,
                    };
                    Some(Action::SendKeepAlive { number })
                } else {
                    self.state = VcdjState::Online {
                        number,
                        next_keepalive,
                        next_status: now.add(self.timing.status_interval_ms),
                    };
                    Some(Action::SendStatus { number })
                }
            }
        }
    }

    /// Reacts to another device claiming a player number.
    ///
    /// While claiming, a conflict means backing off — to the next candidate if
    /// the number was chosen automatically, or to failure if it was demanded.
    /// Once online, it means standing our ground: we were here first, and a
    /// device that has not finished negotiating should pick something else.
    ///
    /// Returns what to send in response, if anything.
    pub fn observe_claim(
        &mut self,
        claimed: u8,
        claimant_mac: Option<MacAddr>,
        claimant_ip: Ipv4Addr,
        now: Millis,
        registry: &DeviceRegistry,
    ) -> Option<Action> {
        // Our own broadcasts come back to us on most networks. Ignore them.
        if claimant_mac == Some(self.mac) {
            return None;
        }

        match self.state {
            VcdjState::ClaimMac { number, .. }
            | VcdjState::ClaimIp { number, .. }
            | VcdjState::ClaimNumber { number, .. }
                if number == claimed =>
            {
                match self.request {
                    NumberRequest::Fixed(_) => {
                        self.state = VcdjState::Failed(NegotiationFailure::NumberTaken(claimed));
                        None
                    }
                    NumberRequest::Auto { .. } => {
                        // Restart the claim sequence on the next candidate
                        // rather than the next number blindly: the registry
                        // may have learned about several devices since.
                        match self.next_candidate_after(claimed, registry) {
                            Some(next) => {
                                self.state = VcdjState::ClaimMac {
                                    number: next,
                                    iteration: 1,
                                    next_at: now.add(self.timing.claim_interval_ms),
                                };
                                Some(Action::SendClaimMac { iteration: 1 })
                            }
                            None => {
                                self.state = VcdjState::Failed(NegotiationFailure::NoFreeNumber);
                                None
                            }
                        }
                    }
                }
            }

            VcdjState::Online { number, .. } if number == claimed => Some(Action::DefendNumber {
                number,
                challenger: claimant_ip,
            }),

            _ => None,
        }
    }

    fn choose_number(&self, registry: &DeviceRegistry) -> Result<u8, NegotiationFailure> {
        match self.request {
            NumberRequest::Fixed(number) => {
                if registry.is_taken(number) {
                    Err(NegotiationFailure::NumberTaken(number))
                } else {
                    Ok(number)
                }
            }
            NumberRequest::Auto { first } => {
                let start = first.clamp(MIN_PLAYER_NUMBER, MAX_PLAYER_NUMBER);
                (start..=MAX_PLAYER_NUMBER)
                    .chain(MIN_PLAYER_NUMBER..start)
                    .find(|number| !registry.is_taken(*number))
                    .ok_or(NegotiationFailure::NoFreeNumber)
            }
        }
    }

    fn next_candidate_after(&self, rejected: u8, registry: &DeviceRegistry) -> Option<u8> {
        let start = rejected.saturating_add(1);
        (start..=MAX_PLAYER_NUMBER)
            .chain(MIN_PLAYER_NUMBER..rejected)
            .find(|number| !registry.is_taken(*number))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MODEL_LEN;
    use crate::packet::DeviceType;
    use crate::wire::FixedStr;

    const MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
    const OTHER_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x02]);
    const OTHER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 9);

    fn registry_with(numbers: &[u8]) -> DeviceRegistry {
        let mut registry = DeviceRegistry::new();
        for (i, number) in numbers.iter().enumerate() {
            registry.observe(
                *number,
                DeviceType::Cdj,
                FixedStr::<MODEL_LEN>::new("CDJ-3000").unwrap(),
                Ipv4Addr::new(192, 168, 1, 10 + i as u8),
                None,
                Millis(0),
            );
        }
        registry
    }

    fn negotiator(request: NumberRequest) -> Negotiator {
        Negotiator::new(request, Timing::DEFAULT, MAC)
    }

    /// Runs the sequence to completion, collecting everything sent.
    fn run_to_online(negotiator: &mut Negotiator, registry: &DeviceRegistry) -> Vec<Action> {
        let mut sent = Vec::new();
        sent.extend(negotiator.start(Millis(0)));

        let mut now = 0u64;
        while !negotiator.state().is_online() && now < 10_000 {
            now += 300;
            sent.extend(negotiator.step(Millis(now), registry));
            if matches!(negotiator.state(), VcdjState::Failed(_)) {
                break;
            }
        }
        sent
    }

    #[test]
    fn the_full_sequence_is_hello_mac_ip_number_then_online() {
        let registry = registry_with(&[1, 2]);
        let mut negotiator = negotiator(NumberRequest::Auto { first: 5 });
        let sent = run_to_online(&mut negotiator, &registry);

        assert_eq!(sent[0], Action::SendHello);
        assert_eq!(sent[1], Action::SendHello);
        assert_eq!(sent[2], Action::SendHello);
        assert_eq!(sent[3], Action::SendClaimMac { iteration: 1 });
        assert_eq!(sent[4], Action::SendClaimMac { iteration: 2 });
        assert_eq!(sent[5], Action::SendClaimMac { iteration: 3 });
        assert_eq!(
            sent[6],
            Action::SendClaimIp {
                number: 5,
                iteration: 1
            }
        );
        assert_eq!(
            sent[9],
            Action::SendClaimNumber {
                number: 5,
                iteration: 1
            }
        );
        assert_eq!(sent[12], Action::SendKeepAlive { number: 5 });
        assert_eq!(negotiator.player_number(), Some(5));
    }

    #[test]
    fn a_number_is_not_ours_until_negotiation_finishes() {
        let registry = registry_with(&[]);
        let mut negotiator = negotiator(NumberRequest::Auto { first: 5 });
        negotiator.start(Millis(0));
        negotiator.step(Millis(300), &registry);
        negotiator.step(Millis(600), &registry);
        negotiator.step(Millis(900), &registry); // now claiming 5

        assert!(matches!(
            negotiator.state(),
            VcdjState::ClaimMac { number: 5, .. }
        ));
        assert_eq!(
            negotiator.player_number(),
            None,
            "a contested number must not be reported as ours"
        );
    }

    #[test]
    fn auto_skips_numbers_the_registry_already_knows_about() {
        let registry = registry_with(&[5, 6]);
        let mut negotiator = negotiator(NumberRequest::Auto { first: 5 });
        run_to_online(&mut negotiator, &registry);
        // 5 and 6 are taken, so it wraps around to 1.
        assert_eq!(negotiator.player_number(), Some(1));
    }

    #[test]
    fn auto_moves_on_when_another_device_objects() {
        let registry = registry_with(&[]);
        let mut negotiator = negotiator(NumberRequest::Auto { first: 5 });
        negotiator.start(Millis(0));
        for t in [300, 600, 900] {
            negotiator.step(Millis(t), &registry);
        }
        assert!(matches!(
            negotiator.state(),
            VcdjState::ClaimMac { number: 5, .. }
        ));

        let action = negotiator.observe_claim(5, Some(OTHER_MAC), OTHER_IP, Millis(950), &registry);
        assert_eq!(action, Some(Action::SendClaimMac { iteration: 1 }));
        assert!(matches!(
            negotiator.state(),
            VcdjState::ClaimMac { number: 6, .. }
        ));
    }

    #[test]
    fn a_fixed_number_fails_rather_than_silently_moving() {
        let registry = registry_with(&[]);
        let mut negotiator = negotiator(NumberRequest::Fixed(3));
        negotiator.start(Millis(0));
        for t in [300, 600, 900] {
            negotiator.step(Millis(t), &registry);
        }

        negotiator.observe_claim(3, Some(OTHER_MAC), OTHER_IP, Millis(950), &registry);
        assert_eq!(
            negotiator.state(),
            VcdjState::Failed(NegotiationFailure::NumberTaken(3))
        );
        assert_eq!(negotiator.player_number(), None);
    }

    #[test]
    fn a_fixed_number_already_in_the_registry_fails_immediately() {
        let registry = registry_with(&[3]);
        let mut negotiator = negotiator(NumberRequest::Fixed(3));
        run_to_online(&mut negotiator, &registry);
        assert_eq!(
            negotiator.state(),
            VcdjState::Failed(NegotiationFailure::NumberTaken(3))
        );
    }

    #[test]
    fn a_full_network_leaves_nowhere_to_go() {
        let registry = registry_with(&[1, 2, 3, 4, 5, 6]);
        let mut negotiator = negotiator(NumberRequest::Auto { first: 5 });
        run_to_online(&mut negotiator, &registry);
        assert_eq!(
            negotiator.state(),
            VcdjState::Failed(NegotiationFailure::NoFreeNumber)
        );
    }

    #[test]
    fn our_own_broadcast_coming_back_is_not_a_conflict() {
        let registry = registry_with(&[]);
        let mut negotiator = negotiator(NumberRequest::Auto { first: 5 });
        negotiator.start(Millis(0));
        for t in [300, 600, 900] {
            negotiator.step(Millis(t), &registry);
        }

        let action = negotiator.observe_claim(5, Some(MAC), OTHER_IP, Millis(950), &registry);
        assert_eq!(action, None);
        assert!(
            matches!(negotiator.state(), VcdjState::ClaimMac { number: 5, .. }),
            "we must not fight ourselves for our own number"
        );
    }

    #[test]
    fn once_online_we_defend_rather_than_yield() {
        let registry = registry_with(&[]);
        let mut negotiator = negotiator(NumberRequest::Auto { first: 5 });
        run_to_online(&mut negotiator, &registry);

        let action =
            negotiator.observe_claim(5, Some(OTHER_MAC), OTHER_IP, Millis(5_000), &registry);
        assert_eq!(
            action,
            Some(Action::DefendNumber {
                number: 5,
                challenger: OTHER_IP
            })
        );
        assert_eq!(negotiator.player_number(), Some(5));
    }

    #[test]
    fn a_claim_for_someone_elses_number_is_none_of_our_business() {
        let registry = registry_with(&[]);
        let mut negotiator = negotiator(NumberRequest::Auto { first: 5 });
        run_to_online(&mut negotiator, &registry);

        let action =
            negotiator.observe_claim(2, Some(OTHER_MAC), OTHER_IP, Millis(5_000), &registry);
        assert_eq!(action, None);
    }

    #[test]
    fn the_heartbeat_fires_every_interval_and_not_before() {
        let registry = registry_with(&[]);
        // Push our own status packets out of the way so only the heartbeat
        // deadline is in play.
        let mut timing = Timing::DEFAULT;
        timing.status_interval_ms = u64::MAX / 4;
        let mut negotiator = Negotiator::new(NumberRequest::Auto { first: 5 }, timing, MAC);
        run_to_online(&mut negotiator, &registry);

        let VcdjState::Online { next_keepalive, .. } = negotiator.state() else {
            panic!("expected to be online");
        };

        assert!(negotiator
            .step(Millis(next_keepalive.0 - 1), &registry)
            .is_none());
        assert_eq!(
            negotiator.step(Millis(next_keepalive.0), &registry),
            Some(Action::SendKeepAlive { number: 5 })
        );
    }

    #[test]
    fn deadlines_are_recomputed_from_now_so_lateness_does_not_accumulate() {
        let registry = registry_with(&[]);
        let mut negotiator = negotiator(NumberRequest::Auto { first: 5 });
        run_to_online(&mut negotiator, &registry);

        // Poll a long time late, as a busy caller would.
        negotiator.step(Millis(50_000), &registry);
        let VcdjState::Online { next_keepalive, .. } = negotiator.state() else {
            panic!("expected to be online");
        };
        assert_eq!(
            next_keepalive,
            Millis(51_500),
            "the next deadline must be relative to now, not to a missed schedule"
        );
    }

    #[test]
    fn stopping_returns_to_idle_and_gives_up_the_number() {
        let registry = registry_with(&[]);
        let mut negotiator = negotiator(NumberRequest::Auto { first: 5 });
        run_to_online(&mut negotiator, &registry);
        negotiator.stop();
        assert_eq!(negotiator.state(), VcdjState::Idle);
        assert_eq!(negotiator.player_number(), None);
    }
}
