//! Connection admission: a global cap on concurrent sessions plus a cap per
//! source address, so a single host cannot take every MPC slot.
//!
//! The decision is synchronous and made right after `accept`, before the
//! notary reads a byte. A [`Permit`] holds both slots and frees them on drop.

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// All `limit` session slots are taken.
    AtCapacity { limit: usize },
    /// The source already holds `limit` sessions.
    PerSource { limit: usize },
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtCapacity { limit } => write!(f, "all {limit} session slots are busy"),
            Self::PerSource { limit } => {
                write!(f, "source already holds {limit} concurrent sessions")
            }
        }
    }
}

impl std::error::Error for Refused {}

/// Shared session counters. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Admission {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    max_total: usize,
    max_per_source: usize,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    total: usize,
    per_source: HashMap<IpAddr, usize>,
}

impl Inner {
    /// The counters stay consistent under a poisoned lock (no code path
    /// panics while holding it), so recover instead of propagating.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Admission {
    /// At most `max_total` sessions overall and `max_per_source` per source.
    /// Both are clamped to at least 1.
    pub fn new(max_total: usize, max_per_source: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                max_total: max_total.max(1),
                max_per_source: max_per_source.max(1),
                state: Mutex::default(),
            }),
        }
    }

    /// Takes a slot for a connection from `peer`, or says why not.
    pub fn try_admit(&self, peer: IpAddr) -> Result<Permit, Refused> {
        let source = source_key(peer);
        let mut state = self.inner.lock();
        let held = state.per_source.get(&source).copied().unwrap_or(0);
        if held >= self.inner.max_per_source {
            return Err(Refused::PerSource {
                limit: self.inner.max_per_source,
            });
        }
        if state.total >= self.inner.max_total {
            return Err(Refused::AtCapacity {
                limit: self.inner.max_total,
            });
        }
        state.total += 1;
        *state.per_source.entry(source).or_insert(0) += 1;
        Ok(Permit {
            inner: self.inner.clone(),
            source,
        })
    }

    /// Sessions currently admitted.
    pub fn active(&self) -> usize {
        self.inner.lock().total
    }

    /// Sessions currently admitted for `peer`'s source.
    pub fn active_for(&self, peer: IpAddr) -> usize {
        let source = source_key(peer);
        self.inner
            .lock()
            .per_source
            .get(&source)
            .copied()
            .unwrap_or(0)
    }
}

/// One admitted session. Dropping it frees the global and the per-source slot.
#[derive(Debug)]
pub struct Permit {
    inner: Arc<Inner>,
    source: IpAddr,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.inner.lock();
        state.total = state.total.saturating_sub(1);
        if let Some(held) = state.per_source.get_mut(&self.source) {
            *held -= 1;
            if *held == 0 {
                state.per_source.remove(&self.source);
            }
        }
    }
}

/// The address a connection is counted against: the IPv4 address itself
/// (IPv4-mapped IPv6 included), or the /64 prefix for IPv6, since one host
/// usually controls a whole /64.
pub fn source_key(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut segments = v6.segments();
                segments[4..].fill(0);
                IpAddr::V6(Ipv6Addr::from(segments))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const A: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const B: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    const C: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));

    #[test]
    fn per_source_cap_then_release() {
        let admission = Admission::new(8, 2);
        let a1 = admission.try_admit(A).expect("1st");
        let _a2 = admission.try_admit(A).expect("2nd");
        assert_eq!(
            admission.try_admit(A).unwrap_err(),
            Refused::PerSource { limit: 2 }
        );
        // Other sources are unaffected.
        let _b = admission.try_admit(B).expect("other source");
        assert_eq!(admission.active(), 3);
        assert_eq!(admission.active_for(A), 2);

        drop(a1);
        assert_eq!(admission.active_for(A), 1);
        let _a3 = admission.try_admit(A).expect("slot freed");
    }

    #[test]
    fn global_cap_then_release() {
        let admission = Admission::new(2, 2);
        let a = admission.try_admit(A).expect("A");
        let _b = admission.try_admit(B).expect("B");
        assert_eq!(
            admission.try_admit(C).unwrap_err(),
            Refused::AtCapacity { limit: 2 }
        );
        drop(a);
        let _c = admission.try_admit(C).expect("slot freed");
        assert_eq!(admission.active(), 2);
        assert_eq!(admission.active_for(A), 0);
    }

    #[test]
    fn refusal_takes_no_slot() {
        let admission = Admission::new(1, 1);
        let _a = admission.try_admit(A).expect("A");
        for _ in 0..10 {
            assert!(admission.try_admit(A).is_err());
            assert!(admission.try_admit(B).is_err());
        }
        assert_eq!(admission.active(), 1);
        assert_eq!(admission.active_for(B), 0);
    }

    #[test]
    fn zero_limits_are_clamped_to_one() {
        let admission = Admission::new(0, 0);
        let _a = admission.try_admit(A).expect("one slot");
        assert!(admission.try_admit(B).is_err());
    }

    #[test]
    fn ipv6_counts_per_64_and_mapped_v4_as_v4() {
        let admission = Admission::new(8, 1);
        let x: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let same_64: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let other_64: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        let _x = admission.try_admit(x).expect("x");
        assert!(admission.try_admit(same_64).is_err());
        let _y = admission.try_admit(other_64).expect("other /64");

        let _a = admission.try_admit(A).expect("A");
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert!(admission.try_admit(mapped).is_err());
    }
}
