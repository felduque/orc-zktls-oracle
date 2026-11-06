//! M0a guest: verify a TLSNotary presentation inside SP1.
//!
//! stdin:  `Mode` (bincode), then the bincode `Presentation` bytes (read_vec).
//! commit: `m0a_lib::Output` (server name, session time, transcript lengths,
//!         notary verifying key).

#![no_main]
sp1_zkvm::entrypoint!(main);

use m0a_lib::{Mode, Tracker, verify};

/// Emits SP1 cycle-tracker markers; the executor reports them in
/// `ExecutionReport::cycle_tracker`.
struct CycleTracker;

impl Tracker for CycleTracker {
    fn start(&mut self, label: &str) {
        println!("cycle-tracker-report-start: {label}");
    }
    fn end(&mut self, label: &str) {
        println!("cycle-tracker-report-end: {label}");
    }
}

pub fn main() {
    let mode: Mode = sp1_zkvm::io::read();
    let presentation = sp1_zkvm::io::read_vec();

    let output = verify(&presentation, mode, &mut CycleTracker).expect("verification failed");

    sp1_zkvm::io::commit(&output);
}
