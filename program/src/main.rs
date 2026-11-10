//! orc SP1 guest: verifies one GitHub commit-count claim and commits
//! `abi.encode(PublicValues)` (288 bytes), which `OrcClaim.sol` decodes.
//!
//! stdin (in order):
//! 1. the bincode `Presentation` bytes (`read_vec`)
//! 2. the `GuestInput` (`read`, bincode)
//!
//! All checks live in `orc_core::verify_claim`, the same code the host runs
//! natively. Any rejection panics with the `ClaimError` message, so no proof
//! can exist for a rejected claim.
//!
//! Trust anchors are compile-time constants: the production build hardcodes
//! `VerifyParams::github()` (`api.github.com` + Mozilla roots). Nothing on
//! stdin can change the server name or the root store.
//!
//! The `test-ca` feature (TEST ONLY, see Cargo.toml) swaps them for tlsn's
//! public test CA and `test-server.io`. It is a different ELF with a
//! different vkey and must never be deployed.

#![no_main]
sp1_zkvm::entrypoint!(main);

use orc_core::{GuestInput, Tracker, VerifyParams, verify_claim_tracked};

/// Turns orc-core phases into SP1 cycle-tracker markers (reported by the
/// host's executor when sp1-sdk has the `profiling` feature; otherwise
/// they are plain stdout lines and cost a few hundred cycles).
struct CycleTracker;

impl Tracker for CycleTracker {
    fn start(&mut self, label: &'static str) {
        println!("cycle-tracker-report-start: {label}");
    }
    fn end(&mut self, label: &'static str) {
        println!("cycle-tracker-report-end: {label}");
    }
}

pub fn main() {
    let mut tracker = CycleTracker;

    tracker.start("input");
    let presentation = sp1_zkvm::io::read_vec();
    let input: GuestInput = sp1_zkvm::io::read();
    tracker.end("input");

    tracker.start("params");
    let params = trusted_params();
    tracker.end("params");

    let public_values = match verify_claim_tracked(&presentation, &input, &params, &mut tracker) {
        Ok(public_values) => public_values,
        Err(e) => panic!("orc claim rejected: {e}"),
    };

    tracker.start("encode");
    sp1_zkvm::io::commit_slice(&public_values.to_abi_bytes());
    tracker.end("encode");
}

/// Production trust anchors: `api.github.com`, Mozilla root store.
#[cfg(not(feature = "test-ca"))]
fn trusted_params() -> VerifyParams {
    VerifyParams::github()
}

/// TEST ONLY: tlsn's public test CA and `test-server.io`.
#[cfg(feature = "test-ca")]
fn trusted_params() -> VerifyParams {
    use tlsn_core::webpki::{CertificateDer, RootCertStore};
    use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

    println!("orc-program: TEST-CA BUILD (tlsn test CA, {SERVER_DOMAIN}). NOT FOR DEPLOYMENT.");
    let roots = RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    };
    VerifyParams::with_root_store(SERVER_DOMAIN, &roots).expect("test CA verifier params")
}
