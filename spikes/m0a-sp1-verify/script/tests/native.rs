//! Native baseline: the exact verification code the guest runs, on the host.

use std::time::Instant;

use m0a_lib::{Mode, NoTrack, Output, verify};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m0b-mpc-github/fixtures");
/// k256 pubkey of the M0b dummy notary key `[1u8; 32]`.
const NOTARY_KEY: &str = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";

fn run(name: &str, mode: Mode) -> Output {
    let bytes = std::fs::read(format!("{FIXTURES}/presentation-{name}.bin")).unwrap();
    let t = Instant::now();
    let out = verify(&bytes, mode, &mut NoTrack).unwrap();
    println!("[native] {name} {mode:?}: {:.2?} -> {out:?}", t.elapsed());
    out
}

#[test]
fn native_verify_matches_across_modes() {
    for name in ["repo-noauth", "graphql"] {
        let full = run(name, Mode::Full);
        assert_eq!(full.server_name.as_deref(), Some("api.github.com"));
        assert_eq!(full.notary_key_alg, 1, "K256");
        assert_eq!(hex::encode(&full.notary_key), NOTARY_KEY);
        assert_eq!(full.recv_authed, full.recv_len, "all of recv is authenticated");
        assert!(full.sent_authed < full.sent_len || name == "repo-noauth");

        // Split must agree with the upstream single-call verify field for field.
        let split = run(name, Mode::Split);
        assert_eq!(Output { mode: Mode::Full, ..split }, full);

        let no_id = run(name, Mode::NoIdentity);
        assert_eq!(no_id.server_name, None);
        assert_eq!(
            Output { mode: Mode::Full, server_name: full.server_name.clone(), ..no_id },
            full
        );
    }
}

#[test]
fn tampered_presentation_fails() {
    let mut bytes = std::fs::read(format!("{FIXTURES}/presentation-repo-noauth.bin")).unwrap();
    // Flip one byte of the revealed response body (`"full_name"` only occurs there).
    let needle = b"\"full_name\"";
    let i = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("response body in presentation");
    bytes[i + 1] ^= 0x01;
    for mode in [Mode::Full, Mode::Split, Mode::NoIdentity] {
        assert!(verify(&bytes, mode, &mut NoTrack).is_err(), "{mode:?} accepted tampered bytes");
    }
}
