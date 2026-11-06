//! M0a spike: verify a TLSNotary v0.1.0-alpha.15 `Presentation`.
//!
//! The same code runs inside the SP1 guest and natively in a host `#[test]`.
//!
//! Three modes:
//! - [`Mode::Full`]: `Presentation::verify` in one call (the canonical path).
//! - [`Mode::Split`]: the same three checks `Presentation::verify` performs
//!   (attestation, server identity, transcript), called one by one so each can
//!   be cycle-tracked in the guest.
//! - [`Mode::NoIdentity`]: `Split` without the server identity check (X.509
//!   chain + TLS server signature via webpki/ring). This is the cost floor of
//!   "Fallback A", where the notary verifies the identity instead.

use serde::{Deserialize, Serialize};
use tlsn_attestation::{
    AttestationProof, CryptoProvider, Extension, Field,
    connection::{ServerCertCommitment, ServerIdentityProof},
    presentation::{Presentation, PresentationOutput},
    signing::VerifyingKey,
};
use tlsn_core::{
    connection::{ConnectionInfo, ServerEphemKey},
    transcript::{PartialTranscript, TranscriptCommitment, TranscriptProof},
};

/// Which verification path to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Full,
    Split,
    NoIdentity,
}

/// Values the guest commits as public outputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub mode: Mode,
    /// Authenticated server name; `None` when the identity check is skipped.
    pub server_name: Option<String>,
    /// UNIX time of the TLS session (`ConnectionInfo::time`).
    pub session_time: u64,
    pub sent_len: u32,
    /// Received transcript length (`ConnectionInfo::transcript_length.received`).
    pub recv_len: u32,
    /// Number of sent / received bytes authenticated by the transcript proof.
    pub sent_authed: u32,
    pub recv_authed: u32,
    /// Notary verifying key (`KeyAlgId` byte + SEC1 compressed key bytes).
    pub notary_key_alg: u8,
    pub notary_key: Vec<u8>,
}

/// Cycle-tracking hooks; the guest prints SP1 `cycle-tracker-report-*` markers.
pub trait Tracker {
    fn start(&mut self, _label: &str) {}
    fn end(&mut self, _label: &str) {}
}

/// No-op tracker for native runs.
pub struct NoTrack;
impl Tracker for NoTrack {}

/// Field-for-field mirror of `Presentation` (whose fields are private), so the
/// three checks can be run one by one. bincode is positional, so the field
/// order must match the upstream struct; the native test checks Split == Full.
#[derive(Deserialize)]
struct PresentationParts {
    attestation: AttestationProof,
    identity: Option<ServerIdentityProof>,
    transcript: Option<TranscriptProof>,
}

/// Mirror of `tlsn_attestation::Body`, whose accessors are `pub(crate)`.
#[derive(Serialize, Deserialize)]
struct BodyParts {
    verifying_key: Field<VerifyingKey>,
    connection_info: Field<ConnectionInfo>,
    server_ephemeral_key: Field<ServerEphemKey>,
    cert_commitment: Field<ServerCertCommitment>,
    extensions: Vec<Field<Extension>>,
    transcript_commitments: Vec<Field<TranscriptCommitment>>,
}

/// Verifies bincode-encoded presentation bytes with the default provider
/// (Mozilla roots, SHA256/BLAKE3/Keccak hashers, k256/p256 signature verifiers).
pub fn verify(bytes: &[u8], mode: Mode, t: &mut impl Tracker) -> Result<Output, String> {
    t.start("provider");
    let provider = CryptoProvider::default();
    t.end("provider");

    match mode {
        Mode::Full => verify_full(bytes, &provider, t),
        Mode::Split | Mode::NoIdentity => verify_split(bytes, mode, &provider, t),
    }
}

fn verify_full(
    bytes: &[u8],
    provider: &CryptoProvider,
    t: &mut impl Tracker,
) -> Result<Output, String> {
    t.start("deserialize");
    let presentation: Presentation =
        bincode::deserialize(bytes).map_err(|e| format!("deserialize presentation: {e}"))?;
    t.end("deserialize");

    let vk = presentation.verifying_key().clone();

    t.start("verify");
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation
        .verify(provider)
        .map_err(|e| format!("presentation verify: {e}"))?;
    t.end("verify");

    Ok(output(
        Mode::Full,
        server_name.map(|n| n.to_string()),
        &connection_info,
        transcript.as_ref(),
        vk,
    ))
}

fn verify_split(
    bytes: &[u8],
    mode: Mode,
    provider: &CryptoProvider,
    t: &mut impl Tracker,
) -> Result<Output, String> {
    t.start("deserialize");
    let parts: PresentationParts =
        bincode::deserialize(bytes).map_err(|e| format!("deserialize presentation: {e}"))?;
    t.end("deserialize");

    let vk = parts.attestation.verifying_key().clone();

    // 1. Notary signature over the header + Merkle proof of the body fields.
    t.start("attestation");
    let attestation = parts
        .attestation
        .verify(provider)
        .map_err(|e| format!("attestation verify: {e}"))?;
    t.end("attestation");

    let body: BodyParts = bincode::serialize(&attestation.body)
        .and_then(|b| bincode::deserialize(&b))
        .map_err(|e| format!("body mirror: {e}"))?;
    let conn = &body.connection_info.data;

    // 2. Server identity: cert commitment opening + webpki chain + TLS server
    //    signature over the ephemeral key (ring under the hood).
    let server_name = match (mode, parts.identity) {
        (Mode::Split, Some(identity)) => {
            t.start("identity");
            let name = identity
                .verify_with_provider(
                    provider,
                    conn.time,
                    &body.server_ephemeral_key.data,
                    &body.cert_commitment.data,
                )
                .map_err(|e| format!("identity verify: {e}"))?;
            t.end("identity");
            Some(name.to_string())
        }
        _ => None,
    };

    // 3. Transcript: SHA256 plaintext-hash openings against the commitments.
    t.start("transcript");
    let transcript = parts
        .transcript
        .map(|tp| {
            tp.verify_with_provider(
                &provider.hash,
                &conn.transcript_length,
                body.transcript_commitments.iter().map(|f| &f.data),
            )
        })
        .transpose()
        .map_err(|e| format!("transcript verify: {e}"))?;
    t.end("transcript");

    Ok(output(mode, server_name, conn, transcript.as_ref(), vk))
}

fn output(
    mode: Mode,
    server_name: Option<String>,
    conn: &ConnectionInfo,
    transcript: Option<&PartialTranscript>,
    vk: VerifyingKey,
) -> Output {
    let (sent_authed, recv_authed) = transcript
        .map(|p| (p.sent_authed().len() as u32, p.received_authed().len() as u32))
        .unwrap_or_default();
    Output {
        mode,
        server_name,
        session_time: conn.time,
        sent_len: conn.transcript_length.sent,
        recv_len: conn.transcript_length.received,
        sent_authed,
        recv_authed,
        notary_key_alg: vk.alg.as_u8(),
        notary_key: vk.data,
    }
}
