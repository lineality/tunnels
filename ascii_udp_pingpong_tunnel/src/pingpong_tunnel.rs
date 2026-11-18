//! # PingPong Two-Table ASCII UDP Tunnel (v7-lite)
//!
//! File: `tunnels/ascii_udp_pingpong_tunnel/src/pingpong_tunnel.rs`
//!
//! Single-flat module (project rule "Single-Flat"). `src/main.rs` contains only
//! the module declaration, one `use` of the entry point, and the process-exit
//! boundary. This file uses only the Rust standard library (no third-party
//! crates, no `unsafe`) and is intended to be portable into other crates.
//!
//! ## Status and Warning (read first)
//!
//! This is an educational research exploration of a home-made "Pearson
//! PingPong" stream-style cipher. It is NOT reviewed cryptography and must NOT
//! be relied upon to protect anything that matters. The advice "do not roll
//! your own crypto" applies here in full. This crate exists to make design
//! questions concrete, inspectable, and testable: nonces, key schedules,
//! ciphertext feedback, table mutation, replay windows, and fail-fast packet
//! checks. See "Known Limitations" below before drawing any conclusions.
//!
//! - Development phase: v7-lite, an MVP-1 hardening pass (LHF-1..LHF-24,
//!   see "Change Log"). Core cipher-design changes are deferred to v7.
//! - Wire compatibility: v7-lite is NOT compatible with v6 packets. There is
//!   no version byte, so both peers must run the same version.
//!
//! ## Intended Scope (what this tunnel is)
//!
//! - A live, terminal-based ASCII "text-ticker" between a small team of
//!   1..=`MAX_PEER_TARGETS` peers over UDP/IPv4.
//! - Each stdin line (up to `PAYLOAD_SIZE` bytes per packet; longer lines are
//!   split across packets) is encrypted separately for each configured peer
//!   and sent as one fixed-size `PACKET_SIZE`-byte datagram.
//! - Received text that passes every check is written to stdout. Nothing is
//!   stored.
//!
//! Features, not bugs:
//! - No chat history. Once text scrolls off the terminal, it is gone.
//! - Fixed-size packets. Every datagram is exactly `PACKET_SIZE` bytes, so
//!   message length is not visible on the wire. The cost is padding bytes.
//! - ASCII only: TAB, LF, CR, and printable 0x20..=0x7E. UTF-8 is out of scope.
//! - Stateless datagrams. Every packet is self-contained (its own nonce,
//!   timestamp, and freshly initialized tables), so lost, reordered, or
//!   duplicated UDP datagrams never desynchronize sender and receiver.
//! - Zero heap in production-release paths (stack buffers only).
//! - Fail-fast receiver. Cheap checks run before any decryption work.
//!
//! Non-goals (for this version): chat history, delivery guarantees,
//! retransmission, UTF-8, IPv6, audio or video, production-grade security,
//! and Windows support (welcome if it works, but not a target; POSIX is the
//! target, e.g. `/dev/urandom` and absolute `/`-rooted paths).
//!
//! ## Packet Layout (v7-lite, 64 bytes)
//!
//! | Bytes  | Field                | On wire   | Notes |
//! |--------|----------------------|-----------|-------|
//! | 0..=3  | nonce (u32 LE)       | plain     | Fresh OS entropy per packet (`/dev/urandom`). Never derived from salts or text. |
//! | 4..=7  | timestamp (u32 BE)   | plain     | Unix seconds. NOT inverted, NOT encrypted. Bound into the key schedule, so tampering breaks decryption. |
//! | 8..=61 | payload (54 bytes)   | encrypted | ASCII text followed by 0x00 padding (padding always at the end). |
//! | 62     | validation byte      | encrypted | The recipient's `{name}_val`, encrypted as stream position 54 (after all payload mutation). |
//! | 63     | checksum             | plain     | Wrapping sum of bytes 0..=62. Corruption filter only. |
//!
//! Why the plain checksum leaks nothing about keys: it is computed only from
//! bytes 0..=62 *as transmitted*, all of which an observer already sees. It
//! is NOT authentication. It cheaply discards corrupted datagrams before any
//! decryption work. (The v6 bytes 62/63 were encryptions under the fresh,
//! unmutated table T1, which handed an observer a known plaintext/ciphertext
//! pair from the initial table on every packet. That design is removed.)
//!
//! ## Key Ownership Model (recipient-key, LHF-21)
//!
//! The shared TOML config holds one key set per identity name: 16 salts
//! (`{name}_salt_1` ..= `{name}_salt_16`) and one validation byte
//! (`{name}_val`). In v7-lite a key set belongs to the RECIPIENT `{name}`:
//! - Sender: for each peer P, encrypts with P's salts and P's validation byte.
//! - Receiver: decrypts every incoming packet exactly once, with its OWN
//!   (self) key set. There is no per-peer trial decryption.
//!
//! Consequence (documented, not hidden): anyone holding the shared config can
//! read and forge traffic addressed to any identity in it. Per-pair keys are
//! a planning item.
//!
//! ## Key Schedule: Salts Are Read Only at Per-Packet Initialization
//!
//! 1. Salt groups ("Dining Rations"): `salts[0..8]` belong to table T1 and
//!    `salts[8..16]` belong to table T2.
//! 2. Seeds (FNV-1a-64 over bytes; salts serialized little-endian):
//!    - `seed_t1 = FNV1a64(0x01 || group_1 || nonce || timestamp)`
//!    - `seed_t2 = FNV1a64(0x02 || group_2 || nonce || timestamp)`
//!
//!    The domain-tag bytes 0x01 and 0x02 keep T1 and T2 distinct even if a
//!    user configures identical groups. Including the timestamp binds it to
//!    the packet (LHF-7). Including the nonce makes every packet's tables
//!    fresh.
//! 3. Tables: each seed drives a 64-bit LCG through a Fisher-Yates shuffle
//!    of the identity permutation. Inverse tables are built from the result.
//! 4. Mutation keys: each table's LCG then emits `MUTATION_KEY_LEN` bytes
//!    (`mk1`, `mk2`), unique per packet.
//! 5. After step 4 the salts are never read again for that packet. The
//!    per-byte loop uses only T1, T2, their inverses, `mk1`, `mk2`, and
//!    ciphertext feedback (LHF-2).
//!
//! ## Per-Byte Stream Loop (positions p = 0..ENCRYPTED_STREAM_LEN)
//!
//! The stream is `payload[0..54]` followed by the validation byte.
//! `state` starts at 0 for every packet.
//!
//! ```text
//! Encrypt (m -> c):
//!   x = T1[state ^ m ^ p];  c = T2[x];  state = c
//!   mutate T2 around x using offset (mk2[p & MASK] | 1)
//!   mutate T1 around c using offset (mk1[p & MASK] | 1)
//! Decrypt (c -> m):
//!   x = T2_inv[c];  raw = T1_inv[x];  m = state ^ raw ^ p;  state = c
//!   identical mutations (both sides know x and c)
//! ```
//!
//! Each mutation is two swaps. The offset is forced odd, so the two indices
//! of each swap always differ.
//!
//! ## Receiver Fail-Fast Pipeline (cheapest first; any failure = silent drop)
//!
//! | Step | Check | Code on failure |
//! |------|-------|-----------------|
//! | 1 | datagram length == `PACKET_SIZE` | 10 |
//! | 2 | byte 63 == wrapping sum of bytes 0..=62 (no decryption needed) | 13 |
//! | 3 | absolute difference (now, timestamp) <= `TIMESTAMP_WINDOW_SECONDS` | 11 |
//! | 4 | (timestamp, nonce) not in replay history (check only, no insert) | 12 |
//! | 5 | init engine with self keys + nonce + timestamp; decrypt 55 bytes | (none) |
//! | 6 | decrypted byte 62 == self validation byte | 203 |
//! | 7 | payload bytes before the first 0x00 are allowed ASCII | 202 |
//! | 8 | every byte after the first 0x00 is 0x00 (strict padding) | 204 |
//! | 9 | insert (timestamp, nonce) into replay history, ONLY now (LHF-8) | (none) |
//! | 10 | write accepted text to stdout | 31 / 32 |
//!
//! ## Sender Pipeline
//!
//! 1. Read one stdin line (up to `PAYLOAD_SIZE` bytes) and pad with 0x00.
//! 2. For each configured peer:
//!    - fresh nonce (fail closed on entropy error, LHF-9);
//!    - current timestamp;
//!    - init with the peer's keys;
//!    - encrypt payload and the peer's validation byte;
//!    - write the plaintext checksum;
//!    - send (bounded retry).
//!
//! ## Known Limitations (honest security notes)
//!
//! - Effective key material is far below the salt size. Each table is seeded
//!   by a 64-bit value and shuffled by a 64-bit-state LCG. So no matter how
//!   many salt bits are configured, at most about 2 x 64 bits of key reach
//!   the tables. The "512-bit" figure in older docs is NOT achieved. (Planning.)
//! - Authentication is weak. There is one 8-bit validation byte plus the
//!   ASCII/padding filters; this is not a MAC. (Planning: tag length.)
//! - Replay protection is a ring of `REPLAY_HISTORY_LEN` entries inside a
//!   +/- `TIMESTAMP_WINDOW_SECONDS` window. More accepted packets than that
//!   within one window lets an old packet pass again. (Planning.)
//! - Not constant-time. Table lookups are data-dependent, so cache-timing
//!   side channels are not addressed. (Planning: branchless table selection,
//!   cache-line sweeping.)
//! - The Fisher-Yates step uses `% (idx + 1)`, which has slight modulo bias.
//! - u32 timestamps overflow on 2106-02-07 (code 53). (Planning: u64.)
//! - There is no forward secrecy. Anyone who obtains the config can decrypt
//!   every recorded packet addressed to identities in it.
//!
//! ## Configuration File (shared TOML subset; one `key = value` per line)
//!
//! ```toml
//! # Identity names: ASCII letters, digits, '_' or '-'; 1..=32 bytes.
//! alice_ip4 = "192.168.1.10"     # dotted quad, no leading zeros
//! alice_port = 40001             # 1..=65535
//! alice_salt_1 = 0x0F1E2D3C      # decimal or 0x-hex u32; salt_1 ..= salt_16 all required
//! # ... alice_salt_2 ..= alice_salt_16 ...
//! alice_val = 0x44               # 0..=255 (values > 255 rejected, LHF-10)
//! ```
//!
//! - Default path: `<directory of the executable>/tunnel.toml` (absolute).
//! - `--config` must be an absolute path (LHF-24).
//! - There is no built-in default key set; missing keys are errors (LHF-1).
//!
//! ## Modes and Case Handling (this crate)
//!
//! - Production-release: never panics, never prints from inside a function,
//!   never allocates on error paths. Failures are 2-byte `TunnelError` codes.
//!   Rendering happens only at the boundary (`main.rs` and the runtime loop's
//!   one stderr notice site), as `PPT-<code>` via a no-heap renderer.
//! - Debug: verbose `eprintln!` gated by `#[cfg(debug_assertions)]`.
//!   Internal-invariant `debug_assert!` is gated by
//!   `#[cfg(all(debug_assertions, not(test)))]`.
//! - Test: `#[cfg(test)] mod pingpong_tunnel_tests` at the end of this file.
//!   `unwrap`/`assert!` are allowed only there.
//!
//! Recovery tiers:
//! - Tier 1 (micro-retry): socket send and receive errors marked
//!   `is_retryable()`, with bounded attempts and backoff.
//! - Tier 2 (step fallback): a rejected datagram is dropped and the loop
//!   continues; a message whose nonce or clock fails is not sent and the
//!   loop continues.
//! - Tier 3 (macro): startup failures exit with a rendered code. The receive
//!   loop never exits on per-packet errors.
//!
//! ## Change Log (v6 -> v7-lite)
//!
//! - LHF-1  Removed hard-coded default salts and validation byte; fail closed.
//! - LHF-2  Salts read only at init; per-byte loop uses derived mutation keys.
//! - LHF-3  Salt groups split per table; seed_t2 no longer derived from seed_t1.
//! - LHF-4  Byte 62 = encrypted validation byte; byte 63 = plain sum checksum;
//!   fresh-table snapshots removed.
//! - LHF-5  Doc comments throughout; error-code table.
//! - LHF-6  Timestamp no longer inverted.
//! - LHF-7  Timestamp bound into the key schedule.
//! - LHF-8  Replay history inserts only after full validation.
//! - LHF-9  Nonce fails closed (no time/stack-address fallback).
//! - LHF-10 Validation byte > 255 rejected (no silent `as u8` truncation).
//! - LHF-11 Salt TOML-key suffix bounds-checked.
//! - LHF-12 IPv4 parser rejects empty octets and leading zeros.
//! - LHF-13 CLI rejects missing, oversized, duplicate, unknown, and excess arguments.
//! - LHF-14 Strict zero-padding check after the first 0x00.
//! - LHF-15 Error enum: Debug/Display gated, exhaustive `is_retryable`,
//!   `code()`, retired codes reserved.
//! - LHF-16 Panic-free arithmetic and indexing; bounded `for` loops.
//! - LHF-17 No `let _ =` on fallible I/O.
//! - LHF-18 Named layout constants with compile-time consistency checks.
//! - LHF-19 Lints: unconditional `forbid(unsafe_code)`; policy-mapped clippy lints.
//! - LHF-20 Tests renamed and extended per detection site.
//! - LHF-21 Recipient-key model (fixes v6 peers with different salts unable to talk).
//! - LHF-22 Exit status no longer truncates error codes (stderr `PPT-<code>`, exit 1).
//! - LHF-23 CLI uses `args_os()` (std `args()` panics on non-Unicode).
//! - LHF-24 No relative-path fallback; prompt input over-length is an error,
//!   not silent truncation.

// ----------------------------------------------------------------------------
// Lints: each maps to a project rule. Clippy lints are checked by
// `cargo clippy`; plain `cargo build` ignores the `clippy::` namespace.
// The test module re-allows unwrap/expect/indexing/arithmetic (test mode only).
// Hot-loop table indexing (u8 index into a [_; 256] table, provably in-bounds)
// carries a documented local `#[allow(clippy::indexing_slicing)]` in Part 5.
// ----------------------------------------------------------------------------
#![forbid(unsafe_code)]
// Rule: no unwrap/expect/panic in production-release.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unreachable)]
// Rule: no panicking index/slice; no unchecked arithmetic; no silent truncation.
#![deny(clippy::indexing_slicing)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::string_slice)]
// Rule: never hide a Result in `let _ =`; always handle results.
#![deny(clippy::let_underscore_must_use)]
#![deny(unused_must_use)]
// Rule: always extensive doc strings (private items included).
#![warn(clippy::missing_docs_in_private_items)]

use std::{
    fs::File,
    io::{Read, Write, stdin, stdout},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// =============================================================================
// PART 1b: CONSTANTS
// Single source of truth for every size, offset, limit, and tuning value.
// Compile-time consistency checks follow at the end of this part.
// =============================================================================

// ----- Packet layout (see module docs, "Packet Layout") ----------------------

/// Exact size in bytes of every PingPong datagram, sent and accepted.
///
/// Fixed size is deliberate: message length is invisible on the wire, and the
/// receiver rejects anything else with one comparison (fail-fast step 1).
const PACKET_SIZE: usize = 64;

/// Byte offset of the plaintext nonce (fresh OS entropy, one per packet).
const NONCE_OFFSET: usize = 0;

/// Length in bytes of the nonce field (u32, little-endian on the wire).
const NONCE_LEN: usize = 4;

/// Byte offset of the plaintext timestamp (Unix seconds, u32 big-endian).
///
/// Not inverted (LHF-6) and not encrypted (it is predictable known plaintext,
/// so encrypting it would only give an attacker known plaintext). It is bound
/// into the key schedule instead (LHF-7).
const TIMESTAMP_OFFSET: usize = 4;

/// Length in bytes of the timestamp field (u32 seconds; overflows 2106-02-07).
const TIMESTAMP_LEN: usize = 4;

/// Byte offset of the encrypted ASCII payload.
const PAYLOAD_OFFSET: usize = 8;

/// Number of ASCII payload bytes per packet (text followed by 0x00 padding).
///
/// Sized for typical short chat lines ("Lunch?" ... a few sentences). Longer
/// stdin lines are split across several packets by the sender loop.
const PAYLOAD_SIZE: usize = 54;

/// Index of the encrypted validation byte: the recipient's `{name}_val`,
/// encrypted as the final stream position after all payload mutation (LHF-4).
const VALIDATION_BYTE_INDEX: usize = 62;

/// Index of the plaintext checksum byte: wrapping sum of bytes 0..=62.
///
/// Corruption filter only (NOT authentication). Leaks nothing new because it
/// is computed only from bytes already visible on the wire.
const CHECKSUM_BYTE_INDEX: usize = 63;

/// Number of leading packet bytes covered by the checksum (bytes 0..=62).
const CHECKSUM_COVERED_LEN: usize = 63;

/// Number of bytes run through the per-byte stream loop:
/// `PAYLOAD_SIZE` payload bytes followed by the 1 validation byte.
const ENCRYPTED_STREAM_LEN: usize = 55;

// ----- Payload content rules (receiver fail-fast steps 7 and 8) ------------

/// Padding byte. Fills the payload after the text; must be at the end only,
/// and every byte after the first padding byte must also be padding (LHF-14).
const PAYLOAD_PADDING_BYTE: u8 = 0x00;

/// ASCII horizontal tab (allowed in payload text).
const ASCII_TAB: u8 = 0x09;

/// ASCII line feed (allowed in payload text).
const ASCII_LINE_FEED: u8 = 0x0A;

/// ASCII carriage return (allowed in payload text).
const ASCII_CARRIAGE_RETURN: u8 = 0x0D;

/// First printable ASCII byte (space), inclusive.
const ASCII_PRINTABLE_FIRST: u8 = 0x20;

/// Last printable ASCII byte (tilde), inclusive. 0x7F (DEL) is excluded.
const ASCII_PRINTABLE_LAST: u8 = 0x7E;

// ----- Peers ----------------------------------------------------------------

/// Maximum number of peer targets per process.
///
/// No-heap design: peer storage is a fixed-size stack array. The tunnel is
/// intended for small teams (2..=4 people).
const MAX_PEER_TARGETS: usize = 4;

// ----- Key material and key schedule (see module docs, "Key Schedule") ------

/// Number of u32 salts in one identity's key set (`{name}_salt_1..=16`).
const SALT_COUNT: usize = 16;

/// Number of salts in each per-table group (half of `SALT_COUNT`, LHF-3).
const SALT_GROUP_SIZE: usize = 8;

/// Index of the first salt of the table-1 group (`salts[0..8]`).
const SALT_GROUP_T1_START: usize = 0;

/// Index of the first salt of the table-2 group (`salts[8..16]`).
const SALT_GROUP_T2_START: usize = 8;

/// Domain-separation tag hashed first into the table-1 seed.
///
/// Keeps T1 and T2 distinct even if a user configures identical salt groups.
const KEY_SCHEDULE_DOMAIN_TAG_T1: u8 = 0x01;

/// Domain-separation tag hashed first into the table-2 seed.
const KEY_SCHEDULE_DOMAIN_TAG_T2: u8 = 0x02;

/// FNV-1a 64-bit offset basis (standard published constant).
const FNV1A_64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a 64-bit prime (standard published constant).
const FNV1A_64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 64-bit LCG multiplier (Knuth MMIX). Used only to drive the Fisher-Yates
/// shuffle and the mutation-key bytes; not a cryptographic PRNG (see Known
/// Limitations).
const LCG_64_MULTIPLIER: u64 = 6_364_136_223_846_793_005;

/// 64-bit LCG increment (Knuth MMIX).
const LCG_64_INCREMENT: u64 = 1_442_695_040_888_963_407;

/// Size of each Pearson substitution table (one entry per byte value).
const PEARSON_TABLE_SIZE: usize = 256;

/// Bytes in each per-packet, per-table mutation key (`mk1`, `mk2`).
///
/// Must be a power of two so the stream position is mapped to a key index by
/// a branchless bitmask (`p & MUTATION_KEY_INDEX_MASK`) instead of `%`.
const MUTATION_KEY_LEN: usize = 16;

/// Bitmask mapping a stream position to a mutation-key index.
const MUTATION_KEY_INDEX_MASK: usize = 15;

// ----- Time window and replay filter ----------------------------------------

/// Maximum allowed absolute difference (seconds) between the receiver's clock
/// and a packet's timestamp, in either direction (fail-fast step 3).
const TIMESTAMP_WINDOW_SECONDS: u32 = 30;

/// Number of recently accepted (timestamp, nonce) pairs remembered for replay
/// rejection. Fixed-size stack ring buffer (see Known Limitations).
const REPLAY_HISTORY_LEN: usize = 32;

// ----- Network I/O ----------------------------------------------------------

/// Receive buffer size. Deliberately larger than `PACKET_SIZE` so an oversized
/// datagram is observed as "too long" and rejected, rather than truncated by
/// the OS into an apparently valid 64-byte read.
const RECEIVE_BUFFER_BYTES: usize = 128;

/// Sleep after a failed `recv_from` before retrying (Tier-1 backoff; keeps a
/// persistent socket error from becoming a busy spin).
const SOCKET_RECEIVE_ERROR_BACKOFF_MILLIS: u64 = 10;

/// Maximum send attempts per packet per peer (Tier-1 bounded retry).
const SOCKET_SEND_MAX_ATTEMPTS: u32 = 3;

/// Sleep between send attempts (Tier-1 backoff).
const SOCKET_SEND_RETRY_BACKOFF_MILLIS: u64 = 5;

// ----- Nonce entropy ----------------------------------------------------------

/// Absolute path of the OS entropy source used for nonces (POSIX).
///
/// No fallback source exists by design: if this fails, the message is not
/// sent (fail closed, LHF-9).
const NONCE_ENTROPY_SOURCE_PATH: &str = "/dev/urandom";

// ----- Configuration and TOML scanner ----------------------------------------

/// Config file name, joined to the absolute directory of the executable when
/// `--config` is not given.
const CONFIG_FILE_NAME: &str = "tunnel.toml";

/// Maximum byte length of an absolute config file path (stack buffer size).
const CONFIG_PATH_MAX_BYTES: usize = 256;

/// Maximum byte length of an identity name (e.g. `alice`, `bob_north`).
const IDENTITY_NAME_MAX_BYTES: usize = 32;

/// Maximum byte length of a fully built TOML key (e.g. `alice_salt_16`).
///
/// With validated names (32 bytes max) plus '_' plus the longest suffix
/// (`salt_16`, 7 bytes), keys fit with room to spare. Exceeding this limit is
/// therefore an internal invariant failure (code 108).
const TOML_KEY_MAX_BYTES: usize = 64;

/// Upper bound on bytes the TOML scanner will read from one file, per lookup.
/// Guards against huge or endless files (code 137).
const TOML_SCANNER_MAX_BYTES_SCANNED: u64 = 1_048_576;

/// Upper bound on TOML scanner loop iterations: the byte budget plus a small
/// slack for end-of-file handling. Keeps the scan loop provably bounded.
const TOML_SCANNER_MAX_LOOP_ITERATIONS: u64 = 1_048_592;

/// Stack buffer size for a raw IPv4 TOML value (`255.255.255.255` is 15 bytes).
const TOML_IPV4_VALUE_MAX_BYTES: usize = 32;

/// Stack buffer size for a raw port TOML value.
const TOML_PORT_VALUE_MAX_BYTES: usize = 16;

/// Stack buffer size for a raw u32 TOML value (salts, validation byte).
const TOML_U32_VALUE_MAX_BYTES: usize = 32;

/// Stack buffer size for a built salt suffix (`salt_1` ..= `salt_16`).
const SALT_SUFFIX_MAX_BYTES: usize = 16;

/// First TOML salt index (`{name}_salt_1`). TOML numbering is 1-based.
const SALT_TOML_INDEX_FIRST: usize = 1;

/// Last TOML salt index (`{name}_salt_16`); equals `SALT_COUNT`.
const SALT_TOML_INDEX_LAST: usize = 16;

/// Number of dotted-decimal octets in an IPv4 address.
const IPV4_OCTET_COUNT: usize = 4;

/// Maximum decimal digits in one IPv4 octet (`255`).
const IPV4_OCTET_MAX_DIGITS: usize = 3;

/// Maximum byte length of one interactive prompt answer. Longer input is an
/// error (code 180), never silently truncated (LHF-24).
const PROMPT_INPUT_MAX_BYTES: usize = 128;

// ----- Process boundary -------------------------------------------------------

/// Process exit status for any failure (LHF-22).
///
/// POSIX exit statuses carry only 8 bits, so `exit(code)` would corrupt codes
/// >= 256 (e.g. 300 -> 44). The boundary prints `PPT-<code>` to stderr and
/// exits with this single status instead.
pub const PROCESS_EXIT_STATUS_FAILURE: i32 = 1;

// ----- Compile-time consistency checks ----------------------------------------
// Evaluated by the compiler only. A violation is a BUILD error, never a
// runtime panic, so these are production-safe. They make the layout constants
// a single coherent source of truth: changing one value without the others
// fails the build instead of silently corrupting packets.
const _: () = {
    // Packet layout is contiguous and exactly PACKET_SIZE.
    assert!(NONCE_OFFSET == 0);
    assert!(TIMESTAMP_OFFSET == NONCE_OFFSET + NONCE_LEN);
    assert!(PAYLOAD_OFFSET == TIMESTAMP_OFFSET + TIMESTAMP_LEN);
    assert!(VALIDATION_BYTE_INDEX == PAYLOAD_OFFSET + PAYLOAD_SIZE);
    assert!(CHECKSUM_BYTE_INDEX == VALIDATION_BYTE_INDEX + 1);
    assert!(PACKET_SIZE == CHECKSUM_BYTE_INDEX + 1);
    assert!(CHECKSUM_COVERED_LEN == CHECKSUM_BYTE_INDEX);
    // Stream = payload + validation byte; positions fit in u8 (lossless cast).
    assert!(ENCRYPTED_STREAM_LEN == PAYLOAD_SIZE + 1);
    assert!(ENCRYPTED_STREAM_LEN <= 256);
    // Field widths match the u32 types used for nonce and timestamp.
    assert!(NONCE_LEN == 4);
    assert!(TIMESTAMP_LEN == 4);
    // Salt groups split SALT_COUNT exactly in half (LHF-3).
    assert!(SALT_GROUP_SIZE * 2 == SALT_COUNT);
    assert!(SALT_GROUP_T2_START == SALT_GROUP_T1_START + SALT_GROUP_SIZE);
    assert!(SALT_TOML_INDEX_FIRST == 1);
    assert!(SALT_TOML_INDEX_LAST == SALT_COUNT);
    // The salt-suffix builder supports 1- and 2-digit indexes only.
    assert!(SALT_TOML_INDEX_LAST < 100);
    // Branchless mutation-key indexing requires a power-of-two key length.
    assert!(MUTATION_KEY_LEN.is_power_of_two());
    assert!(MUTATION_KEY_INDEX_MASK == MUTATION_KEY_LEN - 1);
    // Tables are indexed by u8 values.
    assert!(PEARSON_TABLE_SIZE == 256);
    // Receive buffer must exceed packet size to detect oversized datagrams.
    assert!(RECEIVE_BUFFER_BYTES > PACKET_SIZE);
    // Non-empty bounded structures.
    assert!(REPLAY_HISTORY_LEN > 0);
    assert!(MAX_PEER_TARGETS > 0);
    assert!(SOCKET_SEND_MAX_ATTEMPTS > 0);
    // TOML loop bound covers the byte budget plus EOF slack.
    assert!(TOML_SCANNER_MAX_LOOP_ITERATIONS == TOML_SCANNER_MAX_BYTES_SCANNED + 16);
    // Longest built key ("<32-byte name>_salt_16") fits the key buffer.
    assert!(IDENTITY_NAME_MAX_BYTES + 1 + 7 <= TOML_KEY_MAX_BYTES);
    // Printable range is ordered.
    assert!(ASCII_PRINTABLE_FIRST < ASCII_PRINTABLE_LAST);
};

// =============================================================================
// PART 2: ERROR CODES (single project-wide fieldless enum)
// =============================================================================

/// Maximum decimal digits needed to render any `u16` error code (`65535`).
const ERROR_CODE_DECIMAL_MAX_DIGITS: usize = 5;

/// ASCII digit lookup for the no-heap error-code renderer.
const DECIMAL_DIGIT_ASCII: [u8; 10] = *b"0123456789";

/// Project-wide error code for the PingPong tunnel (`PPT-<code>`).
///
/// # Policy
///
/// - Fieldless and `Copy`: exactly 2 bytes. No heap, no `String`, no
///   `io::Error` payloads (payloads can carry paths, PII, or key-related
///   detail). The discriminant IS the code.
/// - APPEND-ONLY: a code number is never renumbered or reused. Retired codes
///   stay in the enum, never constructed, so the compiler rejects any attempt
///   to reuse their number (duplicate discriminant, E0081).
/// - Retry behavior is defined per code in `is_retryable` (exhaustive, no
///   wildcard), never by number ranges.
/// - Functions return codes; they never print them. Rendering to text happens
///   only at the boundary (`render_code_decimal` then stderr), as `PPT-<code>`.
/// - `Debug` and `Display` exist only in test/debug builds, so no error text
///   ships in production-release binaries, and a stray `{:?}` in production
///   code fails to compile (intended guard).
///
/// # Code Blocks
///
/// | Range   | Area |
/// |---------|------|
/// | 1-9     | UDP socket (OS) |
/// | 10-29   | UDP frame integrity (receiver fail-fast, pre-decryption) |
/// | 30-49   | Local terminal I/O (stdin/stdout) |
/// | 50-69   | Nonce entropy and system clock |
/// | 70-99   | Unassigned (reserved: OS/environment) |
/// | 100-129 | Configuration values |
/// | 130-150 | TOML scanner |
/// | 151-159 | Unassigned |
/// | 160-179 | Command-line arguments |
/// | 180-199 | Interactive prompts |
/// | 200-299 | Cryptographic / decrypted-payload checks |
/// | 300-399 | Threading |
/// | 400-499 | Cross-cutting internal invariants |
///
/// # Error-Code Table
///
/// Class legend:
/// - IV: input validation (expected: bad input, bad config, hostile or
///   corrupt packet).
/// - OS: environment failure (expected).
/// - INV: internal invariant (should-not-happen check; only a code bug,
///   bit-flip, or memory corruption can trigger it).
/// - RET: retired (never constructed; number reserved forever).
///
/// | Code | Variant | Class | Retry | Meaning |
/// |-----:|---------|:-----:|:-----:|---------|
/// | 1   | SocketBindFailed               | OS  | no  | Bind to the self endpoint failed |
/// | 3   | SocketReadFailed               | OS  | yes | `recv_from` failed |
/// | 4   | SocketWriteFailed              | OS  | yes | `send_to` failed |
/// | 5   | SocketCloneFailed              | OS  | no  | `try_clone` for the receive thread failed |
/// | 6   | SocketSendIncomplete           | OS  | yes | `send_to` sent fewer than `PACKET_SIZE` bytes |
/// | 10  | UdpPacketTruncated             | IV  | no  | Datagram length != `PACKET_SIZE` (short OR long) |
/// | 11  | UdpTimestampStale              | IV  | no  | Timestamp outside window (past or future) |
/// | 12  | UdpReplayDetected              | IV  | no  | (timestamp, nonce) already accepted |
/// | 13  | UdpChecksumMismatch            | IV  | no  | Byte 63 != wrapping sum of bytes 0..=62 |
/// | 30  | TerminalStdinReadFailed        | OS  | no  | Reading stdin failed |
/// | 31  | TerminalStdoutWriteFailed      | OS  | no  | Writing accepted text to stdout failed |
/// | 32  | TerminalStdoutFlushFailed      | OS  | no  | Flushing stdout failed |
/// | 50  | NonceEntropyOpenFailed         | OS  | no  | Entropy source could not be opened |
/// | 51  | NonceEntropyReadFailed         | OS  | no  | Entropy source read failed |
/// | 52  | ClockBeforeUnixEpoch           | OS  | no  | System clock earlier than 1970-01-01 |
/// | 53  | ClockTimestampExceedsU32       | OS  | no  | System clock past u32 seconds (2106) |
/// | 100 | ConfigInvalidPort              | IV  | no  | Port empty, non-digit, leading zero, zero, or > 65535 |
/// | 101 | ConfigInvalidIp                | IV  | no  | IPv4 text contains a character other than digit or '.' |
/// | 102 | ConfigInvalidArgs              | IV  | no  | Required identity not provided at prompt |
/// | 103 | ConfigInvalidToml              | IV  | no  | TOML value bytes are not valid UTF-8 |
/// | 104 | ConfigExePathFailed            | OS  | no  | Executable dir unresolvable / not UTF-8 / too long |
/// | 105 | ConfigNoPeersConfigured        | IV  | no  | Zero peers configured (fail closed) |
/// | 106 | ConfigValidationByteOutOfRange | IV  | no  | `{name}_val` > 255 |
/// | 107 | ConfigSaltIndexOutOfRange      | INV | no  | Salt suffix index outside 1..=`SALT_COUNT` |
/// | 108 | ConfigTomlKeyTooLong           | INV | no  | Built TOML key exceeds `TOML_KEY_MAX_BYTES` |
/// | 109 | ConfigU32ValueEmpty            | IV  | no  | Numeric value empty after trimming |
/// | 110 | ConfigU32ValueInvalidDigit     | IV  | no  | Numeric value has an invalid digit |
/// | 111 | ConfigU32ValueOverflow         | IV  | no  | Numeric value exceeds u32 |
/// | 112 | ConfigIpv4OctetEmpty           | IV  | no  | IPv4 octet is empty (e.g. "1..2.3") |
/// | 113 | ConfigIpv4OctetLeadingZero     | IV  | no  | IPv4 octet has a leading zero (e.g. "010") |
/// | 114 | ConfigIpv4OctetOutOfRange      | IV  | no  | IPv4 octet > 255 or > 3 digits |
/// | 115 | ConfigIpv4WrongOctetCount      | IV  | no  | IPv4 text does not have exactly 4 octets |
/// | 116 | ConfigIdentityNameEmpty        | IV  | no  | Identity name is empty |
/// | 117 | ConfigIdentityNameInvalidChar  | IV  | no  | Identity name has a char other than [A-Za-z0-9_-] |
/// | 118 | ConfigIdentityNameTooLong      | IV  | no  | Identity name > `IDENTITY_NAME_MAX_BYTES` |
/// | 119 | ConfigPathTooLong              | IV  | no  | Config path > `CONFIG_PATH_MAX_BYTES` |
/// | 120 | ConfigPathNotUnicode           | IV  | no  | Config path is not valid UTF-8 |
/// | 121 | ConfigPathNotAbsolute          | IV  | no  | Config path does not start with '/' |
/// | 122 | ConfigSaltSetAllZero           | IV  | no  | All salts are zero (blank template) |
/// | 130 | TomlEmptyKey                   | INV | no  | Scanner called with an empty key |
/// | 131 | TomlOutputBufferZeroSized      | INV | no  | Scanner output buffer size is 0 |
/// | 132 | TomlFileOpenFailed             | OS  | no  | Config file could not be opened |
/// | 133 | TomlFileReadFailed             | OS  | no  | I/O error while reading the config file |
/// | 134 | TomlFieldNotFound              | IV  | no  | Requested key not present |
/// | 135 | TomlValueExceedsOutputBuffer   | IV  | no  | Value longer than its stack buffer |
/// | 136 | TomlValueUnterminatedAtEof     | IV  | no  | Value unterminated at end of file |
/// | 137 | TomlSafetyBudgetExhausted      | IV  | no  | Byte or iteration budget exhausted |
/// | 160 | CliFlagMissingValue            | IV  | no  | Flag given without its value |
/// | 161 | CliValueTooLong                | IV  | no  | Flag value exceeds its buffer |
/// | 162 | CliTooManyPeers                | IV  | no  | More than `MAX_PEER_TARGETS` `--peer` flags |
/// | 163 | CliUnknownArgument             | IV  | no  | Unrecognized argument |
/// | 164 | CliArgumentNotUnicode          | IV  | no  | Argument is not valid Unicode |
/// | 165 | CliDuplicateFlag               | IV  | no  | `--config` or `--self` given more than once |
/// | 180 | PromptInputTooLong             | IV  | no  | Prompt answer > `PROMPT_INPUT_MAX_BYTES` |
/// | 181 | PromptInputNotUnicode          | IV  | no  | Prompt answer is not valid UTF-8 |
/// | 200 | CryptoByte63Failed             | RET | no  | v6 fresh-table byte-63 check (retired by LHF-4) |
/// | 201 | CryptoByte62Failed             | RET | no  | v6 fresh-table byte-62 check (retired by LHF-4) |
/// | 202 | CryptoInvalidAscii             | IV  | no  | Decrypted text has a disallowed byte |
/// | 203 | CryptoValidationByteMismatch   | IV  | no  | Decrypted byte 62 != self validation byte |
/// | 204 | CryptoPaddingNotZero           | IV  | no  | Non-zero byte after the first padding byte |
/// | 205 | CryptoTableNotPermutation      | INV | no  | Initialized table is not a valid permutation |
/// | 300 | InternalThreadSpawnFailed      | OS  | no  | Receive thread could not be spawned |
/// | 400 | InternalErrorCodeRenderFailed  | INV | no  | No-heap code renderer arithmetic failed |
/// | 401 | InternalPortIntegrityCheckFailed            | INV | no | Port recheck failed |
/// | 402 | InternalIpv4IntegrityCheckFailed            | INV | no | IPv4 recheck failed |
/// | 403 | InternalIdentityNameIntegrityCheckFailed    | INV | no | Identity name recheck failed |
/// | 404 | InternalValidationByteIntegrityCheckFailed  | INV | no | Validation byte recheck failed |
/// | 405 | InternalSaltSetIntegrityCheckFailed         | INV | no | Salt set recheck / group split failed |
/// | 406 | InternalPeerRosterIntegrityCheckFailed      | INV | no | Peer roster inconsistent |
/// | 407 | InternalPeerRosterFull                      | INV | no | Append to full peer roster |
#[cfg_attr(any(test, debug_assertions), derive(Debug))]
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum TunnelError {
    // ----- 1-9: UDP socket (OS) ------------------------------------------------
    /// `UdpSocket::bind` on the self endpoint failed (address not local, port
    /// in use, or permission denied). Startup only. Recovery: Tier 3 (exit).
    SocketBindFailed = 1,

    /// `recv_from` returned an error. Recovery: Tier 1 (backoff, continue
    /// receiving; the receive loop never exits on this).
    SocketReadFailed = 3,

    /// `send_to` returned an error. Recovery: Tier 1 (bounded resend of the
    /// same packet), then Tier 2 (drop this message for this peer).
    SocketWriteFailed = 4,

    /// `UdpSocket::try_clone` (socket handle for the receive thread) failed.
    /// Startup only. Recovery: Tier 3 (exit).
    SocketCloneFailed = 5,

    /// `send_to` reported fewer than `PACKET_SIZE` bytes sent. Safe to resend:
    /// the receiver drops any partial datagram at step 1. Recovery: as code 4.
    SocketSendIncomplete = 6,

    // ----- 10-29: UDP frame integrity (receiver fail-fast) ---------------------
    /// Datagram length != `PACKET_SIZE` (shorter OR longer; the v6 name is kept
    /// for code stability). Fail-fast step 1. Recovery: Tier 2 (silent drop).
    UdpPacketTruncated = 10,

    /// Packet timestamp is more than `TIMESTAMP_WINDOW_SECONDS` from the local
    /// clock, in either direction. Step 3. Recovery: Tier 2 (silent drop).
    UdpTimestampStale = 11,

    /// (timestamp, nonce) pair already accepted recently. Step 4.
    /// Recovery: Tier 2 (silent drop).
    UdpReplayDetected = 12,

    /// Byte 63 != wrapping sum of bytes 0..=62 (corruption filter, not
    /// authentication). Step 2. Recovery: Tier 2 (silent drop).
    UdpChecksumMismatch = 13,

    // ----- 30-49: local terminal I/O ---------------------------------------------
    /// Reading stdin failed. Recovery: Tier 2 (stop the send loop cleanly;
    /// the boundary renders the code).
    TerminalStdinReadFailed = 30,

    /// Writing accepted text to stdout failed. Recovery: Tier 2 (that
    /// message's display is lost; the receive loop continues).
    TerminalStdoutWriteFailed = 31,

    /// Flushing stdout failed. Recovery: Tier 2 (receive loop continues).
    TerminalStdoutFlushFailed = 32,

    // ----- 50-69: nonce entropy and clock ----------------------------------------
    /// Opening the OS entropy source failed. There is no fallback (fail
    /// closed, LHF-9). Recovery: Tier 2 (this message is not sent).
    NonceEntropyOpenFailed = 50,

    /// Reading nonce bytes from the OS entropy source failed. Recovery: Tier 2
    /// (this message is not sent).
    NonceEntropyReadFailed = 51,

    /// System clock reports a time before the Unix epoch. Recovery: Tier 2
    /// (sender: message not sent; receiver: packet dropped).
    ClockBeforeUnixEpoch = 52,

    /// System clock is past the u32 seconds range (after 2106-02-07).
    /// Recovery: Tier 2. Planning item: widen timestamps to u64.
    ClockTimestampExceedsU32 = 53,

    // ----- 100-129: configuration values -----------------------------------------
    /// Port text is empty, non-digit, zero, or > 65535.
    ConfigInvalidPort = 100,

    /// IPv4 text contains a character other than an ASCII digit or '.'.
    /// (Other IPv4 shape failures have their own codes, 112-115.)
    ConfigInvalidIp = 101,

    /// A required identity name was not provided at the interactive prompt
    /// (empty answer). Startup only.
    ConfigInvalidArgs = 102,

    /// Raw TOML value bytes are not valid UTF-8.
    ConfigInvalidToml = 103,

    /// The executable's directory could not be resolved, is not UTF-8, or is
    /// too long to hold the default config path. There is no relative-path
    /// fallback (LHF-24); the user may pass `--config` with an absolute path.
    ConfigExePathFailed = 104,

    /// No peers configured. There are no default keys to fall back to
    /// (fail closed, LHF-1). Startup only.
    ConfigNoPeersConfigured = 105,

    /// `{name}_val` parsed to a value > 255 (previously silently truncated
    /// by `as u8`, LHF-10).
    ConfigValidationByteOutOfRange = 106,

    /// INV: the salt-suffix builder was called with an index outside
    /// 1..=`SALT_COUNT`. Only internal bounded loops call it (LHF-11).
    ConfigSaltIndexOutOfRange = 107,

    /// INV: a built TOML key exceeded `TOML_KEY_MAX_BYTES`. Unreachable with
    /// validated identity names (see the const check on key length).
    ConfigTomlKeyTooLong = 108,

    /// Numeric TOML value is empty after trimming whitespace and quotes.
    ConfigU32ValueEmpty = 109,

    /// Numeric TOML value contains a non-decimal or non-hex digit.
    ConfigU32ValueInvalidDigit = 110,

    /// Numeric TOML value exceeds `u32::MAX`.
    ConfigU32ValueOverflow = 111,

    /// IPv4 octet is empty (e.g. `"1..2.3"`, `".1.2.3"`, `"1.2.3."`) (LHF-12).
    ConfigIpv4OctetEmpty = 112,

    /// IPv4 octet has a leading zero (e.g. `"010"`). Rejected because some
    /// parsers read leading zeros as octal, which makes the text ambiguous.
    ConfigIpv4OctetLeadingZero = 113,

    /// IPv4 octet value > 255 or more than `IPV4_OCTET_MAX_DIGITS` digits.
    ConfigIpv4OctetOutOfRange = 114,

    /// IPv4 text does not contain exactly `IPV4_OCTET_COUNT` octets.
    ConfigIpv4WrongOctetCount = 115,

    /// Identity name (CLI, prompt, or config lookup) is empty.
    ConfigIdentityNameEmpty = 116,

    /// Identity name contains a byte outside ASCII `[A-Za-z0-9_-]`. The
    /// restriction keeps built TOML keys unambiguous for the line scanner
    /// (no '=', '#', whitespace, or quotes).
    ConfigIdentityNameInvalidChar = 117,

    /// Identity name is longer than `IDENTITY_NAME_MAX_BYTES`.
    ConfigIdentityNameTooLong = 118,

    /// Config path is longer than `CONFIG_PATH_MAX_BYTES`.
    ConfigPathTooLong = 119,

    /// Config path is not valid UTF-8.
    ConfigPathNotUnicode = 120,

    /// Config path is not absolute, i.e. does not start with '/'
    /// (project rule: always absolute file paths).
    ConfigPathNotAbsolute = 121,

    /// All `SALT_COUNT` configured salts are zero, which is almost certainly an
    /// unfilled config template. This is NOT a key-strength test; it only catches
    /// the most likely blank-key mistake (same spirit as LHF-1: no weak keys
    /// by default).
    ConfigSaltSetAllZero = 122,

    // (in block 400-499, after InternalErrorCodeRenderFailed = 400)
    /// INV: a `Port` failed its integrity recheck (complement mismatch or zero).
    InternalPortIntegrityCheckFailed = 401,

    /// INV: an `Ipv4Address` failed its integrity recheck (complement mismatch).
    InternalIpv4IntegrityCheckFailed = 402,

    /// INV: an `IdentityName` failed its integrity recheck (complement mismatch,
    /// length out of bounds, disallowed byte, or non-zero tail padding).
    InternalIdentityNameIntegrityCheckFailed = 403,

    /// INV: a `ValidationByte` failed its integrity recheck (complement mismatch).
    InternalValidationByteIntegrityCheckFailed = 404,

    /// INV: a `SaltSet` failed its integrity recheck (complement mismatch or
    /// all-zero), or a salt-group split failed.
    InternalSaltSetIntegrityCheckFailed = 405,

    /// INV: a `PeerRoster` is inconsistent (count > max, or the occupied slots
    /// disagree with the count).
    InternalPeerRosterIntegrityCheckFailed = 406,

    /// INV: append to a full `PeerRoster`. Callers bound their loops by
    /// `MAX_PEER_TARGETS` (and the CLI rejects extra peers with code 162), so
    /// this is unreachable when the code is correct.
    InternalPeerRosterFull = 407,

    // ----- 130-150: TOML scanner ---------------------------------------------------
    /// INV: TOML scanner called with an empty target key.
    TomlEmptyKey = 130,

    /// INV: TOML scanner instantiated with a zero-sized output buffer.
    TomlOutputBufferZeroSized = 131,

    /// The config file could not be opened (missing, permission denied, ...).
    /// The path is NOT included in any error (PII rule).
    TomlFileOpenFailed = 132,

    /// I/O error while reading the config file.
    TomlFileReadFailed = 133,

    /// The requested key is not present in the config file.
    TomlFieldNotFound = 134,

    /// The value is longer than the caller's fixed stack buffer.
    TomlValueExceedsOutputBuffer = 135,

    /// End of file reached while a value was still open (e.g. no closing
    /// quote).
    TomlValueUnterminatedAtEof = 136,

    /// The scanner byte budget (`TOML_SCANNER_MAX_BYTES_SCANNED`) or loop
    /// budget (`TOML_SCANNER_MAX_LOOP_ITERATIONS`) was exhausted.
    TomlSafetyBudgetExhausted = 137,

    // ----- 160-179: command-line arguments -----------------------------------------
    /// A flag (`--config`/`-f`, `--self`/`-s`, `--peer`/`-p`) was given
    /// without a value (LHF-13).
    CliFlagMissingValue = 160,

    /// A flag value exceeds its fixed stack buffer (previously silently
    /// ignored).
    CliValueTooLong = 161,

    /// More than `MAX_PEER_TARGETS` `--peer` flags were given (previously
    /// silently ignored).
    CliTooManyPeers = 162,

    /// An unrecognized argument was given (previously silently ignored).
    CliUnknownArgument = 163,

    /// An argument is not valid Unicode. Read via `args_os()` because std
    /// `args()` would panic (LHF-23).
    CliArgumentNotUnicode = 164,

    /// `--config` or `--self` was given more than once (ambiguous intent).
    CliDuplicateFlag = 165,

    // ----- 180-199: interactive prompts --------------------------------------------
    /// Prompt answer longer than `PROMPT_INPUT_MAX_BYTES` (previously
    /// silently truncated, LHF-24).
    PromptInputTooLong = 180,

    /// Prompt answer is not valid UTF-8.
    PromptInputNotUnicode = 181,

    // ----- 200-299: cryptographic / decrypted-payload checks -----------------------
    /// RETIRED (v7-lite, LHF-4): v6 check of byte 63 under the fresh table.
    /// Never constructed. Kept so the compiler rejects reuse of 200.
    #[allow(dead_code)]
    CryptoByte63Failed = 200,

    /// RETIRED (v7-lite, LHF-4): v6 checksum of byte 62 under the fresh table.
    /// Never constructed. Kept so the compiler rejects reuse of 201.
    #[allow(dead_code)]
    CryptoByte62Failed = 201,

    /// Decrypted text (before the first padding byte) contains a byte other
    /// than TAB, LF, CR, or printable 0x20..=0x7E. Step 7. Recovery: Tier 2.
    CryptoInvalidAscii = 202,

    /// Decrypted byte 62 does not equal the self validation byte: wrong key,
    /// tampered packet, or tampered timestamp/nonce. Step 6. Recovery: Tier 2.
    CryptoValidationByteMismatch = 203,

    /// A non-zero byte follows the first padding byte (LHF-14). Step 8.
    /// Recovery: Tier 2.
    CryptoPaddingNotZero = 204,

    /// INV: an initialized table/inverse pair is not a consistent permutation
    /// (every value exactly once, inverse matches). Only a code bug or memory
    /// corruption can cause this. Recovery: Tier 2 (packet not sent/accepted).
    CryptoTableNotPermutation = 205,

    // ----- 300-399: threading --------------------------------------------------------
    /// The receive thread could not be spawned. Startup only.
    /// Recovery: Tier 3 (exit).
    InternalThreadSpawnFailed = 300,

    // ----- 400-499: cross-cutting internal invariants --------------------------------
    /// INV: the no-heap error-code renderer's checked arithmetic or indexing
    /// failed (unreachable for any u16). The boundary prints `PPT-?` instead.
    InternalErrorCodeRenderFailed = 400,
}

impl TunnelError {
    /// Returns the terse numeric error code. Available in all builds.
    /// No heap. Cannot fail.
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Returns whether this case is transient and worth a bounded Tier-1 retry.
    ///
    /// Explicit per-code list with NO wildcard arm: adding a variant fails to
    /// compile until it is classified here. Retry behavior is never inferred
    /// from number ranges.
    ///
    /// Only socket send/receive transients are retryable. Everything else is
    /// either deterministic (retrying gives the same result) or a security
    /// rejection (retrying would help an attacker, never a user).
    pub const fn is_retryable(self) -> bool {
        match self {
            TunnelError::SocketReadFailed
            | TunnelError::SocketWriteFailed
            | TunnelError::SocketSendIncomplete => true,

            TunnelError::SocketBindFailed
            | TunnelError::SocketCloneFailed
            | TunnelError::UdpPacketTruncated
            | TunnelError::UdpTimestampStale
            | TunnelError::UdpReplayDetected
            | TunnelError::UdpChecksumMismatch
            | TunnelError::TerminalStdinReadFailed
            | TunnelError::TerminalStdoutWriteFailed
            | TunnelError::TerminalStdoutFlushFailed
            | TunnelError::NonceEntropyOpenFailed
            | TunnelError::NonceEntropyReadFailed
            | TunnelError::ClockBeforeUnixEpoch
            | TunnelError::ClockTimestampExceedsU32
            | TunnelError::ConfigInvalidPort
            | TunnelError::ConfigInvalidIp
            | TunnelError::ConfigInvalidArgs
            | TunnelError::ConfigInvalidToml
            | TunnelError::ConfigExePathFailed
            | TunnelError::ConfigNoPeersConfigured
            | TunnelError::ConfigValidationByteOutOfRange
            | TunnelError::ConfigSaltIndexOutOfRange
            | TunnelError::ConfigTomlKeyTooLong
            | TunnelError::ConfigU32ValueEmpty
            | TunnelError::ConfigU32ValueInvalidDigit
            | TunnelError::ConfigU32ValueOverflow
            | TunnelError::ConfigIpv4OctetEmpty
            | TunnelError::ConfigIpv4OctetLeadingZero
            | TunnelError::ConfigIpv4OctetOutOfRange
            | TunnelError::ConfigIpv4WrongOctetCount
            | TunnelError::ConfigIdentityNameEmpty
            | TunnelError::ConfigIdentityNameInvalidChar
            | TunnelError::ConfigIdentityNameTooLong
            | TunnelError::ConfigPathTooLong
            | TunnelError::ConfigPathNotUnicode
            | TunnelError::ConfigPathNotAbsolute
            | TunnelError::TomlEmptyKey
            | TunnelError::TomlOutputBufferZeroSized
            | TunnelError::TomlFileOpenFailed
            | TunnelError::TomlFileReadFailed
            | TunnelError::TomlFieldNotFound
            | TunnelError::TomlValueExceedsOutputBuffer
            | TunnelError::TomlValueUnterminatedAtEof
            | TunnelError::TomlSafetyBudgetExhausted
            | TunnelError::CliFlagMissingValue
            | TunnelError::CliValueTooLong
            | TunnelError::CliTooManyPeers
            | TunnelError::CliUnknownArgument
            | TunnelError::CliArgumentNotUnicode
            | TunnelError::CliDuplicateFlag
            | TunnelError::PromptInputTooLong
            | TunnelError::PromptInputNotUnicode
            | TunnelError::CryptoByte63Failed
            | TunnelError::CryptoByte62Failed
            | TunnelError::CryptoInvalidAscii
            | TunnelError::CryptoValidationByteMismatch
            | TunnelError::CryptoPaddingNotZero
            | TunnelError::CryptoTableNotPermutation
            | TunnelError::InternalThreadSpawnFailed
            | TunnelError::ConfigSaltSetAllZero
            | TunnelError::InternalPortIntegrityCheckFailed
            | TunnelError::InternalIpv4IntegrityCheckFailed
            | TunnelError::InternalIdentityNameIntegrityCheckFailed
            | TunnelError::InternalValidationByteIntegrityCheckFailed
            | TunnelError::InternalSaltSetIntegrityCheckFailed
            | TunnelError::InternalPeerRosterIntegrityCheckFailed
            | TunnelError::InternalPeerRosterFull
            | TunnelError::InternalErrorCodeRenderFailed => false,
            // NO wildcard: a new variant is a compile error until classified.
        }
    }

    /// Renders this error's numeric code as decimal ASCII into a caller-owned
    /// stack buffer. No heap, no panic. Used only by output boundaries
    /// (process exit in `main.rs`, the runtime's stderr notice site), which
    /// print `PPT-<digits>`.
    ///
    /// Returns a `&str` borrowing the rendered digits from `output_buffer`.
    ///
    /// # Errors
    ///
    /// `InternalErrorCodeRenderFailed` (400, internal invariant): unreachable
    /// for any `u16`, because 5 digits always suffice. It is checked anyway
    /// per the no-unchecked-arithmetic rule. Callers print `PPT-?` on failure.
    pub fn render_code_decimal(
        self,
        output_buffer: &mut [u8; ERROR_CODE_DECIMAL_MAX_DIGITS],
    ) -> Result<&str, TunnelError> {
        let mut remaining_value: u16 = self.code();
        // Digits are written right-to-left; this is the index of the most
        // significant digit written so far.
        let mut first_digit_index: usize = ERROR_CODE_DECIMAL_MAX_DIGITS;

        // Bounded loop: at most ERROR_CODE_DECIMAL_MAX_DIGITS iterations.
        for _digit_slot in 0..ERROR_CODE_DECIMAL_MAX_DIGITS {
            // --- Check: decimal digit extraction (internal invariant) ---
            let digit_value: u16 = match remaining_value.checked_rem(10) {
                Some(digit) => digit,
                None => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(false, "PPT-400: render_code_decimal: checked_rem failed");
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: render_code_decimal: checked_rem failed",
                        TunnelError::InternalErrorCodeRenderFailed.code()
                    );
                    return Err(TunnelError::InternalErrorCodeRenderFailed);
                }
            };
            remaining_value = match remaining_value.checked_div(10) {
                Some(quotient) => quotient,
                None => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(false, "PPT-400: render_code_decimal: checked_div failed");
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: render_code_decimal: checked_div failed",
                        TunnelError::InternalErrorCodeRenderFailed.code()
                    );
                    return Err(TunnelError::InternalErrorCodeRenderFailed);
                }
            };
            // --- Check: write cursor stays within the buffer (internal invariant) ---
            first_digit_index = match first_digit_index.checked_sub(1) {
                Some(index) => index,
                None => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(false, "PPT-400: render_code_decimal: cursor underflow");
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: render_code_decimal: cursor underflow",
                        TunnelError::InternalErrorCodeRenderFailed.code()
                    );
                    return Err(TunnelError::InternalErrorCodeRenderFailed);
                }
            };
            // Lookup instead of `b'0' + digit`: no arithmetic, no truncating cast.
            let ascii_digit: u8 = match DECIMAL_DIGIT_ASCII.get(usize::from(digit_value)) {
                Some(ascii) => *ascii,
                None => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(false, "PPT-400: render_code_decimal: digit lookup failed");
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: render_code_decimal: digit lookup failed for {}",
                        TunnelError::InternalErrorCodeRenderFailed.code(),
                        digit_value
                    );
                    return Err(TunnelError::InternalErrorCodeRenderFailed);
                }
            };
            match output_buffer.get_mut(first_digit_index) {
                Some(slot) => *slot = ascii_digit,
                None => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(false, "PPT-400: render_code_decimal: buffer index failed");
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: render_code_decimal: buffer index {} failed",
                        TunnelError::InternalErrorCodeRenderFailed.code(),
                        first_digit_index
                    );
                    return Err(TunnelError::InternalErrorCodeRenderFailed);
                }
            }
            if remaining_value == 0 {
                break;
            }
        }

        // --- Check: all digits consumed (internal invariant; u16 <= 5 digits) ---
        if remaining_value != 0 {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "PPT-400: render_code_decimal: digits remain after loop"
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "PPT-{}: render_code_decimal: {} remains after loop",
                TunnelError::InternalErrorCodeRenderFailed.code(),
                remaining_value
            );
            return Err(TunnelError::InternalErrorCodeRenderFailed);
        }

        let digit_bytes: &[u8] = match output_buffer.get(first_digit_index..) {
            Some(bytes) => bytes,
            None => {
                #[cfg(all(debug_assertions, not(test)))]
                debug_assert!(false, "PPT-400: render_code_decimal: final slice failed");
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: render_code_decimal: final slice from {} failed",
                    TunnelError::InternalErrorCodeRenderFailed.code(),
                    first_digit_index
                );
                return Err(TunnelError::InternalErrorCodeRenderFailed);
            }
        };

        // Match-A-Function-Call-Pattern (internal invariant: digits are ASCII).
        match std::str::from_utf8(digit_bytes) {
            Ok(rendered_digits) => Ok(rendered_digits),
            Err(_utf8_detail) => {
                #[cfg(all(debug_assertions, not(test)))]
                debug_assert!(
                    false,
                    "PPT-{}: render_code_decimal: checked_rem failed",
                    TunnelError::InternalErrorCodeRenderFailed.code()
                );
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: render_code_decimal: {}",
                    TunnelError::InternalErrorCodeRenderFailed.code(),
                    _utf8_detail
                );
                Err(TunnelError::InternalErrorCodeRenderFailed)
            }
        }
    }
}

/// Human-readable error text. TEST AND DEBUG BUILDS ONLY: never compiled into
/// production-release binaries. Format: `PPT-<code>: <description>`. The
/// number comes from `code()` (single source of truth); it is never typed
/// into the text by hand.
#[cfg(any(test, debug_assertions))]
impl std::fmt::Display for TunnelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description: &str = match self {
            TunnelError::SocketBindFailed => "failed to bind UDP socket to self endpoint",
            TunnelError::SocketReadFailed => "failed to receive from UDP socket",
            TunnelError::SocketWriteFailed => "failed to send via UDP socket",
            TunnelError::SocketCloneFailed => "failed to clone UDP socket for receive thread",
            TunnelError::SocketSendIncomplete => "UDP send wrote fewer than PACKET_SIZE bytes",
            TunnelError::UdpPacketTruncated => "datagram length != PACKET_SIZE",
            TunnelError::UdpTimestampStale => "packet timestamp outside allowed window",
            TunnelError::UdpReplayDetected => "replayed (timestamp, nonce) pair",
            TunnelError::UdpChecksumMismatch => "plaintext checksum byte mismatch",
            TunnelError::TerminalStdinReadFailed => "failed to read stdin",
            TunnelError::TerminalStdoutWriteFailed => "failed to write stdout",
            TunnelError::TerminalStdoutFlushFailed => "failed to flush stdout",
            TunnelError::NonceEntropyOpenFailed => "failed to open OS entropy source",
            TunnelError::NonceEntropyReadFailed => "failed to read OS entropy source",
            TunnelError::ClockBeforeUnixEpoch => "system clock before Unix epoch",
            TunnelError::ClockTimestampExceedsU32 => "system clock beyond u32 seconds",
            TunnelError::ConfigInvalidPort => {
                "invalid port (empty, non-digit, leading zero, zero, or > 65535)"
            }
            TunnelError::ConfigInvalidIp => "invalid character in IPv4 address",
            TunnelError::ConfigInvalidArgs => "required identity name not provided",
            TunnelError::ConfigInvalidToml => "TOML value is not valid UTF-8",
            TunnelError::ConfigExePathFailed => {
                "cannot build default config path from executable directory"
            }
            TunnelError::ConfigNoPeersConfigured => "no peers configured",
            TunnelError::ConfigValidationByteOutOfRange => "validation byte value exceeds 255",
            TunnelError::ConfigSaltIndexOutOfRange => "salt suffix index out of range",
            TunnelError::ConfigTomlKeyTooLong => "built TOML key exceeds key buffer",
            TunnelError::ConfigU32ValueEmpty => "numeric value empty",
            TunnelError::ConfigU32ValueInvalidDigit => "numeric value has invalid digit",
            TunnelError::ConfigU32ValueOverflow => "numeric value exceeds u32",
            TunnelError::ConfigIpv4OctetEmpty => "IPv4 octet empty",
            TunnelError::ConfigIpv4OctetLeadingZero => "IPv4 octet has leading zero",
            TunnelError::ConfigIpv4OctetOutOfRange => "IPv4 octet out of range",
            TunnelError::ConfigIpv4WrongOctetCount => "IPv4 address does not have 4 octets",
            TunnelError::ConfigIdentityNameEmpty => "identity name empty",
            TunnelError::ConfigIdentityNameInvalidChar => "identity name has invalid character",
            TunnelError::ConfigIdentityNameTooLong => "identity name too long",
            TunnelError::ConfigPathTooLong => "config path too long",
            TunnelError::ConfigPathNotUnicode => "config path not valid UTF-8",
            TunnelError::ConfigPathNotAbsolute => "config path not absolute",
            TunnelError::TomlEmptyKey => "TOML scanner: empty key",
            TunnelError::TomlOutputBufferZeroSized => "TOML scanner: zero-sized output buffer",
            TunnelError::TomlFileOpenFailed => "TOML scanner: failed to open config file",
            TunnelError::TomlFileReadFailed => "TOML scanner: I/O error while reading",
            TunnelError::TomlFieldNotFound => "TOML scanner: key not found",
            TunnelError::TomlValueExceedsOutputBuffer => "TOML scanner: value exceeds buffer",
            TunnelError::TomlValueUnterminatedAtEof => "TOML scanner: value unterminated at EOF",
            TunnelError::TomlSafetyBudgetExhausted => "TOML scanner: safety budget exhausted",
            TunnelError::CliFlagMissingValue => "CLI flag missing its value",
            TunnelError::CliValueTooLong => "CLI value too long",
            TunnelError::CliTooManyPeers => "too many --peer flags",
            TunnelError::CliUnknownArgument => "unknown CLI argument",
            TunnelError::CliArgumentNotUnicode => "CLI argument not valid Unicode",
            TunnelError::CliDuplicateFlag => "CLI flag given more than once",
            TunnelError::PromptInputTooLong => "prompt input too long",
            TunnelError::PromptInputNotUnicode => "prompt input not valid UTF-8",
            TunnelError::CryptoByte63Failed => "RETIRED v6 code (byte 63 check)",
            TunnelError::CryptoByte62Failed => "RETIRED v6 code (byte 62 check)",
            TunnelError::CryptoInvalidAscii => "decrypted payload contains disallowed byte",
            TunnelError::CryptoValidationByteMismatch => "decrypted validation byte mismatch",
            TunnelError::CryptoPaddingNotZero => "non-zero byte after padding start",
            TunnelError::CryptoTableNotPermutation => "table is not a valid permutation",
            TunnelError::InternalThreadSpawnFailed => "failed to spawn receive thread",
            TunnelError::InternalErrorCodeRenderFailed => "error-code renderer failed",

            TunnelError::ConfigSaltSetAllZero => "all configured salts are zero",
            TunnelError::InternalPortIntegrityCheckFailed => "port integrity recheck failed",
            TunnelError::InternalIpv4IntegrityCheckFailed => "IPv4 integrity recheck failed",
            TunnelError::InternalIdentityNameIntegrityCheckFailed => {
                "identity name integrity recheck failed"
            }
            TunnelError::InternalValidationByteIntegrityCheckFailed => {
                "validation byte integrity recheck failed"
            }
            TunnelError::InternalSaltSetIntegrityCheckFailed => "salt set integrity recheck failed",
            TunnelError::InternalPeerRosterIntegrityCheckFailed => {
                "peer roster integrity recheck failed"
            }
            TunnelError::InternalPeerRosterFull => "append to full peer roster",
        };
        write!(formatter, "PPT-{}: {}", self.code(), description)
    }
}

// =============================================================================
// PART 2: VALIDATED CUSTOM TYPES (project rule 5: Enforced Custom Types)
// =============================================================================
//
// Every configuration-derived value (ports, IPv4 addresses, identity names,
// validation bytes, salts) crosses function boundaries only as one of these
// types, never as a raw primitive. "Parse, don't validate": untrusted text is
// checked once by a constructor, and the rest of the tunnel can rely on the
// type.
//
// Value-integrity pattern used by every type in this part:
// 1. One validating constructor per type; fields are private to the inner
//    module, so nothing else in the file can build or modify a value directly.
// 2. Redundant complement: each stored value is kept together with its bitwise
//    complement (policy Appendix 3, "redundant-checked values"). For types
//    where every bit pattern is a valid domain value (IPv4 addresses, salts),
//    this is what makes a later recheck meaningful at all.
// 3. Recheck on every get: `get_*` methods rerun the complement and domain
//    checks and return a distinct internal-invariant code (401..407).
// 4. Scope of the guard (best effort, documented honestly): it catches code
//    bugs that write wrong values and some memory corruption (e.g. a single
//    bit-flip). It does NOT defend against an attacker who can write process
//    memory (such an attacker can update both copies). The optimizer may
//    elide a recheck where it can prove the value is unchanged, which is
//    exactly where no software corruption path exists.
// 5. Key material (ValidationByte, SaltSet, KeySet, IdentityRecord): no
//    Debug, no Display, no PartialEq, no Copy. Secrets can never be formatted
//    into a log (not even in debug builds), are never compared with
//    non-constant-time `==`, and every copy is an explicit `.clone()`.
//    Known limitation: std offers no guaranteed zeroization, so copies of key
//    material on the stack are not wiped after use.

// Compile-time checks specific to Part 2. The salt-group split uses
// `first_chunk` / `last_chunk`, which is exact only if group 1 starts at 0 and
// group 2 ends at SALT_COUNT. Build error (never a runtime panic) otherwise.
const _: () = {
    assert!(SALT_GROUP_T1_START == 0);
    assert!(SALT_GROUP_T2_START + SALT_GROUP_SIZE == SALT_COUNT);
    assert!(IPV4_OCTET_COUNT == 4);
};

/// Validated, integrity-rechecked configuration types (Part 2).
///
/// This is an inner module inside the single flat file, so that struct
/// fields are private to THIS module. The rest of the tunnel can only create
/// values through the validating constructors and read them through
/// rechecking getters. (Without the inner module, every function in the file
/// could bypass the checks, because Rust privacy is per module.)
///
/// Visibility: items are `pub(super)`, i.e. visible to `pingpong_tunnel` and
/// its descendants (including the file's test module), not to `main.rs` or
/// to other crates.
mod validated_config_types {
    use super::{
        IDENTITY_NAME_MAX_BYTES, IPV4_OCTET_COUNT, IPV4_OCTET_MAX_DIGITS, MAX_PEER_TARGETS,
        SALT_COUNT, SALT_GROUP_SIZE, TunnelError,
    };
    use std::net::{Ipv4Addr, SocketAddrV4};

    // -------------------------------------------------------------------------
    // Port
    // -------------------------------------------------------------------------

    /// A validated UDP port number in 1..=65535, stored with its complement.
    ///
    /// Project context: used for the local bind endpoint (self) and for each
    /// peer's destination endpoint. Port 0 ("let the OS choose") is rejected:
    /// the tunnel's peers must know each other's fixed ports from the shared
    /// config.
    ///
    /// Stored as plain `u16` rather than `NonZeroU16` on purpose. With a niche
    /// type, the compiler may assume the value is non-zero and remove the
    /// recheck; plain `u16` keeps the recheck real.
    #[cfg_attr(any(test, debug_assertions), derive(Debug))]
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub(super) struct Port {
        /// The port number (1..=65535).
        port_number: u16,
        /// Bitwise complement of `port_number`, for integrity rechecks.
        port_number_complement: u16,
    }

    impl Port {
        /// Parses a decimal port from config text (e.g. the value of
        /// `alice_port`).
        ///
        /// Accepts 1..=65535 written with ASCII digits only. Rejected: empty
        /// text, leading zeros (e.g. `"08080"`, for unambiguous config),
        /// non-digits (including signs and spaces), zero, and > 65535.
        ///
        /// # Errors
        /// `ConfigInvalidPort` (100, input validation) for every rejection.
        pub(super) fn parse_port_decimal_text(port_text: &str) -> Result<Port, TunnelError> {
            let port_text_bytes: &[u8] = port_text.as_bytes();

            // --- Check: text is non-empty ---
            // Input validation: a blank config value is an expected user error.
            if port_text_bytes.is_empty() {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: parse_port_decimal_text: empty port text",
                    TunnelError::ConfigInvalidPort.code()
                );
                return Err(TunnelError::ConfigInvalidPort);
            }

            // --- Check: no leading zero ("0" alone is rejected below as zero) ---
            // Input validation: keeps config text unambiguous.
            if port_text_bytes.len() > 1 && port_text_bytes.first() == Some(&b'0') {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: parse_port_decimal_text: leading zero in {:?}",
                    TunnelError::ConfigInvalidPort.code(),
                    port_text
                );
                return Err(TunnelError::ConfigInvalidPort);
            }

            let mut accumulated_port_value: u32 = 0;
            // Bounded loop: one iteration per input byte. The range check
            // inside stops the loop by the 6th digit at the latest.
            for &port_text_byte in port_text_bytes.iter() {
                // --- Check: byte is an ASCII decimal digit ---
                let digit_value: u32 = match char::from(port_text_byte).to_digit(10) {
                    Some(digit) => digit,
                    None => {
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "PPT-{}: parse_port_decimal_text: non-digit in {:?}",
                            TunnelError::ConfigInvalidPort.code(),
                            port_text
                        );
                        return Err(TunnelError::ConfigInvalidPort);
                    }
                };
                accumulated_port_value = match accumulated_port_value
                    .checked_mul(10)
                    .and_then(|shifted_value| shifted_value.checked_add(digit_value))
                {
                    Some(next_value) => next_value,
                    None => {
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "PPT-{}: parse_port_decimal_text: overflow in {:?}",
                            TunnelError::ConfigInvalidPort.code(),
                            port_text
                        );
                        return Err(TunnelError::ConfigInvalidPort);
                    }
                };
                // --- Check: value stays within u16 (also bounds the arithmetic) ---
                if accumulated_port_value > u32::from(u16::MAX) {
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: parse_port_decimal_text: > 65535 in {:?}",
                        TunnelError::ConfigInvalidPort.code(),
                        port_text
                    );
                    return Err(TunnelError::ConfigInvalidPort);
                }
            }

            // Match-A-Function-Call: lossless after the range check above.
            let port_number: u16 = match u16::try_from(accumulated_port_value) {
                Ok(converted_port) => converted_port,
                Err(_range_detail) => {
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: parse_port_decimal_text: u16 conversion: {}",
                        TunnelError::ConfigInvalidPort.code(),
                        _range_detail
                    );
                    return Err(TunnelError::ConfigInvalidPort);
                }
            };

            // --- Check: port is non-zero ---
            if port_number == 0 {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: parse_port_decimal_text: port 0 not allowed",
                    TunnelError::ConfigInvalidPort.code()
                );
                return Err(TunnelError::ConfigInvalidPort);
            }

            Ok(Port {
                port_number,
                port_number_complement: !port_number,
            })
        }

        /// Rechecks this port's integrity: complement matches and value is
        /// non-zero.
        ///
        /// # Errors
        /// `InternalPortIntegrityCheckFailed` (401, internal invariant).
        pub(super) fn recheck_port_integrity(&self) -> Result<(), TunnelError> {
            let complement_matches: bool = self.port_number == !self.port_number_complement;
            let port_is_nonzero: bool = self.port_number != 0;
            let port_is_intact: bool = complement_matches && port_is_nonzero;

            // --- Check: stored port intact (internal invariant) ---
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                port_is_intact,
                "PPT-{}: recheck_port_integrity: complement_matches={} nonzero={}",
                TunnelError::InternalPortIntegrityCheckFailed.code(),
                complement_matches,
                port_is_nonzero
            );
            if !port_is_intact {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: recheck_port_integrity: complement_matches={} nonzero={}",
                    TunnelError::InternalPortIntegrityCheckFailed.code(),
                    complement_matches,
                    port_is_nonzero
                );
                return Err(TunnelError::InternalPortIntegrityCheckFailed);
            }
            Ok(())
        }

        /// Returns the port number after an integrity recheck.
        ///
        /// # Errors
        /// `InternalPortIntegrityCheckFailed` (401).
        pub(super) fn get_port_number(&self) -> Result<u16, TunnelError> {
            self.recheck_port_integrity()?;
            Ok(self.port_number)
        }
    }

    // -------------------------------------------------------------------------
    // Ipv4Address
    // -------------------------------------------------------------------------

    /// A validated IPv4 address parsed from strict dotted-quad text, stored
    /// with its complement.
    ///
    /// Project context: bind address (self) and destination address (peers).
    /// `0.0.0.0` is accepted (valid for binding to all local interfaces).
    /// Choosing sensible peer addresses is left to the user's config.
    ///
    /// Stored as the big-endian `u32` form (`127.0.0.1` == `0x7F00_0001`),
    /// matching `Ipv4Addr::from(u32)`.
    #[cfg_attr(any(test, debug_assertions), derive(Debug))]
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub(super) struct Ipv4Address {
        /// Address as a big-endian u32.
        ipv4_address_bits: u32,
        /// Bitwise complement of `ipv4_address_bits`, for integrity rechecks.
        ipv4_address_bits_complement: u32,
    }

    impl Ipv4Address {
        /// Parses strict dotted-quad IPv4 text, e.g. `"192.168.1.10"` (LHF-12).
        ///
        /// Rules: exactly 4 octets separated by single dots; each octet is 1
        /// to 3 ASCII digits, value 0..=255, and has no leading zero (`"0"`
        /// is fine, `"010"` is not). No whitespace, signs, or other bytes.
        /// The loop always fails by the 16th byte for over-long input
        /// (at most 4 octets of 3 digits plus 3 dots = 15 bytes).
        ///
        /// # Errors (all input validation)
        /// - `ConfigInvalidIp` (101): a byte other than a digit or '.'.
        /// - `ConfigIpv4OctetEmpty` (112): empty octet (`"1..2.3"`, `".1.2.3"`,
        ///   `"1.2.3."`, `""`).
        /// - `ConfigIpv4OctetLeadingZero` (113): e.g. `"010"`, `"00"`.
        /// - `ConfigIpv4OctetOutOfRange` (114): octet > 255 or > 3 digits.
        /// - `ConfigIpv4WrongOctetCount` (115): not exactly 4 octets.
        pub(super) fn parse_ipv4_dotted_quad(
            address_text: &str,
        ) -> Result<Ipv4Address, TunnelError> {
            let mut parsed_octets: [u8; IPV4_OCTET_COUNT] = [0u8; IPV4_OCTET_COUNT];
            let mut completed_octet_count: usize = 0;
            let mut current_octet_value: u32 = 0;
            let mut current_octet_digit_count: usize = 0;

            // Bounded loop: one iteration per input byte.
            for &address_byte in address_text.as_bytes().iter() {
                if address_byte == b'.' {
                    // --- Check: the octet before this dot is non-empty ---
                    if current_octet_digit_count == 0 {
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "PPT-{}: parse_ipv4_dotted_quad: empty octet in {:?}",
                            TunnelError::ConfigIpv4OctetEmpty.code(),
                            address_text
                        );
                        return Err(TunnelError::ConfigIpv4OctetEmpty);
                    }
                    // --- Check: there is room for this octet ---
                    let octet_slot: &mut u8 = match parsed_octets.get_mut(completed_octet_count) {
                        Some(slot) => slot,
                        None => {
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "PPT-{}: parse_ipv4_dotted_quad: too many octets in {:?}",
                                TunnelError::ConfigIpv4WrongOctetCount.code(),
                                address_text
                            );
                            return Err(TunnelError::ConfigIpv4WrongOctetCount);
                        }
                    };
                    // Match-A-Function-Call: lossless (value <= 255 checked per digit).
                    *octet_slot = match u8::try_from(current_octet_value) {
                        Ok(octet_value) => octet_value,
                        Err(_range_detail) => {
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "PPT-{}: parse_ipv4_dotted_quad: octet conversion: {}",
                                TunnelError::ConfigIpv4OctetOutOfRange.code(),
                                _range_detail
                            );
                            return Err(TunnelError::ConfigIpv4OctetOutOfRange);
                        }
                    };
                    completed_octet_count = match completed_octet_count.checked_add(1) {
                        Some(next_count) => next_count,
                        None => {
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "PPT-{}: parse_ipv4_dotted_quad: octet count overflow",
                                TunnelError::ConfigIpv4WrongOctetCount.code()
                            );
                            return Err(TunnelError::ConfigIpv4WrongOctetCount);
                        }
                    };
                    // --- Check: a dot after the 4th octet means too many octets ---
                    if completed_octet_count >= IPV4_OCTET_COUNT {
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "PPT-{}: parse_ipv4_dotted_quad: too many dots in {:?}",
                            TunnelError::ConfigIpv4WrongOctetCount.code(),
                            address_text
                        );
                        return Err(TunnelError::ConfigIpv4WrongOctetCount);
                    }
                    current_octet_value = 0;
                    current_octet_digit_count = 0;
                    continue;
                }

                // --- Check: byte is an ASCII decimal digit ---
                let digit_value: u32 = match char::from(address_byte).to_digit(10) {
                    Some(digit) => digit,
                    None => {
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "PPT-{}: parse_ipv4_dotted_quad: invalid char in {:?}",
                            TunnelError::ConfigInvalidIp.code(),
                            address_text
                        );
                        return Err(TunnelError::ConfigInvalidIp);
                    }
                };

                // --- Check: no leading zero ("0" alone is fine; "01"/"00" are not) ---
                if current_octet_digit_count == 1 && current_octet_value == 0 {
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: parse_ipv4_dotted_quad: leading zero in {:?}",
                        TunnelError::ConfigIpv4OctetLeadingZero.code(),
                        address_text
                    );
                    return Err(TunnelError::ConfigIpv4OctetLeadingZero);
                }

                // --- Check: at most IPV4_OCTET_MAX_DIGITS digits per octet ---
                if current_octet_digit_count >= IPV4_OCTET_MAX_DIGITS {
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: parse_ipv4_dotted_quad: octet too long in {:?}",
                        TunnelError::ConfigIpv4OctetOutOfRange.code(),
                        address_text
                    );
                    return Err(TunnelError::ConfigIpv4OctetOutOfRange);
                }

                current_octet_value = match current_octet_value
                    .checked_mul(10)
                    .and_then(|shifted_value| shifted_value.checked_add(digit_value))
                {
                    Some(next_value) => next_value,
                    None => {
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "PPT-{}: parse_ipv4_dotted_quad: octet arithmetic overflow",
                            TunnelError::ConfigIpv4OctetOutOfRange.code()
                        );
                        return Err(TunnelError::ConfigIpv4OctetOutOfRange);
                    }
                };

                // --- Check: octet value <= 255 ---
                if current_octet_value > u32::from(u8::MAX) {
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: parse_ipv4_dotted_quad: octet > 255 in {:?}",
                        TunnelError::ConfigIpv4OctetOutOfRange.code(),
                        address_text
                    );
                    return Err(TunnelError::ConfigIpv4OctetOutOfRange);
                }

                current_octet_digit_count = match current_octet_digit_count.checked_add(1) {
                    Some(next_count) => next_count,
                    None => {
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "PPT-{}: parse_ipv4_dotted_quad: digit count overflow",
                            TunnelError::ConfigIpv4OctetOutOfRange.code()
                        );
                        return Err(TunnelError::ConfigIpv4OctetOutOfRange);
                    }
                };
            }

            // --- Check: final octet is non-empty (catches "1.2.3." and "") ---
            if current_octet_digit_count == 0 {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: parse_ipv4_dotted_quad: empty final octet in {:?}",
                    TunnelError::ConfigIpv4OctetEmpty.code(),
                    address_text
                );
                return Err(TunnelError::ConfigIpv4OctetEmpty);
            }

            // Store the final octet; then require exactly IPV4_OCTET_COUNT octets.
            let final_octet_slot: &mut u8 = match parsed_octets.get_mut(completed_octet_count) {
                Some(slot) => slot,
                None => {
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: parse_ipv4_dotted_quad: no slot for final octet",
                        TunnelError::ConfigIpv4WrongOctetCount.code()
                    );
                    return Err(TunnelError::ConfigIpv4WrongOctetCount);
                }
            };
            *final_octet_slot = match u8::try_from(current_octet_value) {
                Ok(octet_value) => octet_value,
                Err(_range_detail) => {
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: parse_ipv4_dotted_quad: final octet conversion: {}",
                        TunnelError::ConfigIpv4OctetOutOfRange.code(),
                        _range_detail
                    );
                    return Err(TunnelError::ConfigIpv4OctetOutOfRange);
                }
            };
            let total_octet_count: usize = match completed_octet_count.checked_add(1) {
                Some(total) => total,
                None => {
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: parse_ipv4_dotted_quad: total count overflow",
                        TunnelError::ConfigIpv4WrongOctetCount.code()
                    );
                    return Err(TunnelError::ConfigIpv4WrongOctetCount);
                }
            };

            // --- Check: exactly IPV4_OCTET_COUNT octets ---
            if total_octet_count != IPV4_OCTET_COUNT {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: parse_ipv4_dotted_quad: {} octets in {:?}",
                    TunnelError::ConfigIpv4WrongOctetCount.code(),
                    total_octet_count,
                    address_text
                );
                return Err(TunnelError::ConfigIpv4WrongOctetCount);
            }

            let ipv4_address_bits: u32 = u32::from_be_bytes(parsed_octets);
            Ok(Ipv4Address {
                ipv4_address_bits,
                ipv4_address_bits_complement: !ipv4_address_bits,
            })
        }

        /// Rechecks this address's integrity (complement matches).
        ///
        /// # Errors
        /// `InternalIpv4IntegrityCheckFailed` (402, internal invariant).
        pub(super) fn recheck_ipv4_address_integrity(&self) -> Result<(), TunnelError> {
            let complement_matches: bool =
                self.ipv4_address_bits == !self.ipv4_address_bits_complement;

            // --- Check: stored address intact (internal invariant) ---
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                complement_matches,
                "PPT-{}: recheck_ipv4_address_integrity: complement mismatch",
                TunnelError::InternalIpv4IntegrityCheckFailed.code()
            );
            if !complement_matches {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: recheck_ipv4_address_integrity: complement mismatch",
                    TunnelError::InternalIpv4IntegrityCheckFailed.code()
                );
                return Err(TunnelError::InternalIpv4IntegrityCheckFailed);
            }
            Ok(())
        }

        /// Returns the address as `std::net::Ipv4Addr` after an integrity
        /// recheck.
        ///
        /// # Errors
        /// `InternalIpv4IntegrityCheckFailed` (402).
        pub(super) fn get_ipv4_addr(&self) -> Result<Ipv4Addr, TunnelError> {
            self.recheck_ipv4_address_integrity()?;
            Ok(Ipv4Addr::from(self.ipv4_address_bits))
        }
    }

    // -------------------------------------------------------------------------
    // IdentityName
    // -------------------------------------------------------------------------

    /// A validated identity name (e.g. `alice`, `bob_north`), stored in a
    /// fixed stack buffer with complements.
    ///
    /// Project context: identity names select records in the shared TOML
    /// config (`{name}_ip4`, `{name}_port`, `{name}_salt_N`, `{name}_val`).
    /// The allowed set is ASCII `[A-Za-z0-9_-]`, 1..=`IDENTITY_NAME_MAX_BYTES`
    /// bytes. This keeps every built key unambiguous for the line scanner:
    /// no '=', '#', quotes, or whitespace can appear inside a key.
    ///
    /// Invariant: bytes `[..len]` are allowed characters; bytes `[len..]` are
    /// zero.
    #[cfg_attr(any(test, debug_assertions), derive(Debug))]
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub(super) struct IdentityName {
        /// Name bytes; the first `identity_name_len` are the name, the rest 0.
        identity_name_bytes: [u8; IDENTITY_NAME_MAX_BYTES],
        /// Bytewise complement of `identity_name_bytes`.
        identity_name_bytes_complement: [u8; IDENTITY_NAME_MAX_BYTES],
        /// Name length in bytes (1..=IDENTITY_NAME_MAX_BYTES).
        identity_name_len: usize,
        /// Bitwise complement of `identity_name_len`.
        identity_name_len_complement: usize,
    }

    impl IdentityName {
        /// Validates and stores an identity name from CLI, prompt, or tests.
        ///
        /// # Errors (all input validation)
        /// - `ConfigIdentityNameEmpty` (116)
        /// - `ConfigIdentityNameTooLong` (118)
        /// - `ConfigIdentityNameInvalidChar` (117)
        pub(super) fn parse_identity_name(name_text: &str) -> Result<IdentityName, TunnelError> {
            let name_text_bytes: &[u8] = name_text.as_bytes();

            // --- Check: non-empty ---
            if name_text_bytes.is_empty() {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: parse_identity_name: empty name",
                    TunnelError::ConfigIdentityNameEmpty.code()
                );
                return Err(TunnelError::ConfigIdentityNameEmpty);
            }

            // --- Check: fits the fixed buffer ---
            if name_text_bytes.len() > IDENTITY_NAME_MAX_BYTES {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: parse_identity_name: {} bytes > max {}",
                    TunnelError::ConfigIdentityNameTooLong.code(),
                    name_text_bytes.len(),
                    IDENTITY_NAME_MAX_BYTES
                );
                return Err(TunnelError::ConfigIdentityNameTooLong);
            }

            // --- Check: every byte is in [A-Za-z0-9_-] ---
            let all_bytes_allowed: bool = name_text_bytes.iter().all(|name_byte| {
                name_byte.is_ascii_alphanumeric() || *name_byte == b'_' || *name_byte == b'-'
            });
            if !all_bytes_allowed {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: parse_identity_name: disallowed char in {:?}",
                    TunnelError::ConfigIdentityNameInvalidChar.code(),
                    name_text
                );
                return Err(TunnelError::ConfigIdentityNameInvalidChar);
            }

            let mut identity_name_bytes: [u8; IDENTITY_NAME_MAX_BYTES] =
                [0u8; IDENTITY_NAME_MAX_BYTES];
            // Bounded copy: zip stops at the shorter side (the name, <= max).
            for (destination_byte, source_byte) in
                identity_name_bytes.iter_mut().zip(name_text_bytes.iter())
            {
                *destination_byte = *source_byte;
            }

            let mut identity_name_bytes_complement: [u8; IDENTITY_NAME_MAX_BYTES] =
                [0u8; IDENTITY_NAME_MAX_BYTES];
            for (complement_byte, name_byte) in identity_name_bytes_complement
                .iter_mut()
                .zip(identity_name_bytes.iter())
            {
                *complement_byte = !*name_byte;
            }

            let identity_name_len: usize = name_text_bytes.len();
            Ok(IdentityName {
                identity_name_bytes,
                identity_name_bytes_complement,
                identity_name_len,
                identity_name_len_complement: !identity_name_len,
            })
        }

        /// Rechecks integrity: complements match, length in bounds, name bytes
        /// allowed, tail bytes zero.
        ///
        /// # Errors
        /// `InternalIdentityNameIntegrityCheckFailed` (403, internal invariant).
        pub(super) fn recheck_identity_name_integrity(&self) -> Result<(), TunnelError> {
            let length_complement_matches: bool =
                self.identity_name_len == !self.identity_name_len_complement;
            let bytes_complement_match: bool = self
                .identity_name_bytes
                .iter()
                .zip(self.identity_name_bytes_complement.iter())
                .all(|(name_byte, complement_byte)| *name_byte == !*complement_byte);
            let length_in_bounds: bool =
                self.identity_name_len >= 1 && self.identity_name_len <= IDENTITY_NAME_MAX_BYTES;
            let charset_and_padding_valid: bool =
                self.identity_name_bytes
                    .iter()
                    .enumerate()
                    .all(|(byte_index, name_byte)| {
                        if byte_index < self.identity_name_len {
                            name_byte.is_ascii_alphanumeric()
                                || *name_byte == b'_'
                                || *name_byte == b'-'
                        } else {
                            *name_byte == 0
                        }
                    });
            let name_is_intact: bool = length_complement_matches
                && bytes_complement_match
                && length_in_bounds
                && charset_and_padding_valid;

            // --- Check: stored name intact (internal invariant) ---
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                name_is_intact,
                "PPT-{}: recheck_identity_name_integrity: len_cmp={} bytes_cmp={} len_ok={} chars_ok={}",
                TunnelError::InternalIdentityNameIntegrityCheckFailed.code(),
                length_complement_matches,
                bytes_complement_match,
                length_in_bounds,
                charset_and_padding_valid
            );
            if !name_is_intact {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: recheck_identity_name_integrity: len_cmp={} bytes_cmp={} len_ok={} chars_ok={}",
                    TunnelError::InternalIdentityNameIntegrityCheckFailed.code(),
                    length_complement_matches,
                    bytes_complement_match,
                    length_in_bounds,
                    charset_and_padding_valid
                );
                return Err(TunnelError::InternalIdentityNameIntegrityCheckFailed);
            }
            Ok(())
        }

        /// Returns the name as `&str` after an integrity recheck. No heap: the
        /// returned slice borrows the internal fixed buffer.
        ///
        /// # Errors
        /// `InternalIdentityNameIntegrityCheckFailed` (403).
        pub(super) fn get_identity_name_str(&self) -> Result<&str, TunnelError> {
            self.recheck_identity_name_integrity()?;

            let name_slice: &[u8] = match self.identity_name_bytes.get(..self.identity_name_len) {
                Some(slice) => slice,
                None => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(
                        false,
                        "PPT-{}: get_identity_name_str: slice out of bounds",
                        TunnelError::InternalIdentityNameIntegrityCheckFailed.code()
                    );
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: get_identity_name_str: slice out of bounds",
                        TunnelError::InternalIdentityNameIntegrityCheckFailed.code()
                    );
                    return Err(TunnelError::InternalIdentityNameIntegrityCheckFailed);
                }
            };

            // Match-A-Function-Call (internal invariant: bytes are ASCII).
            match std::str::from_utf8(name_slice) {
                Ok(name_str) => Ok(name_str),
                Err(_utf8_detail) => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(
                        false,
                        "PPT-{}: get_identity_name_str: {}",
                        TunnelError::InternalIdentityNameIntegrityCheckFailed.code(),
                        _utf8_detail
                    );
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: get_identity_name_str: {}",
                        TunnelError::InternalIdentityNameIntegrityCheckFailed.code(),
                        _utf8_detail
                    );
                    Err(TunnelError::InternalIdentityNameIntegrityCheckFailed)
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // ValidationByte (key material)
    // -------------------------------------------------------------------------

    /// The recipient's validation byte (`{name}_val`), stored with its
    /// complement.
    ///
    /// Project context: the sender encrypts this byte as the final stream
    /// position (packet byte 62). The receiver decrypts byte 62 and compares
    /// it to its own validation byte (fail-fast step 6). Treated as key
    /// material: never printed, no Debug, no PartialEq.
    #[derive(Clone)]
    pub(super) struct ValidationByte {
        /// The validation byte value.
        validation_byte_value: u8,
        /// Bitwise complement of `validation_byte_value`.
        validation_byte_value_complement: u8,
    }

    impl ValidationByte {
        /// Builds a validation byte from an already-parsed config `u32`
        /// (LHF-10: values > 255 are rejected, never truncated).
        ///
        /// # Errors
        /// `ConfigValidationByteOutOfRange` (106, input validation).
        pub(super) fn from_config_value_u32(
            parsed_config_value: u32,
        ) -> Result<ValidationByte, TunnelError> {
            let validation_byte_value: u8 = match u8::try_from(parsed_config_value) {
                Ok(byte_value) => byte_value,
                Err(_range_detail) => {
                    // The value itself is NOT printed, even in debug: key material.
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: from_config_value_u32: value exceeds 255",
                        TunnelError::ConfigValidationByteOutOfRange.code()
                    );
                    return Err(TunnelError::ConfigValidationByteOutOfRange);
                }
            };
            Ok(ValidationByte {
                validation_byte_value,
                validation_byte_value_complement: !validation_byte_value,
            })
        }

        /// Rechecks integrity (complement matches).
        ///
        /// # Errors
        /// `InternalValidationByteIntegrityCheckFailed` (404, internal invariant).
        pub(super) fn recheck_validation_byte_integrity(&self) -> Result<(), TunnelError> {
            let complement_matches: bool =
                self.validation_byte_value == !self.validation_byte_value_complement;

            // --- Check: stored validation byte intact (internal invariant) ---
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                complement_matches,
                "PPT-{}: recheck_validation_byte_integrity: complement mismatch",
                TunnelError::InternalValidationByteIntegrityCheckFailed.code()
            );
            if !complement_matches {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: recheck_validation_byte_integrity: complement mismatch",
                    TunnelError::InternalValidationByteIntegrityCheckFailed.code()
                );
                return Err(TunnelError::InternalValidationByteIntegrityCheckFailed);
            }
            Ok(())
        }

        /// Returns the validation byte after an integrity recheck.
        ///
        /// # Errors
        /// `InternalValidationByteIntegrityCheckFailed` (404).
        pub(super) fn get_validation_byte_value(&self) -> Result<u8, TunnelError> {
            self.recheck_validation_byte_integrity()?;
            Ok(self.validation_byte_value)
        }
    }

    // -------------------------------------------------------------------------
    // SaltSet (key material)
    // -------------------------------------------------------------------------

    /// One identity's `SALT_COUNT` secret salts, stored with complements.
    ///
    /// Project context (LHF-2/LHF-3): salts are read only by the per-packet
    /// key schedule, split into two groups. `salts[0..8]` seed table T1 and
    /// `salts[8..16]` seed table T2. After table initialization, salts are
    /// never read again for that packet.
    ///
    /// Key material: no Debug, no Display, no PartialEq, no Copy. Salt values
    /// are never printed, even in debug builds.
    #[derive(Clone)]
    pub(super) struct SaltSet {
        /// The salts, in TOML order (`{name}_salt_1` is index 0).
        salt_values: [u32; SALT_COUNT],
        /// Element-wise bitwise complement of `salt_values`.
        salt_values_complement: [u32; SALT_COUNT],
    }

    impl SaltSet {
        /// Builds a salt set from already-parsed config values.
        ///
        /// Rejects an all-zero set (an unfilled template). This is not a
        /// key-strength test.
        ///
        /// # Errors
        /// `ConfigSaltSetAllZero` (122, input validation).
        pub(super) fn from_parsed_salt_values(
            parsed_salt_values: [u32; SALT_COUNT],
        ) -> Result<SaltSet, TunnelError> {
            // --- Check: not all zero ---
            if parsed_salt_values.iter().all(|salt_value| *salt_value == 0) {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: from_parsed_salt_values: all salts are zero",
                    TunnelError::ConfigSaltSetAllZero.code()
                );
                return Err(TunnelError::ConfigSaltSetAllZero);
            }

            let mut salt_values_complement: [u32; SALT_COUNT] = [0u32; SALT_COUNT];
            for (complement_value, salt_value) in salt_values_complement
                .iter_mut()
                .zip(parsed_salt_values.iter())
            {
                *complement_value = !*salt_value;
            }

            Ok(SaltSet {
                salt_values: parsed_salt_values,
                salt_values_complement,
            })
        }

        /// Rechecks integrity: all complements match and the set is not all
        /// zero.
        ///
        /// # Errors
        /// `InternalSaltSetIntegrityCheckFailed` (405, internal invariant).
        pub(super) fn recheck_salt_set_integrity(&self) -> Result<(), TunnelError> {
            let complements_match: bool = self
                .salt_values
                .iter()
                .zip(self.salt_values_complement.iter())
                .all(|(salt_value, complement_value)| *salt_value == !*complement_value);
            let not_all_zero: bool = self.salt_values.iter().any(|salt_value| *salt_value != 0);
            let salt_set_is_intact: bool = complements_match && not_all_zero;

            // --- Check: stored salts intact (internal invariant; values never printed) ---
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                salt_set_is_intact,
                "PPT-{}: recheck_salt_set_integrity: complements_match={} not_all_zero={}",
                TunnelError::InternalSaltSetIntegrityCheckFailed.code(),
                complements_match,
                not_all_zero
            );
            if !salt_set_is_intact {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: recheck_salt_set_integrity: complements_match={} not_all_zero={}",
                    TunnelError::InternalSaltSetIntegrityCheckFailed.code(),
                    complements_match,
                    not_all_zero
                );
                return Err(TunnelError::InternalSaltSetIntegrityCheckFailed);
            }
            Ok(())
        }

        /// Returns `(table_1_group, table_2_group)` after an integrity
        /// recheck: `salts[0..8]` for T1 and `salts[8..16]` for T2 (LHF-3).
        ///
        /// Called once per packet by the key schedule (Part 5), and nowhere
        /// else. The returned arrays are stack copies of key material.
        ///
        /// # Errors
        /// `InternalSaltSetIntegrityCheckFailed` (405).
        pub(super) fn get_salt_groups_per_table(
            &self,
        ) -> Result<([u32; SALT_GROUP_SIZE], [u32; SALT_GROUP_SIZE]), TunnelError> {
            self.recheck_salt_set_integrity()?;

            // Exact split guaranteed by the Part 2 compile-time checks.
            let table_1_salt_group: [u32; SALT_GROUP_SIZE] =
                match self.salt_values.first_chunk::<SALT_GROUP_SIZE>() {
                    Some(group) => *group,
                    None => {
                        #[cfg(all(debug_assertions, not(test)))]
                        debug_assert!(
                            false,
                            "PPT-{}: get_salt_groups_per_table: group 1 split failed",
                            TunnelError::InternalSaltSetIntegrityCheckFailed.code()
                        );
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "PPT-{}: get_salt_groups_per_table: group 1 split failed",
                            TunnelError::InternalSaltSetIntegrityCheckFailed.code()
                        );
                        return Err(TunnelError::InternalSaltSetIntegrityCheckFailed);
                    }
                };
            let table_2_salt_group: [u32; SALT_GROUP_SIZE] =
                match self.salt_values.last_chunk::<SALT_GROUP_SIZE>() {
                    Some(group) => *group,
                    None => {
                        #[cfg(all(debug_assertions, not(test)))]
                        debug_assert!(
                            false,
                            "PPT-{}: get_salt_groups_per_table: group 2 split failed",
                            TunnelError::InternalSaltSetIntegrityCheckFailed.code()
                        );
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "PPT-{}: get_salt_groups_per_table: group 2 split failed",
                            TunnelError::InternalSaltSetIntegrityCheckFailed.code()
                        );
                        return Err(TunnelError::InternalSaltSetIntegrityCheckFailed);
                    }
                };
            Ok((table_1_salt_group, table_2_salt_group))
        }
    }

    // -------------------------------------------------------------------------
    // Endpoint
    // -------------------------------------------------------------------------

    /// A validated IPv4 address + port pair.
    ///
    /// Project context: the self record's endpoint is the local bind address;
    /// each peer record's endpoint is that peer's destination.
    #[cfg_attr(any(test, debug_assertions), derive(Debug))]
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub(super) struct Endpoint {
        /// The validated IPv4 address.
        endpoint_ipv4_address: Ipv4Address,
        /// The validated port.
        endpoint_port: Port,
    }

    impl Endpoint {
        /// Combines validated parts, rechecking both.
        ///
        /// # Errors
        /// Propagates 402 or 401 unchanged (root-cause codes preserved).
        pub(super) fn from_validated_endpoint_parts(
            endpoint_ipv4_address: Ipv4Address,
            endpoint_port: Port,
        ) -> Result<Endpoint, TunnelError> {
            endpoint_ipv4_address.recheck_ipv4_address_integrity()?;
            endpoint_port.recheck_port_integrity()?;
            Ok(Endpoint {
                endpoint_ipv4_address,
                endpoint_port,
            })
        }

        /// Rechecks both components.
        ///
        /// # Errors
        /// Propagates 402 or 401 unchanged.
        pub(super) fn recheck_endpoint_integrity(&self) -> Result<(), TunnelError> {
            self.endpoint_ipv4_address
                .recheck_ipv4_address_integrity()?;
            self.endpoint_port.recheck_port_integrity()
        }

        /// Returns the endpoint as `std::net::SocketAddrV4` after rechecks.
        ///
        /// # Errors
        /// Propagates 402 or 401 unchanged.
        pub(super) fn get_socket_address_v4(&self) -> Result<SocketAddrV4, TunnelError> {
            let ipv4_addr: Ipv4Addr = self.endpoint_ipv4_address.get_ipv4_addr()?;
            let port_number: u16 = self.endpoint_port.get_port_number()?;
            Ok(SocketAddrV4::new(ipv4_addr, port_number))
        }
    }

    // -------------------------------------------------------------------------
    // KeySet (key material)
    // -------------------------------------------------------------------------

    /// One identity's complete key set: salts + validation byte.
    ///
    /// Project context (recipient-key model, LHF-21): a key set belongs to the
    /// RECIPIENT identity. Senders encrypt with the peer's key set; receivers
    /// decrypt with their own (self) key set.
    ///
    /// Key material: no Debug, no Display, no PartialEq, no Copy.
    #[derive(Clone)]
    pub(super) struct KeySet {
        /// The identity's salts.
        key_set_salt_set: SaltSet,
        /// The identity's validation byte.
        key_set_validation_byte: ValidationByte,
    }

    impl KeySet {
        /// Combines validated parts, rechecking both.
        ///
        /// # Errors
        /// Propagates 405 or 404 unchanged.
        pub(super) fn from_validated_key_parts(
            key_set_salt_set: SaltSet,
            key_set_validation_byte: ValidationByte,
        ) -> Result<KeySet, TunnelError> {
            key_set_salt_set.recheck_salt_set_integrity()?;
            key_set_validation_byte.recheck_validation_byte_integrity()?;
            Ok(KeySet {
                key_set_salt_set,
                key_set_validation_byte,
            })
        }

        /// Rechecks both components.
        ///
        /// # Errors
        /// Propagates 405 or 404 unchanged.
        pub(super) fn recheck_key_set_integrity(&self) -> Result<(), TunnelError> {
            self.key_set_salt_set.recheck_salt_set_integrity()?;
            self.key_set_validation_byte
                .recheck_validation_byte_integrity()
        }

        /// Returns `(table_1_group, table_2_group)` for the per-packet key
        /// schedule (Part 5). This is the ONLY path by which salts leave the
        /// key set.
        ///
        /// # Errors
        /// Propagates 405 unchanged.
        pub(super) fn get_key_schedule_salt_groups(
            &self,
        ) -> Result<([u32; SALT_GROUP_SIZE], [u32; SALT_GROUP_SIZE]), TunnelError> {
            self.key_set_salt_set.get_salt_groups_per_table()
        }

        /// Returns the validation byte. The sender encrypts it at stream
        /// position 54; the receiver compares the decrypted byte 62 to it.
        ///
        /// # Errors
        /// Propagates 404 unchanged.
        pub(super) fn get_expected_validation_byte(&self) -> Result<u8, TunnelError> {
            self.key_set_validation_byte.get_validation_byte_value()
        }
    }

    // -------------------------------------------------------------------------
    // IdentityRecord (contains key material)
    // -------------------------------------------------------------------------

    /// One complete config record for an identity: name, endpoint, key set.
    ///
    /// Project context: used for BOTH the self record (bind endpoint and the
    /// key set used to decrypt incoming packets) and every peer record
    /// (destination endpoint and the key set used to encrypt outgoing
    /// packets). Roles in the shared config are just roles; "local" is
    /// relative.
    ///
    /// Contains key material: no Debug, no PartialEq, no Copy.
    #[derive(Clone)]
    pub(super) struct IdentityRecord {
        /// The identity's validated name.
        record_identity_name: IdentityName,
        /// The identity's validated endpoint.
        record_endpoint: Endpoint,
        /// The identity's validated key set.
        record_key_set: KeySet,
    }

    impl IdentityRecord {
        /// Combines validated parts, rechecking all three.
        ///
        /// # Errors
        /// Propagates 403, 402, 401, 405, or 404 unchanged.
        pub(super) fn from_validated_record_parts(
            record_identity_name: IdentityName,
            record_endpoint: Endpoint,
            record_key_set: KeySet,
        ) -> Result<IdentityRecord, TunnelError> {
            record_identity_name.recheck_identity_name_integrity()?;
            record_endpoint.recheck_endpoint_integrity()?;
            record_key_set.recheck_key_set_integrity()?;
            Ok(IdentityRecord {
                record_identity_name,
                record_endpoint,
                record_key_set,
            })
        }

        /// Borrows the identity name. No value is extracted here; the name's
        /// own `get_identity_name_str` rechecks at the point of use.
        pub(super) fn borrow_record_identity_name(&self) -> &IdentityName {
            &self.record_identity_name
        }

        /// Borrows the endpoint. `get_socket_address_v4` rechecks at use.
        pub(super) fn borrow_record_endpoint(&self) -> &Endpoint {
            &self.record_endpoint
        }

        /// Borrows the key set. Its `get_*` methods recheck at use.
        pub(super) fn borrow_record_key_set(&self) -> &KeySet {
            &self.record_key_set
        }
    }

    // -------------------------------------------------------------------------
    // PeerRoster
    // -------------------------------------------------------------------------

    /// Fixed-capacity (no-heap) list of peer records, in configured order.
    ///
    /// Project context: the sender loop encrypts and sends each stdin line
    /// once per peer, in roster order. Startup requires at least one peer
    /// (LHF-1: no default keys, so no peers means nothing to send to).
    ///
    /// Invariant: `roster_peer_count <= MAX_PEER_TARGETS`; slots
    /// `[..count]` are `Some`, slots `[count..]` are `None`.
    pub(super) struct PeerRoster {
        /// Peer slots; occupied slots form a prefix.
        roster_peer_slots: [Option<IdentityRecord>; MAX_PEER_TARGETS],
        /// Number of occupied slots.
        roster_peer_count: usize,
    }

    impl PeerRoster {
        /// Creates an empty roster. Cannot fail.
        pub(super) fn create_empty_peer_roster() -> PeerRoster {
            PeerRoster {
                roster_peer_slots: [const { None }; MAX_PEER_TARGETS],
                roster_peer_count: 0,
            }
        }

        /// Rechecks the roster invariant (count in bounds; slots agree with
        /// count).
        ///
        /// # Errors
        /// `InternalPeerRosterIntegrityCheckFailed` (406, internal invariant).
        pub(super) fn recheck_peer_roster_integrity(&self) -> Result<(), TunnelError> {
            let count_in_bounds: bool = self.roster_peer_count <= MAX_PEER_TARGETS;
            let slots_agree_with_count: bool =
                self.roster_peer_slots
                    .iter()
                    .enumerate()
                    .all(|(slot_index, peer_slot)| {
                        (slot_index < self.roster_peer_count) == peer_slot.is_some()
                    });
            let roster_is_intact: bool = count_in_bounds && slots_agree_with_count;

            // --- Check: roster structure intact (internal invariant) ---
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                roster_is_intact,
                "PPT-{}: recheck_peer_roster_integrity: count={} in_bounds={} slots_agree={}",
                TunnelError::InternalPeerRosterIntegrityCheckFailed.code(),
                self.roster_peer_count,
                count_in_bounds,
                slots_agree_with_count
            );
            if !roster_is_intact {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: recheck_peer_roster_integrity: count={} in_bounds={} slots_agree={}",
                    TunnelError::InternalPeerRosterIntegrityCheckFailed.code(),
                    self.roster_peer_count,
                    count_in_bounds,
                    slots_agree_with_count
                );
                return Err(TunnelError::InternalPeerRosterIntegrityCheckFailed);
            }
            Ok(())
        }

        /// Appends a peer record in the next free slot.
        ///
        /// # Errors
        /// - Propagates 406 (roster recheck).
        /// - `InternalPeerRosterFull` (407, internal invariant): callers bound
        ///   their loops by `MAX_PEER_TARGETS`, and the CLI rejects extra
        ///   peers with 162.
        pub(super) fn append_peer_record(
            &mut self,
            peer_record: IdentityRecord,
        ) -> Result<(), TunnelError> {
            self.recheck_peer_roster_integrity()?;

            let next_peer_count: usize = match self.roster_peer_count.checked_add(1) {
                Some(next_count) => next_count,
                None => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(
                        false,
                        "PPT-{}: append_peer_record: count overflow",
                        TunnelError::InternalPeerRosterFull.code()
                    );
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "PPT-{}: append_peer_record: count overflow",
                        TunnelError::InternalPeerRosterFull.code()
                    );
                    return Err(TunnelError::InternalPeerRosterFull);
                }
            };

            // --- Check: a free slot exists (internal invariant) ---
            let next_free_slot: &mut Option<IdentityRecord> =
                match self.roster_peer_slots.get_mut(self.roster_peer_count) {
                    Some(free_slot) => free_slot,
                    None => {
                        #[cfg(all(debug_assertions, not(test)))]
                        debug_assert!(
                            false,
                            "PPT-{}: append_peer_record: roster full",
                            TunnelError::InternalPeerRosterFull.code()
                        );
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "PPT-{}: append_peer_record: roster full",
                            TunnelError::InternalPeerRosterFull.code()
                        );
                        return Err(TunnelError::InternalPeerRosterFull);
                    }
                };
            *next_free_slot = Some(peer_record);
            self.roster_peer_count = next_peer_count;
            Ok(())
        }

        /// Returns the number of peers after a roster recheck.
        ///
        /// # Errors
        /// Propagates 406.
        pub(super) fn get_peer_count(&self) -> Result<usize, TunnelError> {
            self.recheck_peer_roster_integrity()?;
            Ok(self.roster_peer_count)
        }

        /// Fails closed if no peers are configured (LHF-1).
        ///
        /// # Errors
        /// - Propagates 406.
        /// - `ConfigNoPeersConfigured` (105, input validation).
        pub(super) fn require_at_least_one_peer_configured(&self) -> Result<(), TunnelError> {
            self.recheck_peer_roster_integrity()?;
            // --- Check: at least one peer ---
            if self.roster_peer_count == 0 {
                #[cfg(debug_assertions)]
                eprintln!(
                    "PPT-{}: require_at_least_one_peer_configured: no peers",
                    TunnelError::ConfigNoPeersConfigured.code()
                );
                return Err(TunnelError::ConfigNoPeersConfigured);
            }
            Ok(())
        }

        /// Returns an iterator over configured peer records, in order, after a
        /// roster recheck. The iteration is bounded by `MAX_PEER_TARGETS`
        /// slots.
        ///
        /// # Errors
        /// Propagates 406.
        pub(super) fn iterate_peer_records(
            &self,
        ) -> Result<impl Iterator<Item = &IdentityRecord>, TunnelError> {
            self.recheck_peer_roster_integrity()?;
            Ok(self.roster_peer_slots.iter().flatten())
        }
    }

    // -------------------------------------------------------------------------
    // Corruption tests (TEST MODE ONLY)
    // -------------------------------------------------------------------------
    // These tests construct invalid values DIRECTLY through private fields to
    // simulate post-construction corruption (e.g. a bit-flip). They must live
    // inside this inner module, because only this module and its descendants
    // can access the private fields. All other Part 2 tests (public
    // constructors) live in the file-end `pingpong_tunnel_tests` module.
    // No test-only constructors are added to the API (policy).
    #[cfg(test)]
    #[allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    mod validated_config_types_tests {
        use super::*;

        /// TEST FIXTURE ONLY: distinct non-zero salts. Never a default key.
        const FIXTURE_SALT_VALUES_FOR_TESTS: [u32; SALT_COUNT] = [
            0x1A2B_3C4D,
            0x5E6F_7081,
            0x92A3_B4C5,
            0xD6E7_F809,
            0x1B2C_3D4E,
            0x5F60_7182,
            0x93A4_B5C6,
            0xD7E8_F90A,
            0x1C2D_3E4F,
            0x6061_7283,
            0x94A5_B6C7,
            0xD8E9_FA0B,
            0x1D2E_3F50,
            0x6162_7384,
            0x95A6_B7C8,
            0xD9EA_FB0C,
        ];

        /// TEST FIXTURE ONLY: a valid record for roster tests.
        fn build_valid_record_for_inner_tests() -> IdentityRecord {
            let identity_name = IdentityName::parse_identity_name("fixture_peer").unwrap();
            let endpoint = Endpoint::from_validated_endpoint_parts(
                Ipv4Address::parse_ipv4_dotted_quad("127.0.0.1").unwrap(),
                Port::parse_port_decimal_text("40001").unwrap(),
            )
            .unwrap();
            let key_set = KeySet::from_validated_key_parts(
                SaltSet::from_parsed_salt_values(FIXTURE_SALT_VALUES_FOR_TESTS).unwrap(),
                ValidationByte::from_config_value_u32(0x5A).unwrap(),
            )
            .unwrap();
            IdentityRecord::from_validated_record_parts(identity_name, endpoint, key_set).unwrap()
        }

        #[test]
        fn ppt_get_port_number_detects_complement_mismatch_with_code_401() {
            let corrupt_port = Port {
                port_number: 8080,
                port_number_complement: 0,
            };
            let error = corrupt_port.get_port_number().unwrap_err();
            assert_eq!(error, TunnelError::InternalPortIntegrityCheckFailed);
            assert_eq!(error.code(), 401);
        }

        #[test]
        fn ppt_get_port_number_detects_zero_with_code_401() {
            let corrupt_port = Port {
                port_number: 0,
                port_number_complement: !0u16,
            };
            let error = corrupt_port.get_port_number().unwrap_err();
            assert_eq!(error, TunnelError::InternalPortIntegrityCheckFailed);
        }

        #[test]
        fn ppt_get_ipv4_addr_detects_single_bit_flip_with_code_402() {
            let valid = Ipv4Address::parse_ipv4_dotted_quad("10.0.0.1").unwrap();
            let corrupt = Ipv4Address {
                ipv4_address_bits: valid.ipv4_address_bits ^ 0x0000_0100, // one bit flipped
                ipv4_address_bits_complement: valid.ipv4_address_bits_complement,
            };
            let error = corrupt.get_ipv4_addr().unwrap_err();
            assert_eq!(error, TunnelError::InternalIpv4IntegrityCheckFailed);
            assert_eq!(error.code(), 402);
        }

        #[test]
        fn ppt_get_identity_name_str_detects_corrupt_length_with_code_403() {
            let valid = IdentityName::parse_identity_name("alice").unwrap();
            let corrupt = IdentityName {
                identity_name_len: 99,
                identity_name_len_complement: !99usize,
                ..valid
            };
            let error = corrupt.get_identity_name_str().unwrap_err();
            assert_eq!(error, TunnelError::InternalIdentityNameIntegrityCheckFailed);
            assert_eq!(error.code(), 403);
        }

        #[test]
        fn ppt_get_identity_name_str_detects_nonzero_tail_with_code_403() {
            let valid = IdentityName::parse_identity_name("bob").unwrap();
            let mut corrupt = valid;
            corrupt.identity_name_bytes[10] = b'x';
            corrupt.identity_name_bytes_complement[10] = !b'x'; // complement "consistent"
            let error = corrupt.get_identity_name_str().unwrap_err();
            assert_eq!(error, TunnelError::InternalIdentityNameIntegrityCheckFailed);
        }

        #[test]
        fn ppt_get_validation_byte_value_detects_mismatch_with_code_404() {
            let corrupt = ValidationByte {
                validation_byte_value: 0x44,
                validation_byte_value_complement: 0x00,
            };
            let error = corrupt.get_validation_byte_value().unwrap_err();
            assert_eq!(
                error,
                TunnelError::InternalValidationByteIntegrityCheckFailed
            );
            assert_eq!(error.code(), 404);
        }

        #[test]
        fn ppt_get_salt_groups_per_table_detects_flip_with_code_405() {
            let mut corrupt =
                SaltSet::from_parsed_salt_values(FIXTURE_SALT_VALUES_FOR_TESTS).unwrap();
            corrupt.salt_values[7] ^= 0x8000_0000; // one bit flipped
            let error = corrupt.get_salt_groups_per_table().unwrap_err();
            assert_eq!(error, TunnelError::InternalSaltSetIntegrityCheckFailed);
            assert_eq!(error.code(), 405);
        }

        #[test]
        fn ppt_get_salt_groups_per_table_detects_all_zero_with_code_405() {
            let corrupt = SaltSet {
                salt_values: [0u32; SALT_COUNT],
                salt_values_complement: [!0u32; SALT_COUNT],
            };
            let error = corrupt.get_salt_groups_per_table().unwrap_err();
            assert_eq!(error, TunnelError::InternalSaltSetIntegrityCheckFailed);
        }

        #[test]
        fn ppt_get_peer_count_detects_count_over_max_with_code_406() {
            let mut corrupt = PeerRoster::create_empty_peer_roster();
            corrupt.roster_peer_count = MAX_PEER_TARGETS + 1;
            let error = corrupt.get_peer_count().unwrap_err();
            assert_eq!(error, TunnelError::InternalPeerRosterIntegrityCheckFailed);
            assert_eq!(error.code(), 406);
        }

        #[test]
        fn ppt_get_peer_count_detects_count_slot_disagreement_with_code_406() {
            let mut corrupt = PeerRoster::create_empty_peer_roster();
            corrupt.roster_peer_count = 1; // but slot 0 is None
            let error = corrupt.get_peer_count().unwrap_err();
            assert_eq!(error, TunnelError::InternalPeerRosterIntegrityCheckFailed);
        }

        #[test]
        fn ppt_append_peer_record_rejects_full_roster_with_code_407() {
            let mut roster = PeerRoster::create_empty_peer_roster();
            for _ in 0..MAX_PEER_TARGETS {
                roster
                    .append_peer_record(build_valid_record_for_inner_tests())
                    .unwrap();
            }
            let error = roster
                .append_peer_record(build_valid_record_for_inner_tests())
                .unwrap_err();
            assert_eq!(error, TunnelError::InternalPeerRosterFull);
            assert_eq!(error.code(), 407);
            assert_eq!(roster.get_peer_count().unwrap(), MAX_PEER_TARGETS);
        }
    }
}

// Bring the Part 2 types into the main module namespace for Parts 3-10.
use validated_config_types::{
    Endpoint, IdentityName, IdentityRecord, Ipv4Address, KeySet, PeerRoster, Port, SaltSet,
    ValidationByte,
};
