// Enable strict production lints
#![cfg_attr(not(debug_assertions), forbid(unsafe_code))]
#![cfg_attr(not(debug_assertions), deny(clippy::alloc_instead_of_core))]
#![cfg_attr(not(debug_assertions), deny(clippy::string_slice))]
#![cfg_attr(not(debug_assertions), deny(clippy::vec_collect))]

use std::{
    fs::File,
    io::{Read, Write, stdin, stdout},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// --- Global Constants ---
const MAX_TARGETS: usize = 4;
const PACKET_SIZE: usize = 64;
const PAYLOAD_SIZE: usize = 54;
pub const RSLSF_MAX_BYTES_SCANNED: u64 = 1 << 20;

// Default fall-back 512-bit Secret Key Array if TOML is omitted
const DEFAULT_SALTS: [u32; 16] = [
    0x0F1E_2D3C,
    0x4B5A_6978,
    0x8796_A5B4,
    0xC3D2_E1F0,
    0x1234_5678,
    0x9ABC_DEF0,
    0xFEDC_BA98,
    0x7654_3210,
    0x0011_2233,
    0x4455_6677,
    0x8899_AABB,
    0xCCDD_EEFF,
    0xA1B2_C3D4,
    0xE5F6_0718,
    0x2938_4756,
    0x6172_8394,
];
const DEFAULT_VAL_BYTE: u8 = 0x44;

// --- Unified Project Error Enum ---
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TunnelError {
    // Socket / OS Errors (1..99)
    SocketBindFailed = 1,
    SocketReadFailed = 3,
    SocketWriteFailed = 4,

    // UDP Frame Integrity Errors (10..29)
    UdpPacketTruncated = 10,
    UdpTimestampStale = 11,
    UdpReplayDetected = 12,

    // Config & CLI Errors (100..129)
    ConfigInvalidPort = 100,
    ConfigInvalidIp = 101,
    ConfigInvalidArgs = 102,
    ConfigInvalidToml = 103,
    ConfigExePathFailed = 104,

    // TOML Scanner Specific Codes (130..150)
    TomlEmptyKey = 130,
    TomlOutputBufferZeroSized = 131,
    TomlFileOpenFailed = 132,
    TomlFileReadFailed = 133,
    TomlFieldNotFound = 134,
    TomlValueExceedsOutputBuffer = 135,
    TomlValueUnterminatedAtEof = 136,
    TomlSafetyBudgetExhausted = 137,

    // Cryptographic Errors (200..299)
    CryptoByte63Failed = 200,
    CryptoByte62Failed = 201,
    CryptoInvalidAscii = 202,

    // Threading (300..399)
    InternalThreadSpawnFailed = 300,
}

impl TunnelError {
    #[inline]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            TunnelError::SocketReadFailed | TunnelError::SocketWriteFailed
        )
    }
}

#[cfg(debug_assertions)]
impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::SocketBindFailed => write!(f, "Failed to bind UDP socket"),
            TunnelError::SocketReadFailed => write!(f, "Failed to receive from UDP socket"),
            TunnelError::SocketWriteFailed => write!(f, "Failed to transmit via UDP socket"),
            TunnelError::UdpPacketTruncated => write!(f, "Datagram size != 64 bytes"),
            TunnelError::UdpTimestampStale => write!(f, "Packet timestamp outside 30s window"),
            TunnelError::UdpReplayDetected => write!(f, "Replay attack detected (duplicate nonce)"),
            TunnelError::ConfigInvalidPort => write!(f, "Invalid port number"),
            TunnelError::ConfigInvalidIp => write!(f, "Invalid IPv4 address"),
            TunnelError::ConfigInvalidArgs => write!(f, "Invalid CLI arguments"),
            TunnelError::ConfigInvalidToml => write!(f, "Malformed configuration TOML file"),
            TunnelError::ConfigExePathFailed => write!(f, "Failed to resolve executable directory"),
            TunnelError::TomlEmptyKey => write!(f, "TOML Scanner: target key was empty"),
            TunnelError::TomlOutputBufferZeroSized => {
                write!(f, "TOML Scanner: output buffer size is 0")
            }
            TunnelError::TomlFileOpenFailed => {
                write!(f, "TOML Scanner: failed to open config file")
            }
            TunnelError::TomlFileReadFailed => {
                write!(f, "TOML Scanner: I/O error while reading file")
            }
            TunnelError::TomlFieldNotFound => write!(f, "TOML Scanner: requested key not found"),
            TunnelError::TomlValueExceedsOutputBuffer => {
                write!(f, "TOML Scanner: value exceeds stack buffer")
            }
            TunnelError::TomlValueUnterminatedAtEof => {
                write!(f, "TOML Scanner: unterminated value at EOF")
            }
            TunnelError::TomlSafetyBudgetExhausted => {
                write!(f, "TOML Scanner: read budget exhausted")
            }
            TunnelError::CryptoByte63Failed => write!(f, "Static sender validation byte mismatch"),
            TunnelError::CryptoByte62Failed => write!(f, "Dynamic payload checksum mismatch"),
            TunnelError::CryptoInvalidAscii => {
                write!(f, "Decrypted payload contains non-ASCII byte")
            }
            TunnelError::InternalThreadSpawnFailed => {
                write!(f, "Failed to spawn background thread")
            }
        }
    }
}

// --- Custom Strict Types ---
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Port(u16);

impl Port {
    pub fn from_str(s: &str) -> Result<Self, TunnelError> {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return Err(TunnelError::ConfigInvalidPort);
        }
        let mut val = 0u32;
        let mut i = 0usize;
        while i < bytes.len() {
            let b = bytes[i];
            if !(b'0'..=b'9').contains(&b) {
                return Err(TunnelError::ConfigInvalidPort);
            }
            val = match val.checked_mul(10) {
                Some(v) => v,
                None => return Err(TunnelError::ConfigInvalidPort),
            };
            val = match val.checked_add((b - b'0') as u32) {
                Some(v) => v,
                None => return Err(TunnelError::ConfigInvalidPort),
            };
            if val > 65535 {
                return Err(TunnelError::ConfigInvalidPort);
            }
            i = match i.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
        if val == 0 {
            Err(TunnelError::ConfigInvalidPort)
        } else {
            Ok(Self(val as u16))
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Ipv4(Ipv4Addr);

impl Ipv4 {
    pub const fn _from_octets(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(Ipv4Addr::new(a, b, c, d))
    }

    pub fn from_str(s: &str) -> Result<Self, TunnelError> {
        let mut octets = [0u8; 4];
        let mut current = 0u16;
        let mut octet_index = 0usize;
        let bytes = s.as_bytes();
        let mut i = 0usize;

        while i < bytes.len() {
            let b = bytes[i];
            if (b'0'..=b'9').contains(&b) {
                let mul_res = match current.checked_mul(10) {
                    Some(v) => v,
                    None => return Err(TunnelError::ConfigInvalidIp),
                };
                let add_res = match mul_res.checked_add((b - b'0') as u16) {
                    Some(v) => v,
                    None => return Err(TunnelError::ConfigInvalidIp),
                };
                current = add_res;
                if current > 255 {
                    return Err(TunnelError::ConfigInvalidIp);
                }
            } else if b == b'.' {
                octets[octet_index] = current as u8;
                octet_index = match octet_index.checked_add(1) {
                    Some(v) => v,
                    None => return Err(TunnelError::ConfigInvalidIp),
                };
                current = 0;
                if octet_index >= 4 {
                    return Err(TunnelError::ConfigInvalidIp);
                }
            } else {
                return Err(TunnelError::ConfigInvalidIp);
            }
            i = match i.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }

        octets[octet_index] = current as u8;
        if octet_index != 3 {
            return Err(TunnelError::ConfigInvalidIp);
        }

        Ok(Self(Ipv4Addr::from(octets)))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Endpoint {
    ip: Ipv4,
    port: Port,
}

#[derive(Copy, Clone, Debug)]
struct ConfigKeys {
    salts: [u32; 16],
    val_byte: u8,
}

#[derive(Copy, Clone, Debug)]
struct PeerTarget {
    endpoint: Endpoint,
    keys: ConfigKeys,
}

// --- Zero-Heap Stack Replay Filter Ring Buffer ---
struct ReplayFilter {
    history: [(u32, u32); 32],
    head: usize,
}

impl ReplayFilter {
    pub const fn new() -> Self {
        Self {
            history: [(0, 0); 32],
            head: 0,
        }
    }

    pub fn is_replayed_or_insert(&mut self, timestamp: u32, nonce: u32) -> bool {
        let mut i = 0usize;
        while i < 32 {
            if self.history[i] == (timestamp, nonce) {
                return true;
            }
            i = match i.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
        self.history[self.head] = (timestamp, nonce);
        self.head = (self.head + 1) % 32;
        false
    }
}

// --- Zero-Heap Stack TOML Scanner Module ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineScanState {
    AtLineStart,
    SkippingLeadingWhitespace,
    MatchingKey { matched_key_bytes: usize },
    AwaitingEquals,
    AwaitingValueStart,
    CopyingUnquotedValue,
    CopyingQuotedValue,
    SkippingToEndOfLine,
    InCommentToEndOfLine,
}

#[inline]
fn is_ascii_space_or_tab_byte(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

pub fn read_single_line_string_field_from_toml_no_heap<const OUTPUT_BUFFER_BYTES: usize>(
    absolute_toml_file_path: &str,
    target_field_key: &str,
) -> Result<([u8; OUTPUT_BUFFER_BYTES], usize), TunnelError> {
    if OUTPUT_BUFFER_BYTES == 0 {
        return Err(TunnelError::TomlOutputBufferZeroSized);
    }
    if target_field_key.is_empty() {
        return Err(TunnelError::TomlEmptyKey);
    }

    let mut open_file_handle = match File::open(absolute_toml_file_path) {
        Ok(handle) => handle,
        Err(_) => return Err(TunnelError::TomlFileOpenFailed),
    };

    let key_bytes: &[u8] = target_field_key.as_bytes();
    let mut single_byte_scratch: [u8; 1] = [0u8; 1];
    let mut output_buffer: [u8; OUTPUT_BUFFER_BYTES] = [0u8; OUTPUT_BUFFER_BYTES];
    let mut output_write_cursor: usize = 0;

    let mut current_state: LineScanState = LineScanState::AtLineStart;
    let mut unquoted_has_pending_cr: bool = false;
    let mut cumulative_bytes_scanned: u64 = 0;
    let mut safety_iteration_count: u64 = 0;
    let safety_iteration_limit: u64 = RSLSF_MAX_BYTES_SCANNED + 16;

    loop {
        safety_iteration_count = safety_iteration_count.saturating_add(1);
        if safety_iteration_count > safety_iteration_limit {
            return Err(TunnelError::TomlSafetyBudgetExhausted);
        }

        let bytes_read = match open_file_handle.read(&mut single_byte_scratch) {
            Ok(count) => count,
            Err(_) => return Err(TunnelError::TomlFileReadFailed),
        };

        if bytes_read == 0 {
            match current_state {
                LineScanState::CopyingUnquotedValue
                | LineScanState::CopyingQuotedValue
                | LineScanState::AwaitingValueStart => {
                    return Err(TunnelError::TomlValueUnterminatedAtEof);
                }
                _ => return Err(TunnelError::TomlFieldNotFound),
            }
        }

        cumulative_bytes_scanned = cumulative_bytes_scanned.saturating_add(1);
        if cumulative_bytes_scanned > RSLSF_MAX_BYTES_SCANNED {
            return Err(TunnelError::TomlSafetyBudgetExhausted);
        }

        let current_byte: u8 = single_byte_scratch[0];

        match current_state {
            LineScanState::AtLineStart | LineScanState::SkippingLeadingWhitespace => {
                if current_byte == b'\n' {
                    current_state = LineScanState::AtLineStart;
                } else if current_byte == b'\r' {
                } else if is_ascii_space_or_tab_byte(current_byte) {
                    current_state = LineScanState::SkippingLeadingWhitespace;
                } else if current_byte == b'#' {
                    current_state = LineScanState::InCommentToEndOfLine;
                } else {
                    if current_byte == key_bytes[0] {
                        if key_bytes.len() == 1 {
                            current_state = LineScanState::AwaitingEquals;
                        } else {
                            current_state = LineScanState::MatchingKey {
                                matched_key_bytes: 1,
                            };
                        }
                    } else {
                        current_state = LineScanState::SkippingToEndOfLine;
                    }
                }
            }
            LineScanState::MatchingKey { matched_key_bytes } => {
                if matched_key_bytes < key_bytes.len() {
                    if current_byte == key_bytes[matched_key_bytes] {
                        let next_matched = matched_key_bytes + 1;
                        if next_matched == key_bytes.len() {
                            current_state = LineScanState::AwaitingEquals;
                        } else {
                            current_state = LineScanState::MatchingKey {
                                matched_key_bytes: next_matched,
                            };
                        }
                    } else if current_byte == b'\n' {
                        current_state = LineScanState::AtLineStart;
                    } else {
                        current_state = LineScanState::SkippingToEndOfLine;
                    }
                } else {
                    current_state = LineScanState::SkippingToEndOfLine;
                }
            }
            LineScanState::AwaitingEquals => {
                if is_ascii_space_or_tab_byte(current_byte) {
                } else if current_byte == b'=' {
                    current_state = LineScanState::AwaitingValueStart;
                } else if current_byte == b'\n' {
                    current_state = LineScanState::AtLineStart;
                } else {
                    current_state = LineScanState::SkippingToEndOfLine;
                }
            }
            LineScanState::AwaitingValueStart => {
                if is_ascii_space_or_tab_byte(current_byte) {
                } else if current_byte == b'"' {
                    current_state = LineScanState::CopyingQuotedValue;
                } else if current_byte == b'\n' {
                    return Ok((output_buffer, 0));
                } else if current_byte == b'\r' {
                    unquoted_has_pending_cr = true;
                    current_state = LineScanState::CopyingUnquotedValue;
                } else {
                    if output_write_cursor >= OUTPUT_BUFFER_BYTES {
                        return Err(TunnelError::TomlValueExceedsOutputBuffer);
                    }
                    output_buffer[output_write_cursor] = current_byte;
                    output_write_cursor += 1;
                    current_state = LineScanState::CopyingUnquotedValue;
                }
            }
            LineScanState::CopyingUnquotedValue => {
                if current_byte == b'\n' {
                    return Ok((output_buffer, output_write_cursor));
                } else if current_byte == b'\r' {
                    if unquoted_has_pending_cr {
                        if output_write_cursor >= OUTPUT_BUFFER_BYTES {
                            return Err(TunnelError::TomlValueExceedsOutputBuffer);
                        }
                        output_buffer[output_write_cursor] = b'\r';
                        output_write_cursor += 1;
                    }
                    unquoted_has_pending_cr = true;
                } else {
                    if unquoted_has_pending_cr {
                        if output_write_cursor >= OUTPUT_BUFFER_BYTES {
                            return Err(TunnelError::TomlValueExceedsOutputBuffer);
                        }
                        output_buffer[output_write_cursor] = b'\r';
                        output_write_cursor += 1;
                        unquoted_has_pending_cr = false;
                    }
                    if output_write_cursor >= OUTPUT_BUFFER_BYTES {
                        return Err(TunnelError::TomlValueExceedsOutputBuffer);
                    }
                    output_buffer[output_write_cursor] = current_byte;
                    output_write_cursor += 1;
                }
            }
            LineScanState::CopyingQuotedValue => {
                if current_byte == b'"' {
                    return Ok((output_buffer, output_write_cursor));
                } else {
                    if output_write_cursor >= OUTPUT_BUFFER_BYTES {
                        return Err(TunnelError::TomlValueExceedsOutputBuffer);
                    }
                    output_buffer[output_write_cursor] = current_byte;
                    output_write_cursor += 1;
                }
            }
            LineScanState::SkippingToEndOfLine | LineScanState::InCommentToEndOfLine => {
                if current_byte == b'\n' {
                    current_state = LineScanState::AtLineStart;
                }
            }
        }
    }
}

// --- Executable Directory Resolution ---
fn get_executable_directory_config_path(buf: &mut [u8; 256]) -> Result<&str, TunnelError> {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let p_cow = parent.to_string_lossy();
            let p_bytes = p_cow.as_bytes();
            let file_name = b"/tunnel.toml";
            let total_len = p_bytes.len() + file_name.len();
            if total_len <= buf.len() {
                buf[..p_bytes.len()].copy_from_slice(p_bytes);
                buf[p_bytes.len()..total_len].copy_from_slice(file_name);
                if let Ok(s) = std::str::from_utf8(&buf[..total_len]) {
                    return Ok(s);
                }
            }
        }
    }
    Err(TunnelError::ConfigExePathFailed)
}

// --- Zero-Heap Key Formatting & Parsers ---
fn build_toml_key<'a>(
    name: &str,
    suffix: &str,
    buf: &'a mut [u8; 64],
) -> Result<&'a str, TunnelError> {
    let nb = name.as_bytes();
    let sb = suffix.as_bytes();
    let total = nb.len() + 1 + sb.len();
    if total > 64 {
        return Err(TunnelError::ConfigInvalidToml);
    }
    let mut cursor = 0usize;
    let mut i = 0usize;
    while i < nb.len() {
        buf[cursor] = nb[i];
        cursor += 1;
        i += 1;
    }
    buf[cursor] = b'_';
    cursor += 1;
    i = 0;
    while i < sb.len() {
        buf[cursor] = sb[i];
        cursor += 1;
        i += 1;
    }
    match std::str::from_utf8(&buf[..cursor]) {
        Ok(s) => Ok(s),
        Err(_) => Err(TunnelError::ConfigInvalidToml),
    }
}

fn build_salt_suffix<'a>(index: usize, buf: &'a mut [u8; 16]) -> Result<&'a str, TunnelError> {
    buf[0] = b's';
    buf[1] = b'a';
    buf[2] = b'l';
    buf[3] = b't';
    buf[4] = b'_';
    let mut cursor = 5usize;
    if index >= 10 {
        buf[cursor] = b'1';
        cursor += 1;
        buf[cursor] = b'0' + (index % 10) as u8;
        cursor += 1;
    } else {
        buf[cursor] = b'0' + index as u8;
        cursor += 1;
    }
    match std::str::from_utf8(&buf[..cursor]) {
        Ok(s) => Ok(s),
        Err(_) => Err(TunnelError::ConfigInvalidToml),
    }
}

fn parse_u32_from_bytes(bytes: &[u8]) -> Result<u32, TunnelError> {
    let mut start = 0usize;
    while start < bytes.len()
        && (bytes[start] == b' ' || bytes[start] == b'\t' || bytes[start] == b'"')
    {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start
        && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t' || bytes[end - 1] == b'"')
    {
        end -= 1;
    }
    if start >= end {
        return Err(TunnelError::ConfigInvalidToml);
    }
    let s = &bytes[start..end];
    if s.len() > 2 && s[0] == b'0' && (s[1] == b'x' || s[1] == b'X') {
        let mut val = 0u32;
        let mut i = 2usize;
        while i < s.len() {
            let b = s[i];
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                _ => return Err(TunnelError::ConfigInvalidToml),
            };
            val = match val.checked_mul(16) {
                Some(v) => v,
                None => return Err(TunnelError::ConfigInvalidToml),
            };
            val = match val.checked_add(digit) {
                Some(v) => v,
                None => return Err(TunnelError::ConfigInvalidToml),
            };
            i += 1;
        }
        Ok(val)
    } else {
        let mut val = 0u32;
        let mut i = 0usize;
        while i < s.len() {
            let b = s[i];
            if !(b'0'..=b'9').contains(&b) {
                return Err(TunnelError::ConfigInvalidToml);
            }
            val = match val.checked_mul(10) {
                Some(v) => v,
                None => return Err(TunnelError::ConfigInvalidToml),
            };
            val = match val.checked_add((b - b'0') as u32) {
                Some(v) => v,
                None => return Err(TunnelError::ConfigInvalidToml),
            };
            i += 1;
        }
        Ok(val)
    }
}

// Load Endpoint (IP + Port) for Self or Peer
fn load_endpoint_from_toml(file_path: &str, identity_name: &str) -> Result<Endpoint, TunnelError> {
    let mut key_buf = [0u8; 64];

    // Read IP
    let ip_key = match build_toml_key(identity_name, "ip4", &mut key_buf) {
        Ok(k) => k,
        Err(e) => return Err(e),
    };
    let (ip_raw, ip_len) =
        match read_single_line_string_field_from_toml_no_heap::<32>(file_path, ip_key) {
            Ok(res) => res,
            Err(e) => return Err(e),
        };
    let ip_str = match std::str::from_utf8(&ip_raw[..ip_len]) {
        Ok(s) => s,
        Err(_) => return Err(TunnelError::ConfigInvalidIp),
    };
    let ip = match Ipv4::from_str(ip_str) {
        Ok(i) => i,
        Err(e) => return Err(e),
    };

    // Read Port
    let port_key = match build_toml_key(identity_name, "port", &mut key_buf) {
        Ok(k) => k,
        Err(e) => return Err(e),
    };
    let (port_raw, port_len) =
        match read_single_line_string_field_from_toml_no_heap::<16>(file_path, port_key) {
            Ok(res) => res,
            Err(e) => return Err(e),
        };
    let port_str = match std::str::from_utf8(&port_raw[..port_len]) {
        Ok(s) => s,
        Err(_) => return Err(TunnelError::ConfigInvalidPort),
    };
    let port = match Port::from_str(port_str) {
        Ok(p) => p,
        Err(e) => return Err(e),
    };

    Ok(Endpoint { ip, port })
}

// Load Crypto Keys (Salts + Validation Byte) for Peer Target
fn load_keys_from_toml(file_path: &str, peer_name: &str) -> Result<ConfigKeys, TunnelError> {
    let mut key_buf = [0u8; 64];
    let mut salts = [0u32; 16];
    let mut salt_idx = 1usize;
    let mut suffix_buf = [0u8; 16];

    while salt_idx <= 16 {
        let suffix = match build_salt_suffix(salt_idx, &mut suffix_buf) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let salt_key = match build_toml_key(peer_name, suffix, &mut key_buf) {
            Ok(k) => k,
            Err(e) => return Err(e),
        };
        let (salt_raw, salt_len) =
            match read_single_line_string_field_from_toml_no_heap::<32>(file_path, salt_key) {
                Ok(res) => res,
                Err(e) => return Err(e),
            };
        let salt_val = match parse_u32_from_bytes(&salt_raw[..salt_len]) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        salts[salt_idx - 1] = salt_val;
        salt_idx += 1;
    }

    let val_key = match build_toml_key(peer_name, "val", &mut key_buf) {
        Ok(k) => k,
        Err(e) => return Err(e),
    };
    let (val_raw, val_len) =
        match read_single_line_string_field_from_toml_no_heap::<16>(file_path, val_key) {
            Ok(res) => res,
            Err(e) => return Err(e),
        };
    let val_num = match parse_u32_from_bytes(&val_raw[..val_len]) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    Ok(ConfigKeys {
        salts,
        val_byte: val_num as u8,
    })
}

// --- PingPong Cryptographic Engine ---
struct PingPongEngine {
    t1: [u8; 256],
    inv1: [u8; 256],
    t2: [u8; 256],
    inv2: [u8; 256],
    fresh_t1: [u8; 256],
    fresh_inv1: [u8; 256],
}

impl PingPongEngine {
    pub fn init(salts: &[u32; 16], nonce: u32) -> Self {
        let (seed_1, seed_2) = Self::derive_seeds(salts, nonce);
        let mut t1 = [0u8; 256];
        let mut inv1 = [0u8; 256];
        let mut t2 = [0u8; 256];
        let mut inv2 = [0u8; 256];

        Self::scramble_table(&mut t1, &mut inv1, seed_1);
        Self::scramble_table(&mut t2, &mut inv2, seed_2);

        let fresh_t1 = t1;
        let fresh_inv1 = inv1;

        Self {
            t1,
            inv1,
            t2,
            inv2,
            fresh_t1,
            fresh_inv1,
        }
    }

    fn derive_seeds(salts: &[u32; 16], nonce: u32) -> (u64, u64) {
        let mut seed_1 = 0xcbf2_9ce4_8422_2325u64;
        let mut i = 0usize;
        while i < 16 {
            let val = (salts[i] ^ nonce) as u64;
            seed_1 ^= val;
            seed_1 = seed_1.wrapping_mul(0x0000_0100_0000_01B3);
            i = match i.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
        let seed_2 = seed_1 ^ 0xA5A5_A5A5_A5A5_A5A5u64;
        (seed_1, seed_2)
    }

    fn scramble_table(table: &mut [u8; 256], inv: &mut [u8; 256], seed: u64) {
        let mut i = 0usize;
        while i < 256 {
            table[i] = i as u8;
            i = match i.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
        let mut prng = seed;
        let mut idx = 255usize;
        while idx > 0 {
            prng = prng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let rand_val = (prng >> 32) as usize;
            let j = rand_val % (idx + 1);

            let tmp = table[idx];
            table[idx] = table[j];
            table[j] = tmp;

            idx -= 1;
        }

        let mut k = 0usize;
        while k < 256 {
            inv[table[k] as usize] = k as u8;
            k = match k.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
    }

    #[inline]
    fn swap_and_update(t: &mut [u8; 256], inv: &mut [u8; 256], i: usize, j: usize) {
        if i == j {
            return;
        }
        let val_i = t[i];
        let val_j = t[j];
        t[i] = val_j;
        t[j] = val_i;
        inv[val_j as usize] = i as u8;
        inv[val_i as usize] = j as u8;
    }

    // Dynamic table mutation using salt from array, not fixed values e.g. 13, 7, 3, 101
    #[inline]
    fn mutate_t2(&mut self, x: u8, salt_val: u8) {
        let i1 = x as usize;
        // Make offset odd (| 1) so it is coprime with 256 (reaches all positions)
        let offset = (salt_val | 1) as usize;

        // Swap 1: Uses dynamic salt offset instead of static +13
        let j1 = i1.wrapping_add(offset) & 0xFF;
        Self::swap_and_update(&mut self.t2, &mut self.inv2, i1, j1);

        // Swap 2: Uses dynamic salt offset instead of static +3 and +101
        let i2 = (i1.wrapping_mul(5).wrapping_add(offset)) & 0xFF;
        let j2 = i2.wrapping_add(offset) & 0xFF;
        Self::swap_and_update(&mut self.t2, &mut self.inv2, i2, j2);
    }

    #[inline]
    fn mutate_t1(&mut self, c: u8, salt_val: u8) {
        let i1 = c as usize;
        let offset = (salt_val | 1) as usize;

        // Swap 1: Uses dynamic salt offset instead of static +17
        let j1 = i1.wrapping_add(offset) & 0xFF;
        Self::swap_and_update(&mut self.t1, &mut self.inv1, i1, j1);

        // Swap 2: Uses dynamic salt offset instead of static +5 and +67
        let i2 = (i1.wrapping_mul(3).wrapping_add(offset)) & 0xFF;
        let j2 = i2.wrapping_add(offset) & 0xFF;
        Self::swap_and_update(&mut self.t1, &mut self.inv1, i2, j2);
    }

    pub fn encrypt_byte63(&self, val_byte: u8) -> u8 {
        self.fresh_t1[val_byte as usize]
    }

    pub fn decrypt_byte63(&self, cipher_63: u8) -> u8 {
        self.fresh_inv1[cipher_63 as usize]
    }

    pub fn encrypt_byte62(&self, checksum: u8) -> u8 {
        self.fresh_t1[checksum as usize]
    }

    pub fn decrypt_byte62(&self, cipher_62: u8) -> u8 {
        self.fresh_inv1[cipher_62 as usize]
    }

    pub fn compute_pearson_checksum(&self, payload: &[u8; PAYLOAD_SIZE]) -> u8 {
        let mut h = 0u8;
        let mut i = 0usize;
        while i < PAYLOAD_SIZE {
            let idx = (h ^ payload[i]) as usize;
            h = self.fresh_t1[idx];
            i = match i.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
        h
    }

    pub fn encrypt_payload(
        &mut self,
        salts: &[u32; 16],
        plaintext: &[u8; PAYLOAD_SIZE],
        ciphertext: &mut [u8; PAYLOAD_SIZE],
    ) {
        let mut state = 0u8;
        let mut i = 0usize;
        while i < PAYLOAD_SIZE {
            let m = plaintext[i];

            // --- Inject position counter 'i' into lookup ---
            let idx1 = (state ^ m ^ (i as u8)) as usize;
            let x = self.t1[idx1];
            let c = self.t2[x as usize];
            ciphertext[i] = c;

            // --- Set next state to ciphertext 'c' (prevents plaintext lock) ---
            state = c;

            // --- Fetch salt byte using counter 'i & 15' (0-15 wrapping index) ---
            let salt_val = (salts[i & 15] & 0xFF) as u8;

            self.mutate_t2(x, salt_val);
            self.mutate_t1(c, salt_val);

            i = match i.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
    }

    pub fn decrypt_payload(
        &mut self,
        salts: &[u32; 16], // <--- Added salts array reference
        ciphertext: &[u8; PAYLOAD_SIZE],
        plaintext: &mut [u8; PAYLOAD_SIZE],
    ) {
        let mut state = 0u8;
        let mut i = 0usize;
        while i < PAYLOAD_SIZE {
            let c = ciphertext[i];
            let x = self.inv2[c as usize];
            let raw = self.inv1[x as usize];

            // --- CHANGE 1: Invert position counter 'i' to recover original plaintext M ---
            let m = state ^ raw ^ (i as u8);
            plaintext[i] = m;

            // --- CHANGE 1: Set next state to ciphertext 'c' (matches encoder) ---
            state = c;

            // --- CHANGE 2: Fetch salt byte using counter 'i & 15' ---
            let salt_val = (salts[i & 15] & 0xFF) as u8;

            self.mutate_t2(x, salt_val);
            self.mutate_t1(c, salt_val);

            i = match i.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
    }
}

// --- Nonce & Time Operations ---
fn generate_nonce() -> u32 {
    let mut nonce_bytes = [0u8; 4];
    let mut got_random = false;

    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(&mut nonce_bytes).is_ok() {
            got_random = true;
        }
    }

    if !got_random {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stack_addr = &nonce_bytes as *const _ as usize as u128;
        let mixed = now ^ stack_addr;
        nonce_bytes[0] = (mixed & 0xFF) as u8;
        nonce_bytes[1] = ((mixed >> 8) & 0xFF) as u8;
        nonce_bytes[2] = ((mixed >> 16) & 0xFF) as u8;
        nonce_bytes[3] = ((mixed >> 24) & 0xFF) as u8;
    }

    u32::from_le_bytes(nonce_bytes)
}

fn current_timestamp() -> u32 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as u32,
        Err(_) => 0,
    }
}

// --- Packet Transmission & Processing ---
fn construct_packet(
    keys: &ConfigKeys,
    payload: &[u8; PAYLOAD_SIZE],
    out_packet: &mut [u8; PACKET_SIZE],
) {
    let nonce = generate_nonce();
    let nonce_bytes = nonce.to_le_bytes();
    out_packet[0] = nonce_bytes[0];
    out_packet[1] = nonce_bytes[1];
    out_packet[2] = nonce_bytes[2];
    out_packet[3] = nonce_bytes[3];

    let ts = current_timestamp();
    let ts_bytes = (!ts).to_be_bytes();
    out_packet[4] = ts_bytes[0];
    out_packet[5] = ts_bytes[1];
    out_packet[6] = ts_bytes[2];
    out_packet[7] = ts_bytes[3];

    let mut engine = PingPongEngine::init(&keys.salts, nonce);

    out_packet[63] = engine.encrypt_byte63(keys.val_byte);

    let checksum = engine.compute_pearson_checksum(payload);
    out_packet[62] = engine.encrypt_byte62(checksum);

    let mut cipher_payload = [0u8; PAYLOAD_SIZE];
    engine.encrypt_payload(&keys.salts, payload, &mut cipher_payload);

    let mut i = 0usize;
    while i < PAYLOAD_SIZE {
        out_packet[8 + i] = cipher_payload[i];
        i = match i.checked_add(1) {
            Some(v) => v,
            None => break,
        };
    }
}

fn process_incoming_packet(
    packet: &[u8],
    peers: &[Option<PeerTarget>; MAX_TARGETS],
    peer_count: usize,
    fallback_keys: &ConfigKeys,
    replay_filter: &mut ReplayFilter,
    out_payload: &mut [u8; PAYLOAD_SIZE],
) -> Result<usize, TunnelError> {
    if packet.len() != PACKET_SIZE {
        return Err(TunnelError::UdpPacketTruncated);
    }

    let nonce = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
    let ts_bytes = [packet[4], packet[5], packet[6], packet[7]];
    let ts = !u32::from_be_bytes(ts_bytes);

    let now = current_timestamp();

    // to keep packet-ordering safe after 2106
    let diff = now.abs_diff(ts); // prevents potential subtraction overflow

    if diff > 30 {
        return Err(TunnelError::UdpTimestampStale);
    }

    if replay_filter.is_replayed_or_insert(ts, nonce) {
        return Err(TunnelError::UdpReplayDetected);
    }

    let mut active_keys = fallback_keys;
    let mut match_found = false;

    let mut p_idx = 0usize;
    while p_idx < peer_count {
        if let Some(target) = &peers[p_idx] {
            let engine = PingPongEngine::init(&target.keys.salts, nonce);
            if engine.decrypt_byte63(packet[63]) == target.keys.val_byte {
                active_keys = &target.keys;
                match_found = true;
                break;
            }
        }
        p_idx += 1;
    }

    if !match_found {
        let engine = PingPongEngine::init(&fallback_keys.salts, nonce);
        if engine.decrypt_byte63(packet[63]) != fallback_keys.val_byte {
            return Err(TunnelError::CryptoByte63Failed);
        }
    }

    let mut engine = PingPongEngine::init(&active_keys.salts, nonce);
    let decrypted_62 = engine.decrypt_byte62(packet[62]);

    let mut cipher_payload = [0u8; PAYLOAD_SIZE];
    let mut i = 0usize;
    while i < PAYLOAD_SIZE {
        cipher_payload[i] = packet[8 + i];
        i = match i.checked_add(1) {
            Some(v) => v,
            None => break,
        };
    }

    engine.decrypt_payload(&active_keys.salts, &cipher_payload, out_payload);

    let computed_checksum = engine.compute_pearson_checksum(out_payload);
    if computed_checksum != decrypted_62 {
        return Err(TunnelError::CryptoByte62Failed);
    }

    let mut valid_len = 0usize;
    let mut idx = 0usize;
    while idx < PAYLOAD_SIZE {
        let b = out_payload[idx];
        if b == 0x00 {
            break;
        }
        if !(b == 0x0A || b == 0x0D || b == 0x09 || (0x20..=0x7E).contains(&b)) {
            return Err(TunnelError::CryptoInvalidAscii);
        }
        valid_len = match valid_len.checked_add(1) {
            Some(v) => v,
            None => break,
        };
        idx = match idx.checked_add(1) {
            Some(v) => v,
            None => break,
        };
    }

    Ok(valid_len)
}

// --- Multi-Peer Tunnel Loop ---
fn run_tunnel(
    bind_ep: Endpoint,
    peers: &[Option<PeerTarget>; MAX_TARGETS],
    peer_count: usize,
    fallback_keys: ConfigKeys,
) -> Result<(), TunnelError> {
    let local_addr = SocketAddrV4::new(bind_ep.ip.0, bind_ep.port.0);
    let socket = match UdpSocket::bind(local_addr) {
        Ok(s) => s,
        Err(_) => return Err(TunnelError::SocketBindFailed),
    };

    println!("[Tunnel] Bound UDP socket to {}", local_addr);

    let mut peer_addrs = [Option::<(SocketAddrV4, ConfigKeys)>::None; MAX_TARGETS];
    let mut i = 0usize;
    while i < peer_count {
        if let Some(target) = &peers[i] {
            let s_addr = SocketAddrV4::new(target.endpoint.ip.0, target.endpoint.port.0);
            peer_addrs[i] = Some((s_addr, target.keys));
            println!("[Tunnel] Registered target peer endpoint: {}", s_addr);
        }
        i += 1;
    }

    let socket_recv = match socket.try_clone() {
        Ok(s) => s,
        Err(_) => return Err(TunnelError::SocketBindFailed),
    };

    let peers_copy = *peers;
    let spawn_res = thread::Builder::new().spawn(move || {
        let mut buf = [0u8; 128];
        let mut payload_out = [0u8; PAYLOAD_SIZE];
        let mut replay_filter = ReplayFilter::new();

        loop {
            match socket_recv.recv_from(&mut buf) {
                Ok((len, _src)) => {
                    if len == PACKET_SIZE {
                        if let Ok(ascii_len) = process_incoming_packet(
                            &buf[..PACKET_SIZE],
                            &peers_copy,
                            peer_count,
                            &fallback_keys,
                            &mut replay_filter,
                            &mut payload_out,
                        ) {
                            let _ = stdout().write_all(&payload_out[..ascii_len]);
                            let _ = stdout().flush();
                        }
                    }
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    });

    if spawn_res.is_err() {
        return Err(TunnelError::InternalThreadSpawnFailed);
    }

    loop {
        let mut stdin_buf = [0u8; PAYLOAD_SIZE];
        let mut read_len = 0usize;

        while read_len < PAYLOAD_SIZE {
            let mut single = [0u8; 1];
            match stdin().read(&mut single) {
                Ok(1) => {
                    stdin_buf[read_len] = single[0];
                    read_len = match read_len.checked_add(1) {
                        Some(v) => v,
                        None => break,
                    };
                    if single[0] == b'\n' {
                        break;
                    }
                }
                _ => break,
            }
        }

        if read_len == 0 {
            break;
        }

        let mut t_idx = 0usize;
        while t_idx < MAX_TARGETS {
            if let Some((target_addr, target_keys)) = peer_addrs[t_idx] {
                let mut packet = [0u8; PACKET_SIZE];
                construct_packet(&target_keys, &stdin_buf, &mut packet);
                let _ = socket.send_to(&packet, target_addr);
            } else if t_idx == 0 && peer_count == 0 {
                let mut packet = [0u8; PACKET_SIZE];
                construct_packet(&fallback_keys, &stdin_buf, &mut packet);
                let _ = socket.send_to(&packet, SocketAddrV4::new(bind_ep.ip.0, bind_ep.port.0));
            }
            t_idx += 1;
        }
    }

    Ok(())
}

// --- Stdin Prompt Helpers ---
fn read_line_from_stdin(out_buf: &mut [u8]) -> usize {
    let mut len = 0usize;
    loop {
        let mut byte = [0u8; 1];
        if stdin().read_exact(&mut byte).is_err() {
            break;
        }
        if byte[0] == b'\n' || byte[0] == b'\r' {
            if len == 0 {
                continue;
            } else {
                break;
            }
        }
        if len < out_buf.len() {
            out_buf[len] = byte[0];
            len = match len.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
    }
    len
}

fn prompt_string_with_default<'a>(
    prompt: &str,
    default_val: &'a str,
    buf: &'a mut [u8; 128],
) -> &'a str {
    print!("{} [default: {}]: ", prompt, default_val);
    let _ = stdout().flush();
    let len = read_line_from_stdin(buf);
    if len == 0 {
        default_val
    } else {
        std::str::from_utf8(&buf[..len]).unwrap_or(default_val)
    }
}

fn prompt_string<'a>(prompt: &str, buf: &'a mut [u8; 64]) -> Option<&'a str> {
    print!("{}: ", prompt);
    let _ = stdout().flush();
    let len = read_line_from_stdin(buf);
    if len == 0 {
        None
    } else {
        std::str::from_utf8(&buf[..len]).ok()
    }
}

fn prompt_add_another(prompt: &str) -> bool {
    print!("{}", prompt);
    let _ = stdout().flush();
    let mut buf = [0u8; 4];
    let len = read_line_from_stdin(&mut buf);
    len > 0 && (buf[0] == b'y' || buf[0] == b'Y')
}

// Zero-heap CLI Parser separating mutation from borrow slice generation
fn parse_cli_args<'a>(
    config_buf: &'a mut [u8; 256],
    self_buf: &'a mut [u8; 32],
    peer_bufs: &'a mut [[u8; 32]; MAX_TARGETS],
) -> Result<
    (
        Option<&'a str>,
        Option<&'a str>,
        [Option<&'a str>; MAX_TARGETS],
        usize,
    ),
    TunnelError,
> {
    let mut config_len: Option<usize> = None;
    let mut self_len: Option<usize> = None;
    let mut peer_lens = [0usize; MAX_TARGETS];
    let mut peer_count = 0usize;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let bytes = arg.as_bytes();
        if bytes == b"--config" || bytes == b"-f" {
            if let Some(path_str) = args.next() {
                let p_bytes = path_str.as_bytes();
                if p_bytes.len() <= config_buf.len() {
                    config_buf[..p_bytes.len()].copy_from_slice(p_bytes);
                    config_len = Some(p_bytes.len());
                }
            }
        } else if bytes == b"--self" || bytes == b"-s" {
            if let Some(s_str) = args.next() {
                let s_bytes = s_str.as_bytes();
                if s_bytes.len() <= self_buf.len() {
                    self_buf[..s_bytes.len()].copy_from_slice(s_bytes);
                    self_len = Some(s_bytes.len());
                }
            }
        } else if bytes == b"--peer" || bytes == b"-p" {
            if let Some(p_str) = args.next() {
                if peer_count < MAX_TARGETS {
                    let p_bytes = p_str.as_bytes();
                    if p_bytes.len() <= peer_bufs[peer_count].len() {
                        peer_bufs[peer_count][..p_bytes.len()].copy_from_slice(p_bytes);
                        peer_lens[peer_count] = p_bytes.len();
                        peer_count += 1;
                    }
                }
            }
        }
    }

    let config_path = match config_len {
        Some(len) => match std::str::from_utf8(&config_buf[..len]) {
            Ok(s) => Some(s),
            Err(_) => return Err(TunnelError::ConfigInvalidToml),
        },
        None => None,
    };

    let self_name = match self_len {
        Some(len) => match std::str::from_utf8(&self_buf[..len]) {
            Ok(s) => Some(s),
            Err(_) => return Err(TunnelError::ConfigInvalidToml),
        },
        None => None,
    };

    let mut peer_names: [Option<&'a str>; MAX_TARGETS] = [None, None, None, None];
    let mut i = 0usize;
    while i < peer_count {
        let len = peer_lens[i];
        let name = match std::str::from_utf8(&peer_bufs[i][..len]) {
            Ok(s) => s,
            Err(_) => return Err(TunnelError::ConfigInvalidToml),
        };
        peer_names[i] = Some(name);
        i += 1;
    }

    Ok((config_path, self_name, peer_names, peer_count))
}

// --- Entry Point ---
fn main() {
    let mut config_buf = [0u8; 256];
    let mut self_buf = [0u8; 32];
    let mut peer_bufs = [[0u8; 32]; MAX_TARGETS];

    let (cli_config, cli_self, cli_peers, cli_peer_count) =
        match parse_cli_args(&mut config_buf, &mut self_buf, &mut peer_bufs) {
            Ok(parsed) => parsed,
            Err(e) => std::process::exit(e as i32),
        };

    let mut path_scratch = [0u8; 256];
    let exe_dir_path = match get_executable_directory_config_path(&mut path_scratch) {
        Ok(p) => p,
        Err(_) => "tunnel.toml",
    };

    let mut path_input_buf = [0u8; 128];
    let mut self_input_buf = [0u8; 64];
    let mut peer_input_bufs = [[0u8; 64]; MAX_TARGETS];

    let final_config_path = match cli_config {
        Some(p) => p,
        None => prompt_string_with_default(
            "Enter TOML configuration file path",
            exe_dir_path,
            &mut path_input_buf,
        ),
    };

    let final_self_name = match cli_self {
        Some(s) => s,
        None => match prompt_string(
            "Enter your local identity name in TOML (e.g., bob)",
            &mut self_input_buf,
        ) {
            Some(s) => s,
            None => {
                eprintln!("Error: Self identity name is required to bind local socket.");
                std::process::exit(TunnelError::ConfigInvalidArgs as i32);
            }
        },
    };

    let mut targets: [Option<PeerTarget>; MAX_TARGETS] = [None, None, None, None];
    let mut target_count = 0usize;

    if cli_peer_count > 0 {
        let mut i = 0usize;
        while i < cli_peer_count {
            if let Some(peer_name) = cli_peers[i] {
                let ep = match load_endpoint_from_toml(final_config_path, peer_name) {
                    Ok(e) => e,
                    Err(err) => std::process::exit(err as i32),
                };
                let keys = match load_keys_from_toml(final_config_path, peer_name) {
                    Ok(k) => k,
                    Err(err) => std::process::exit(err as i32),
                };
                targets[target_count] = Some(PeerTarget { endpoint: ep, keys });
                target_count += 1;
            }
            i += 1;
        }
    } else {
        let peer_name = match prompt_string(
            "Enter target peer identity name in TOML (e.g., alice)",
            &mut peer_input_bufs[0],
        ) {
            Some(s) => s,
            None => {
                eprintln!("Error: Target peer identity name is required.");
                std::process::exit(TunnelError::ConfigInvalidArgs as i32);
            }
        };

        let ep = match load_endpoint_from_toml(final_config_path, peer_name) {
            Ok(e) => e,
            Err(err) => std::process::exit(err as i32),
        };
        let keys = match load_keys_from_toml(final_config_path, peer_name) {
            Ok(k) => k,
            Err(err) => std::process::exit(err as i32),
        };
        targets[0] = Some(PeerTarget { endpoint: ep, keys });
        target_count = 1;

        while target_count < MAX_TARGETS && prompt_add_another("Add another peer target? [y/N]: ") {
            if let Some(additional_peer) = prompt_string(
                "Enter additional peer identity name",
                &mut peer_input_bufs[target_count],
            ) {
                let ep = match load_endpoint_from_toml(final_config_path, additional_peer) {
                    Ok(e) => e,
                    Err(err) => std::process::exit(err as i32),
                };
                let keys = match load_keys_from_toml(final_config_path, additional_peer) {
                    Ok(k) => k,
                    Err(err) => std::process::exit(err as i32),
                };
                targets[target_count] = Some(PeerTarget { endpoint: ep, keys });
                target_count += 1;
            }
        }
    }

    let bind_ep = match load_endpoint_from_toml(final_config_path, final_self_name) {
        Ok(ep) => ep,
        Err(err) => {
            eprintln!(
                "Failed to load local bind endpoint for identity '{}' from {}",
                final_self_name, final_config_path
            );
            std::process::exit(err as i32);
        }
    };

    let fallback_keys = ConfigKeys {
        salts: DEFAULT_SALTS,
        val_byte: DEFAULT_VAL_BYTE,
    };

    println!(
        "[Setup] Initialized tunnel for self '{}' on {}:{}",
        final_self_name, bind_ep.ip.0, bind_ep.port.0
    );

    if let Err(err) = run_tunnel(bind_ep, &targets, target_count, fallback_keys) {
        #[cfg(debug_assertions)]
        eprintln!("Fatal error: {:?}", err);
        std::process::exit(err as i32);
    }
}

// --- Standard Library Tests ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executable_directory_path_formatting() {
        let mut buf = [0u8; 256];
        let res = get_executable_directory_config_path(&mut buf);
        assert!(res.is_ok());
        let path = res.unwrap();
        assert!(path.ends_with("/tunnel.toml"));
    }

    #[test]
    fn test_toml_key_builder_no_heap() {
        let mut buf = [0u8; 64];
        let key = build_toml_key("alice", "ip4", &mut buf).unwrap();
        assert_eq!(key, "alice_ip4");

        let mut salt_buf = [0u8; 16];
        let suffix = build_salt_suffix(12, &mut salt_buf).unwrap();
        assert_eq!(suffix, "salt_12");
    }

    #[test]
    fn test_hex_and_decimal_parsing() {
        assert_eq!(parse_u32_from_bytes(b"12345").unwrap(), 12345);
        assert_eq!(parse_u32_from_bytes(b"0x12345678").unwrap(), 0x12345678);
        assert_eq!(parse_u32_from_bytes(b"\"0x44\"").unwrap(), 0x44);
    }

    #[test]
    fn test_pingpong_crypto_roundtrip() {
        let keys = ConfigKeys {
            salts: DEFAULT_SALTS,
            val_byte: 0x44,
        };
        let peer_target = PeerTarget {
            endpoint: Endpoint {
                ip: Ipv4::_from_octets(127, 0, 0, 1),
                port: Port(8080),
            },
            keys,
        };
        let peers: [Option<PeerTarget>; MAX_TARGETS] = [Some(peer_target), None, None, None];

        let mut raw_payload = [0u8; PAYLOAD_SIZE];
        let msg = b"Testing zero-heap executable-path relative TOML tunnel";
        let mut i = 0usize;
        while i < msg.len() {
            raw_payload[i] = msg[i];
            i += 1;
        }

        let mut packet = [0u8; PACKET_SIZE];
        construct_packet(&keys, &raw_payload, &mut packet);

        let mut replay_filter = ReplayFilter::new();
        let mut decrypted_payload = [0u8; PAYLOAD_SIZE];

        let valid_len = process_incoming_packet(
            &packet,
            &peers,
            1,
            &keys,
            &mut replay_filter,
            &mut decrypted_payload,
        )
        .expect("Decryption pipeline failed");

        assert_eq!(valid_len, msg.len());
        assert_eq!(&decrypted_payload[..valid_len], msg);
    }
}

#[cfg(test)]
mod entropy_tests {
    use super::*;

    /// Calculates Shannon Entropy on a byte slice.
    /// Returns bits per byte (0.0 to 8.0).
    fn calculate_shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut byte_counts = [0usize; 256];
        for &b in data {
            byte_counts[b as usize] += 1;
        }
        let len_f = data.len() as f64;
        let mut entropy = 0.0f64;
        for &count in &byte_counts {
            if count > 0 {
                let p = count as f64 / len_f;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Finds the maximum length of repeated adjacent bytes (e.g. [0xAA, 0xAA, 0xAA] -> 3).
    fn max_consecutive_run(data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        let mut max_run = 1usize;
        let mut current_run = 1usize;
        let mut i = 1usize;
        while i < data.len() {
            if data[i] == data[i - 1] {
                current_run += 1;
                if current_run > max_run {
                    max_run = current_run;
                }
            } else {
                current_run = 1;
            }
            i += 1;
        }
        max_run
    }

    #[test]
    fn test_entropy_repeated_character_a() {
        let keys = ConfigKeys {
            salts: DEFAULT_SALTS,
            val_byte: DEFAULT_VAL_BYTE,
        };
        let payload = [b'a'; PAYLOAD_SIZE];
        let mut packet = [0u8; PACKET_SIZE];

        construct_packet(&keys, &payload, &mut packet);

        let cipher_payload = &packet[8..62];
        let entropy = calculate_shannon_entropy(cipher_payload);
        let longest_run = max_consecutive_run(cipher_payload);

        println!("Entropy for 'a'*54: {:.4}", entropy);
        println!("Longest run for 'a'*54: {}", longest_run);

        // Enforce high entropy: Must be > 4.5 bits/byte for 54 bytes
        assert!(
            entropy > 4.5,
            "Entropy too low ({:.4}) for repeated input 'a'*54",
            entropy
        );

        // Enforce run-length limit: No more than 3 identical adjacent ciphertext bytes
        assert!(
            longest_run <= 3,
            "Ciphertext contains unacceptable repeating run length of {}",
            longest_run
        );
    }

    #[test]
    fn test_entropy_repeated_pattern_hi() {
        let keys = ConfigKeys {
            salts: DEFAULT_SALTS,
            val_byte: DEFAULT_VAL_BYTE,
        };
        let mut payload = [0u8; PAYLOAD_SIZE];
        let pattern = b"Hi";
        let mut i = 0usize;
        while i < PAYLOAD_SIZE {
            payload[i] = pattern[i % pattern.len()];
            i += 1;
        }

        let mut packet = [0u8; PACKET_SIZE];
        construct_packet(&keys, &payload, &mut packet);

        let cipher_payload = &packet[8..62];
        let entropy = calculate_shannon_entropy(cipher_payload);
        let longest_run = max_consecutive_run(cipher_payload);

        println!("Entropy for 'Hi'*27: {:.4}", entropy);
        println!("Longest run for 'Hi'*27: {}", longest_run);

        assert!(
            entropy > 4.5,
            "Entropy too low ({:.4}) for repeated input 'Hi'*27",
            entropy
        );
        assert!(
            longest_run <= 3,
            "Ciphertext contains unacceptable repeating run length of {}",
            longest_run
        );
    }
    #[test]
    fn test_avalanche_effect_single_bit_flip() {
        let keys = ConfigKeys {
            salts: DEFAULT_SALTS,
            val_byte: DEFAULT_VAL_BYTE,
        };
        let payload1 = [b'a'; PAYLOAD_SIZE];
        let mut payload2 = [b'a'; PAYLOAD_SIZE];
        payload2[0] = b'b'; // Single byte change

        let nonce = 0xDEADBEEF;
        let mut engine1 = PingPongEngine::init(&keys.salts, nonce);
        let mut engine2 = PingPongEngine::init(&keys.salts, nonce);

        let mut cipher1 = [0u8; PAYLOAD_SIZE];
        let mut cipher2 = [0u8; PAYLOAD_SIZE];

        // --- UPDATED: Added &keys.salts as the first payload parameter ---
        engine1.encrypt_payload(&keys.salts, &payload1, &mut cipher1);
        engine2.encrypt_payload(&keys.salts, &payload2, &mut cipher2);

        // Count bit differences (Hamming Distance)
        let mut bit_diffs = 0u32;
        let mut i = 0usize;
        while i < PAYLOAD_SIZE {
            bit_diffs += (cipher1[i] ^ cipher2[i]).count_ones();
            i += 1;
        }

        let total_bits = (PAYLOAD_SIZE * 8) as f32;
        let diff_ratio = bit_diffs as f32 / total_bits;

        println!("Hamming Bit Difference Ratio: {:.2}%", diff_ratio * 100.0);

        // Ideal Avalanche Effect for strong ciphers is ~50% bit flip ratio
        assert!(
            diff_ratio > 0.35,
            "Avalanche effect too weak ({:.2}%) for single byte change",
            diff_ratio * 100.0
        );
    }
}
