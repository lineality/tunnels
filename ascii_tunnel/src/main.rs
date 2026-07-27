// Enable lints for production builds
#![cfg_attr(not(debug_assertions), forbid(unsafe_code))]
#![cfg_attr(not(debug_assertions), deny(clippy::alloc_instead_of_core))]
#![cfg_attr(not(debug_assertions), deny(clippy::string_slice))]
#![cfg_attr(not(debug_assertions), deny(clippy::vec_collect))]

use std::{
    io::{Read, Write, stdin, stdout},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    thread,
};

// --- Error Handling ---
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TunnelError {
    // Network errors (1-99)
    SocketBindFailed = 1,
    SocketConnectFailed = 2,
    SocketReadFailed = 3,
    SocketWriteFailed = 4,
    SocketAcceptFailed = 5,
    SocketCloneFailed = 6,

    // Config errors (100-199)
    ConfigInvalidPort = 100,
    ConfigInvalidIp = 101,
    ConfigInvalidArgs = 102,

    // Encryption errors (200-299)
    EncryptionBufferOverflow = 200,

    // Internal errors (300-399)
    InternalThreadSpawnFailed = 300,
}

impl TunnelError {
    #[inline]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            TunnelError::SocketConnectFailed | TunnelError::SocketAcceptFailed
        )
    }
}

#[cfg(debug_assertions)]
impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::SocketBindFailed => write!(f, "Failed to bind socket"),
            TunnelError::SocketConnectFailed => write!(f, "Failed to connect socket"),
            TunnelError::SocketReadFailed => write!(f, "Failed to read from socket"),
            TunnelError::SocketWriteFailed => write!(f, "Failed to write to socket"),
            TunnelError::SocketAcceptFailed => write!(f, "Failed to accept connection"),
            TunnelError::SocketCloneFailed => write!(f, "Failed to clone socket"),
            TunnelError::ConfigInvalidPort => write!(f, "Invalid port number"),
            TunnelError::ConfigInvalidIp => write!(f, "Invalid IP address"),
            TunnelError::ConfigInvalidArgs => write!(f, "Invalid CLI arguments"),
            TunnelError::EncryptionBufferOverflow => write!(f, "Encryption buffer overflow"),
            TunnelError::InternalThreadSpawnFailed => write!(f, "Failed to spawn thread"),
        }
    }
}

// --- Custom Types for Value Integrity ---
#[derive(Copy, Clone, Debug)]
struct Port(u16);

impl Port {
    pub const fn new(value: u16) -> Result<Self, TunnelError> {
        if value == 0 {
            Err(TunnelError::ConfigInvalidPort)
        } else {
            Ok(Self(value))
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
struct Ipv4(Ipv4Addr);

impl Ipv4 {
    pub const fn from_octets(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(Ipv4Addr::new(a, b, c, d))
    }

    /// Parses an IPv4 address from a `&str` **without heap allocation or `?` operator**.
    /// Returns `TunnelError::ConfigInvalidIp` on failure.
    pub fn from_str(s: &str) -> Result<Self, TunnelError> {
        let mut octets = [0u8; 4];
        let mut current = 0u16;
        let mut octet_index = 0usize;
        let mut chars = s.chars();

        loop {
            match chars.next() {
                Some(c @ '0'..='9') => {
                    let mul_res = match current.checked_mul(10) {
                        Some(v) => v,
                        None => return Err(TunnelError::ConfigInvalidIp),
                    };
                    let add_res = match mul_res.checked_add((c as u16) - ('0' as u16)) {
                        Some(v) => v,
                        None => return Err(TunnelError::ConfigInvalidIp),
                    };
                    current = add_res;
                    if current > 255 {
                        return Err(TunnelError::ConfigInvalidIp);
                    }
                }
                Some('.') => {
                    octets[octet_index] = current as u8;
                    octet_index = match octet_index.checked_add(1) {
                        Some(v) => v,
                        None => return Err(TunnelError::ConfigInvalidIp),
                    };
                    current = 0;
                    if octet_index >= 4 {
                        return Err(TunnelError::ConfigInvalidIp);
                    }
                }
                None => {
                    octets[octet_index] = current as u8;
                    if octet_index != 3 {
                        return Err(TunnelError::ConfigInvalidIp);
                    }
                    break;
                }
                Some(_) => return Err(TunnelError::ConfigInvalidIp),
            }
        }

        Ok(Self(Ipv4Addr::from(octets)))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum AppMode {
    Server,
    Client,
    InteractivePrompt,
}

// --- Encryption ---
#[inline]
fn xor_encrypt_decrypt(data: &[u8], key: u8) -> [u8; 1024] {
    let mut output = [0u8; 1024];
    let len = data.len().min(1024);
    let mut i = 0;
    while i < len {
        output[i] = data[i] ^ key;
        i = match i.checked_add(1) {
            Some(v) => v,
            None => break,
        };
    }
    output
}

// --- Networking ---
fn run_server(ip: Ipv4, port: Port, key: u8) -> Result<(), TunnelError> {
    let addr = SocketAddrV4::new(ip.0, port.0);
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(_) => {
            #[cfg(debug_assertions)]
            eprintln!("TunnelError::SocketBindFailed: {}", addr);
            return Err(TunnelError::SocketBindFailed);
        }
    };

    println!("[Server] Listening on {}:{}...", ip.0, port.0);

    let (stream, remote_addr) = match listener.accept() {
        Ok(res) => res,
        Err(_) => {
            #[cfg(debug_assertions)]
            eprintln!("TunnelError::SocketAcceptFailed");
            return Err(TunnelError::SocketAcceptFailed);
        }
    };

    println!("[Server] Connection accepted from {}", remote_addr);

    let mut stream = stream;
    let mut stream_clone = match stream.try_clone() {
        Ok(c) => c,
        Err(_) => {
            #[cfg(debug_assertions)]
            eprintln!("TunnelError::SocketCloneFailed");
            return Err(TunnelError::SocketCloneFailed);
        }
    };

    // Spawn thread for reading incoming socket stream
    let spawn_res = thread::Builder::new().spawn(move || {
        let mut buffer = [0u8; 1024];
        loop {
            match stream_clone.read(&mut buffer) {
                Ok(0) => break, // Peer closed connection
                Ok(n) => {
                    let decrypted = xor_encrypt_decrypt(&buffer[..n], key);
                    let _ = stdout().write_all(&decrypted[..n]);
                    let _ = stdout().flush();
                }
                Err(_) => {
                    #[cfg(debug_assertions)]
                    eprintln!("TunnelError::SocketReadFailed");
                    break;
                }
            }
        }
    });

    if spawn_res.is_err() {
        #[cfg(debug_assertions)]
        eprintln!("TunnelError::InternalThreadSpawnFailed");
        return Err(TunnelError::InternalThreadSpawnFailed);
    }

    // Main thread: Read from terminal stdin and send over TCP
    loop {
        let mut input = [0u8; 1024];
        let n = match stdin().read(&mut input) {
            Ok(bytes) => bytes,
            Err(_) => {
                #[cfg(debug_assertions)]
                eprintln!("Failed to read stdin");
                return Err(TunnelError::SocketReadFailed);
            }
        };

        if n == 0 {
            break;
        }

        let encrypted = xor_encrypt_decrypt(&input[..n], key);
        if stream.write_all(&encrypted[..n]).is_err() {
            #[cfg(debug_assertions)]
            eprintln!("TunnelError::SocketWriteFailed");
            return Err(TunnelError::SocketWriteFailed);
        }
    }

    Ok(())
}

fn run_client(remote_ip: Ipv4, remote_port: Port, key: u8) -> Result<(), TunnelError> {
    let addr = SocketAddrV4::new(remote_ip.0, remote_port.0);
    println!(
        "[Client] Connecting to {}:{}...",
        remote_ip.0, remote_port.0
    );

    let mut stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => {
            #[cfg(debug_assertions)]
            eprintln!("TunnelError::SocketConnectFailed: {}", addr);
            return Err(TunnelError::SocketConnectFailed);
        }
    };

    println!("[Client] Connected to peer!");

    let mut stream_clone = match stream.try_clone() {
        Ok(c) => c,
        Err(_) => {
            #[cfg(debug_assertions)]
            eprintln!("TunnelError::SocketCloneFailed");
            return Err(TunnelError::SocketCloneFailed);
        }
    };

    // Spawn thread for reading incoming socket stream
    let spawn_res = thread::Builder::new().spawn(move || {
        let mut buffer = [0u8; 1024];
        loop {
            match stream_clone.read(&mut buffer) {
                Ok(0) => break, // Peer closed connection
                Ok(n) => {
                    let decrypted = xor_encrypt_decrypt(&buffer[..n], key);
                    let _ = stdout().write_all(&decrypted[..n]);
                    let _ = stdout().flush();
                }
                Err(_) => {
                    #[cfg(debug_assertions)]
                    eprintln!("TunnelError::SocketReadFailed");
                    break;
                }
            }
        }
    });

    if spawn_res.is_err() {
        #[cfg(debug_assertions)]
        eprintln!("TunnelError::InternalThreadSpawnFailed");
        return Err(TunnelError::InternalThreadSpawnFailed);
    }

    // Main thread: Read from terminal stdin and send over TCP
    loop {
        let mut input = [0u8; 1024];
        let n = match stdin().read(&mut input) {
            Ok(bytes) => bytes,
            Err(_) => {
                #[cfg(debug_assertions)]
                eprintln!("Failed to read stdin");
                return Err(TunnelError::SocketReadFailed);
            }
        };

        if n == 0 {
            break;
        }

        let encrypted = xor_encrypt_decrypt(&input[..n], key);
        if stream.write_all(&encrypted[..n]).is_err() {
            #[cfg(debug_assertions)]
            eprintln!("TunnelError::SocketWriteFailed");
            return Err(TunnelError::SocketWriteFailed);
        }
    }

    Ok(())
}

/// Reads an IPv4 address from stdin without dynamic heap allocation.
fn read_ipv4_from_stdin() -> Option<Ipv4> {
    let mut buf = [0u8; 15]; // Max IPv4 string length: "255.255.255.255"
    let mut len = 0usize;

    loop {
        if len >= 15 {
            break;
        }
        let mut byte = [0u8; 1];
        if stdin().read_exact(&mut byte).is_err() {
            break;
        }
        if byte[0] == b'\n' || byte[0] == b'\r' {
            break;
        }
        buf[len] = byte[0];
        len = match len.checked_add(1) {
            Some(v) => v,
            None => break,
        };
    }

    let input = match std::str::from_utf8(&buf[..len]) {
        Ok(v) => v,
        Err(_) => return None,
    };

    match Ipv4::from_str(input) {
        Ok(ip) => Some(ip),
        Err(_) => None,
    }
}

/// Prompts user for IP address interactively.
fn prompt_ipv4(prompt: &str, fallback: Ipv4) -> Ipv4 {
    println!("{}", prompt);
    match read_ipv4_from_stdin() {
        Some(ip) => ip,
        None => {
            eprintln!("Invalid input. Falling back to default IP.");
            fallback
        }
    }
}

/// Prompts user for execution mode if CLI flags were omitted.
fn prompt_mode() -> AppMode {
    println!("Select Mode:");
    println!(" [1] Server (Listen for incoming tunnel)");
    println!(" [2] Client (Connect to remote peer)");
    print!("Choice [1/2]: ");
    let _ = stdout().flush();

    let mut buf = [0u8; 4];
    let mut len = 0usize;

    loop {
        if len >= 4 {
            break;
        }
        let mut byte = [0u8; 1];
        if stdin().read_exact(&mut byte).is_err() {
            break;
        }
        if byte[0] == b'\n' || byte[0] == b'\r' {
            break;
        }
        buf[len] = byte[0];
        len = match len.checked_add(1) {
            Some(v) => v,
            None => break,
        };
    }

    if len > 0 && buf[0] == b'2' {
        AppMode::Client
    } else {
        AppMode::Server
    }
}

/// Zero-heap command-line flag parser.
fn parse_cli_args() -> (AppMode, Option<Ipv4>) {
    let mut mode = AppMode::InteractivePrompt;
    let mut parsed_ip = None;

    for arg in std::env::args().skip(1) {
        let bytes = arg.as_bytes();
        if bytes == b"--server" || bytes == b"-s" {
            mode = AppMode::Server;
        } else if bytes == b"--client" || bytes == b"-c" {
            mode = AppMode::Client;
        } else if let Ok(ip) = Ipv4::from_str(&arg) {
            parsed_ip = Some(ip);
        }
    }

    (mode, parsed_ip)
}

// --- Main ---
fn main() {
    let (cli_mode, cli_ip) = parse_cli_args();

    let mode = if cli_mode == AppMode::InteractivePrompt {
        println!("Get IP");
        println!("Run: ip route get 1.2.3.4 | awk '{{print $7}}'");
        println!("or, 2->inet from: ip -4 addr");

        prompt_mode()
    } else {
        cli_mode
    };

    let port = match Port::new(12345) {
        Ok(p) => p,
        Err(e) => {
            #[cfg(debug_assertions)]
            eprintln!("Invalid port error: {:?}", e);
            std::process::exit(e as i32);
        }
    };

    let key = 0x5Au8; // Simple initial key byte for stream XOR cipher MVP

    let result = match mode {
        AppMode::Server => {
            let bind_ip = match cli_ip {
                Some(ip) => ip,
                None => prompt_ipv4(
                    "Enter local bind IPv4 address (default: 0.0.0.0):",
                    Ipv4::from_octets(0, 0, 0, 0),
                ),
            };
            run_server(bind_ip, port, key)
        }
        AppMode::Client => {
            let target_ip = match cli_ip {
                Some(ip) => ip,
                None => prompt_ipv4(
                    "Enter remote peer IPv4 address (default: 127.0.0.1):",
                    Ipv4::from_octets(127, 0, 0, 1),
                ),
            };
            run_client(target_ip, port, key)
        }
        AppMode::InteractivePrompt => Unreachable(),
    };

    if let Err(e) = result {
        #[cfg(debug_assertions)]
        eprintln!("Fatal tunnel error: {:?}", e);
        std::process::exit(e as i32);
    }
}

// Macro helper for strict pattern matching guarantees without unsafe or panic
#[allow(non_snake_case)]
fn Unreachable() -> Result<(), TunnelError> {
    Err(TunnelError::ConfigInvalidArgs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_parsing() {
        assert_eq!(
            Ipv4::from_str("192.168.1.1").unwrap(), // unwrap deliberate in test
            Ipv4::from_octets(192, 168, 1, 1)
        );
        assert_eq!(
            Ipv4::from_str("0.0.0.0").unwrap(), // unwrap deliberate in test
            Ipv4::from_octets(0, 0, 0, 0)
        );
        assert!(matches!(
            Ipv4::from_str("256.1.1.1"),
            Err(TunnelError::ConfigInvalidIp)
        ));
        assert!(matches!(
            Ipv4::from_str("192.168.1"),
            Err(TunnelError::ConfigInvalidIp)
        ));
    }

    #[test]
    fn test_port_validation() {
        assert!(Port::new(0).is_err());
        assert!(Port::new(12345).is_ok());
    }

    #[test]
    fn test_xor_encryption() {
        let data = b"hello ascii tunnel";
        let key = 0x5Au8;
        let encrypted = xor_encrypt_decrypt(data, key);
        let decrypted = xor_encrypt_decrypt(&encrypted[..data.len()], key);
        assert_eq!(&decrypted[..data.len()], data);
    }
}
