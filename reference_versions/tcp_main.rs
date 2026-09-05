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

// Maximum number of target IP/Port endpoints supported simultaneously without heap allocation
const MAX_TARGETS: usize = 4;

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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Port(u16);

impl Port {
    pub const fn _new(value: u16) -> Result<Self, TunnelError> {
        if value == 0 {
            Err(TunnelError::ConfigInvalidPort)
        } else {
            Ok(Self(value))
        }
    }

    /// Parses a Port from a `&str` without heap allocation.
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
struct Endpoint {
    ip: Ipv4,
    port: Port,
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
fn run_server(
    endpoints: &[Option<Endpoint>; MAX_TARGETS],
    count: usize,
    key: u8,
) -> Result<(), TunnelError> {
    let mut streams: [Option<TcpStream>; MAX_TARGETS] = [None, None, None, None];
    let mut active_count = 0usize;

    println!("[Server] Initializing {} listening socket(s)...", count);

    for i in 0..count {
        if let Some(ep) = endpoints[i] {
            let addr = SocketAddrV4::new(ep.ip.0, ep.port.0);
            let listener = match TcpListener::bind(addr) {
                Ok(l) => l,
                Err(_) => {
                    #[cfg(debug_assertions)]
                    eprintln!("TunnelError::SocketBindFailed: {}", addr);
                    return Err(TunnelError::SocketBindFailed);
                }
            };

            println!("[Server] Listening on {}:{}...", ep.ip.0, ep.port.0);

            let (stream, remote_addr) = match listener.accept() {
                Ok(res) => res,
                Err(_) => {
                    #[cfg(debug_assertions)]
                    eprintln!("TunnelError::SocketAcceptFailed");
                    return Err(TunnelError::SocketAcceptFailed);
                }
            };

            println!("[Server] Connection accepted from {}", remote_addr);

            let stream_clone = match stream.try_clone() {
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
                let mut stream_read = stream_clone;
                loop {
                    match stream_read.read(&mut buffer) {
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

            streams[active_count] = Some(stream);
            active_count += 1;
        }
    }

    // Main thread: Read stdin and broadcast encrypted output to ALL targets
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
        for stream_opt in streams.iter_mut() {
            if let Some(stream) = stream_opt {
                let _ = stream.write_all(&encrypted[..n]);
            }
        }
    }

    Ok(())
}

fn run_client(
    endpoints: &[Option<Endpoint>; MAX_TARGETS],
    count: usize,
    key: u8,
) -> Result<(), TunnelError> {
    let mut streams: [Option<TcpStream>; MAX_TARGETS] = [None, None, None, None];
    let mut active_count = 0usize;

    for i in 0..count {
        if let Some(ep) = endpoints[i] {
            let addr = SocketAddrV4::new(ep.ip.0, ep.port.0);
            println!("[Client] Connecting to {}:{}...", ep.ip.0, ep.port.0);

            let stream = match TcpStream::connect(addr) {
                Ok(s) => s,
                Err(_) => {
                    #[cfg(debug_assertions)]
                    eprintln!("TunnelError::SocketConnectFailed: {}", addr);
                    return Err(TunnelError::SocketConnectFailed);
                }
            };

            println!("[Client] Connected to peer {}:{}!", ep.ip.0, ep.port.0);

            let stream_clone = match stream.try_clone() {
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
                let mut stream_read = stream_clone;
                loop {
                    match stream_read.read(&mut buffer) {
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

            streams[active_count] = Some(stream);
            active_count += 1;
        }
    }

    // Main thread: Read from terminal stdin and broadcast over TCP streams
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
        for stream_opt in streams.iter_mut() {
            if let Some(stream) = stream_opt {
                let _ = stream.write_all(&encrypted[..n]);
            }
        }
    }

    Ok(())
}

/// Reads an IPv4 address from stdin without dynamic heap allocation.
fn read_ipv4_from_stdin() -> Option<Ipv4> {
    let mut buf = [0u8; 15]; // Max IPv4 string length: "255.255.255.255"
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

        if len < 15 {
            buf[len] = byte[0];
            len = match len.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
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

/// Reads a Port number from stdin without dynamic heap allocation.
fn read_port_from_stdin() -> Option<Port> {
    let mut buf = [0u8; 5]; // Max port string length: "65535"
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

        if len < 5 {
            buf[len] = byte[0];
            len = match len.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
    }

    let input = match std::str::from_utf8(&buf[..len]) {
        Ok(v) => v,
        Err(_) => return None,
    };

    match Port::from_str(input) {
        Ok(port) => Some(port),
        Err(_) => None,
    }
}

/// Prompts user for IP address interactively.
fn prompt_ipv4(prompt: &str, fallback: Ipv4) -> Ipv4 {
    println!("{}", prompt);
    let _ = stdout().flush();
    match read_ipv4_from_stdin() {
        Some(ip) => ip,
        None => {
            eprintln!("Invalid IP input. Falling back to default IP.");
            fallback
        }
    }
}

/// Prompts user for Port number interactively. Requires explicit valid port.
fn prompt_port(prompt: &str) -> Result<Port, TunnelError> {
    println!("{}", prompt);
    let _ = stdout().flush();
    match read_port_from_stdin() {
        Some(port) => Ok(port),
        None => {
            eprintln!("Error: A valid port number (1-65535) is required.");
            Err(TunnelError::ConfigInvalidPort)
        }
    }
}

/// Prompts user if they want to enter additional targets with a custom message.
fn prompt_add_another(prompt: &str) -> bool {
    print!("{}", prompt);
    let _ = stdout().flush();

    let mut buf = [0u8; 4];
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

        if len < 4 {
            buf[len] = byte[0];
            len = match len.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
    }

    len > 0 && (buf[0] == b'y' || buf[0] == b'Y')
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

        if len < 4 {
            buf[len] = byte[0];
            len = match len.checked_add(1) {
                Some(v) => v,
                None => break,
            };
        }
    }

    if len > 0 && buf[0] == b'2' {
        AppMode::Client
    } else {
        AppMode::Server
    }
}

/// Zero-heap CLI parser requiring explicit port flags.
fn parse_cli_args() -> Result<(AppMode, [Option<Endpoint>; MAX_TARGETS], usize), TunnelError> {
    let mut mode = AppMode::InteractivePrompt;
    let mut endpoints: [Option<Endpoint>; MAX_TARGETS] = [None, None, None, None];
    let mut count = 0usize;
    let mut current_port: Option<Port> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let bytes = arg.as_bytes();
        if bytes == b"--server" || bytes == b"-s" {
            mode = AppMode::Server;
        } else if bytes == b"--client" || bytes == b"-c" {
            mode = AppMode::Client;
        } else if bytes == b"--port" || bytes == b"-p" {
            if let Some(p_str) = args.next() {
                match Port::from_str(&p_str) {
                    Ok(p) => current_port = Some(p),
                    Err(e) => {
                        eprintln!(
                            "Error: Invalid port value '{}'. Must be between 1 and 65535.",
                            p_str
                        );
                        return Err(e);
                    }
                }
            } else {
                eprintln!("Error: Missing port value after '-p / --port' flag.");
                return Err(TunnelError::ConfigInvalidPort);
            }
        } else if let Ok(ip) = Ipv4::from_str(&arg) {
            if count < MAX_TARGETS {
                match current_port {
                    Some(p) => {
                        endpoints[count] = Some(Endpoint { ip, port: p });
                        count += 1;
                    }
                    None => {
                        eprintln!("Error: No port specified for IP address '{}'.", arg);
                        eprintln!(
                            "Usage: Specify port first using '-p <port>' before IP addresses."
                        );
                        return Err(TunnelError::ConfigInvalidPort);
                    }
                }
            }
        }
    }

    Ok((mode, endpoints, count))
}

// --- Main ---
fn main() {
    let (cli_mode, mut endpoints, mut endpoint_count) = match parse_cli_args() {
        Ok(parsed) => parsed,
        Err(e) => std::process::exit(e as i32),
    };

    let mode = if cli_mode == AppMode::InteractivePrompt {
        println!("Get IP");
        println!("Run: ip route get 1.2.3.4 | awk '{{print $7}}'");
        println!("or, 2->inet from: ip -4 addr");

        prompt_mode()
    } else {
        cli_mode
    };

    // If CLI provided no IP/Port flags, run mode-specific interactive prompts
    if endpoint_count == 0 {
        match mode {
            AppMode::Server => {
                let ip = prompt_ipv4(
                    "Enter local bind IPv4 address (default: 0.0.0.0):",
                    Ipv4::from_octets(0, 0, 0, 0),
                );
                let port = match prompt_port("Enter local listen port (1-65535):") {
                    Ok(p) => p,
                    Err(e) => std::process::exit(e as i32),
                };
                endpoints[0] = Some(Endpoint { ip, port });
                endpoint_count = 1;

                while endpoint_count < MAX_TARGETS
                    && prompt_add_another("Add another local listening port/address? [y/N]: ")
                {
                    let ip = prompt_ipv4(
                        "Enter additional local bind IPv4 address (default: 0.0.0.0):",
                        Ipv4::from_octets(0, 0, 0, 0),
                    );
                    let port = match prompt_port("Enter additional local listen port:") {
                        Ok(p) => p,
                        Err(e) => std::process::exit(e as i32),
                    };
                    endpoints[endpoint_count] = Some(Endpoint { ip, port });
                    endpoint_count += 1;
                }
            }
            AppMode::Client => {
                let ip = prompt_ipv4(
                    "Enter remote peer IPv4 address (default: 127.0.0.1):",
                    Ipv4::from_octets(127, 0, 0, 1),
                );
                let port = match prompt_port("Enter remote peer port (1-65535):") {
                    Ok(p) => p,
                    Err(e) => std::process::exit(e as i32),
                };
                endpoints[0] = Some(Endpoint { ip, port });
                endpoint_count = 1;

                while endpoint_count < MAX_TARGETS
                    && prompt_add_another("Add another remote peer (IP/Port)? [y/N]: ")
                {
                    let ip = prompt_ipv4(
                        "Enter additional remote peer IPv4 address:",
                        Ipv4::from_octets(127, 0, 0, 1),
                    );
                    let port = match prompt_port("Enter additional remote peer port:") {
                        Ok(p) => p,
                        Err(e) => std::process::exit(e as i32),
                    };
                    endpoints[endpoint_count] = Some(Endpoint { ip, port });
                    endpoint_count += 1;
                }
            }
            AppMode::InteractivePrompt => {
                let _ = Unreachable();
                std::process::exit(TunnelError::ConfigInvalidArgs as i32);
            }
        }
    }

    let key = 0x5Au8; // Simple initial key byte for stream XOR cipher MVP

    let result = match mode {
        AppMode::Server => run_server(&endpoints, endpoint_count, key),
        AppMode::Client => run_client(&endpoints, endpoint_count, key),
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
            Ipv4::from_str("192.168.1.1").unwrap(),
            Ipv4::from_octets(192, 168, 1, 1)
        );
        assert_eq!(
            Ipv4::from_str("0.0.0.0").unwrap(),
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
    fn test_port_validation_and_parsing() {
        assert!(Port::_new(0).is_err());
        assert!(Port::_new(12345).is_ok());

        assert_eq!(Port::from_str("12345").unwrap(), Port(12345));
        assert_eq!(Port::from_str("8080").unwrap(), Port(8080));
        assert!(matches!(
            Port::from_str("0"),
            Err(TunnelError::ConfigInvalidPort)
        ));
        assert!(matches!(
            Port::from_str("70000"),
            Err(TunnelError::ConfigInvalidPort)
        ));
        assert!(matches!(
            Port::from_str("invalid"),
            Err(TunnelError::ConfigInvalidPort)
        ));
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
