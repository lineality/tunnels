#### tunnels

# Tunnel 1: ascii_tunnel
- local-test demo only, not set up to be used over the internet
- a vanilla-Rust ascii-tunnel
- two terminals (or tmux split), one for outgoing text, one to receive
- no default ports (for security)
- multi-target support (text tunnel with multiple remote collaborators)
- default Q&A setup
- aims for low heap
- aims for careful mode & case handling

- aims to support: android, BSD-family, the windowses


## Command Line Usage

### Syntax

```bash
./tunnel [MODE] [-p PORT] [IP_ADDRESS...]
```

### Options & Flags

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| `-s` | `--server` | Run in **Server Mode** (binds local listening sockets). |
| `-c` | `--client` | Run in **Client Mode** (initiates connections to remote peers). |
| `-p <PORT>` | `--port <PORT>` | Sets the active port (`1–65535`). Must precede the IP address(es) it applies to. |
| `<IP_ADDRESS>` | N/A | IPv4 address (`X.X.X.X`). Bound locally in Server mode, or targeted in Client mode. |

> **Security Rule**: There is **no default port**. You must specify a port using `-p <PORT>` before providing an IP address. Passing an IP address without a preceding `-p` flag will result in an error.

---

## Examples

### 1. Client Mode Examples

* **Connect to single remote server:**
  ```bash
  ./tunnel -c -p 8080 192.168.1.10
  ```

* **Connect to multiple remote servers on one port:**
  ```bash
  ./tunnel -c -p 8080 10.0.0.1 10.0.0.2 10.0.0.3
  ```

* **Connect to multiple remote servers on separate ports:**
  ```bash
  ./tunnel -c -p 8080 10.0.0.1 -p 9090 10.0.0.2
  ```


### 2. Server Mode Examples

* **Listen on local port 9000 across all interfaces:**
  ```bash
  ./tunnel -s -p 9000 0.0.0.0
  ```

* **Listen on multiple local interfaces/ports simultaneously:**
  ```bash
  ./tunnel -s -p 8080 127.0.0.1 -p 9090 192.168.1.15
  ```



## Q&A Setup Helper Mode

If you run the executable without command line flags, an interactive prompt will guide you through setup:

```bash
./tunnel
```

### Example Q&A Guide:

1. **Select Execution Mode:**
   ```text
   Select Mode:
    [1] Server (Listen for incoming tunnel) -> you put in your IP & port
    [2] Client (Connect to remote peer) -> you put in the remote collaborator's IP and port
   Choice [1/2]: 2 -> scenareo where you pick option 2
   ```

2. **Configure Remote Peer & Mandatory Port:**
   ```text
   Enter remote peer IPv4 address (default: 127.0.0.1):
   192.168.1.50
   Enter remote peer port (1-65535):
   8080
   ```

3. **Optionally Add Additional Targets:**
   ```text
   Add another remote peer (IP/Port)? [y/N]: y
   Enter additional remote peer IPv4 address:
   192.168.1.51
   Enter additional remote peer port:
   8081
   ```



## Error Codes

The binary exits with specific non-zero error codes on failure:

| Error Code | Error Variant | Cause |
| :---: | :--- | :--- |
| `1` | `SocketBindFailed` | Local address or port is already in use or restricted. |
| `2` | `SocketConnectFailed` | Remote peer refused connection or host is unreachable. |
| `100` | `ConfigInvalidPort` | Port value is missing, `0`, or out of valid `1–65535` range. |
| `101` | `ConfigInvalidIp` | Invalid IPv4 address format. |
| `102` | `ConfigInvalidArgs` | Malformed CLI arguments or missing configuration. |



## Multi-Target Broadcasting Behavior

When multiple targets are configured (up to 4 max):
- **Outbound**: Any text typed into your terminal (`stdin`) is encrypted and broadcast to **all** connected endpoints simultaneously.
- **Inbound**: Any data received from **any** connected endpoint is decrypted and rendered immediately to your screen (`stdout`).
