# Pingpong Two-Table Encoding: UPD Protocol for a Minimal ASCII Packet Stream

## Configuration Guide (`tunnel.toml`)

- By default, the application looks for a configuration file named `tunnel.toml` located in the **same directory as the executable binary.

- You can specify a custom path using the `-f` / `--config` CLI flag:
```bash
./tunnel --config /path/to/custom_config.toml --self bob --peer alice
```


### TOML Key Naming Specification

Keys are formatted as `{NAME}_<KEY>`, where `{NAME}` is a "handle" id string (e.g. `bob`, `alice`).

| TOML Key | Format | Description | Example |
| :--- | :--- | :--- | :--- |
| `{NAME}_ip4` | String | IPv4 address (`0.0.0.0` for local listening, or peer IPv4) | `"192.168.1.50"` |
| `{NAME}_port` | Integer / String | UDP port number (`1–65535`) | `"8080"` or `8080` |
| `{NAME}_val` | Hex / Decimal | Static 1-byte validation check byte | `"0x44"` or `68` |
| `{NAME}_salt_1` .. `16` | Hex / Decimal | 16 $\times$ 32-bit secret key salts (512-bit total entropy) | `"0x0F1E2D3C"` |

#### Hex & Decimal Support:
Salt values (`salt_1..16`) and validation bytes (`val`) can be written in standard decimal (`12345678`) or hexadecimal format (`"0x12345678"`).


### Complete Example Configuration (`tunnel.toml`)

Example `tunnel.toml` for Alice & Bob:

```toml
# ==============================================================================
# Bob
# ==============================================================================
bob_ip4 = "0.0.0.0"
bob_port = "12345"
bob_val = "0x11"

# Alice's 512-bit Secret Key Salts (16 x u32)
bob_salt_1  = "0x4F1E2D2E"
bob_salt_2  = "0x4B5A6978"
bob_salt_3  = "0x8796A5B4"
bob_salt_4  = "0xC3D2E1F0"
bob_salt_5  = "0x12345678"
bob_salt_6  = "0x9ABCDEF0"
bob_salt_7  = "0xFEDCBA98"
bob_salt_8  = "0x76543210"
bob_salt_9  = "0x00112233"
bob_salt_10 = "0x44556677"
bob_salt_11 = "0x8899AABB"
bob_salt_12 = "0xCCDDEEFF"
bob_salt_13 = "0xA1B2C3D4"
bob_salt_14 = "0xE5F60718"
bob_salt_15 = "0x29384756"
bob_salt_16 = "0x61728396"

# ==============================================================================
# Alice
# ==============================================================================
alice_ip4 = "192.168.1.50"
alice_port = "12345"
alice_val = "0x44"

# Alice's 512-bit Secret Key Salts (16 x u32)
alice_salt_1  = "0x0F1E2D3C"
alice_salt_2  = "0x4B5A6978"
alice_salt_3  = "0x8796A5B4"
alice_salt_4  = "0xC3D2E1F0"
alice_salt_5  = "0x12345678"
alice_salt_6  = "0x9ABCDEF0"
alice_salt_7  = "0xFEDCBA98"
alice_salt_8  = "0x76543210"
alice_salt_9  = "0x00112233"
alice_salt_10 = "0x44556677"
alice_salt_11 = "0x8899AABB"
alice_salt_12 = "0xCCDDEEFF"
alice_salt_13 = "0xA1B2C3D4"
alice_salt_14 = "0xE5F60718"
alice_salt_15 = "0x29384756"
alice_salt_16 = "0x61728394"
```

---

### How to Start the Tunnel

#### 1. Quick Launch via CLI Flags

* **Bob's Machine** (Binds local port using `bob`, encrypts/sends to `alice`):
  ```bash
  ./tunnel --self bob --peer alice
  ```

* **Alice's Machine** (Binds local port using `alice`, encrypts/sends to `bob`):
  ```bash
  ./tunnel --self alice --peer bob
  ```

* **Multi-Peer Target Broadcasting** (Bob sends to both Alice and Charlie):
  ```bash
  ./tunnel --self bob --peer alice --peer charlie
  ```

---

#### 2. Interactive Guide Mode

If you run the binary without command-line flags, the interactive setup will automatically resolve `tunnel.toml` alongside the binary and prompt for identity names:

```text
Enter TOML configuration file path [default: /etc/tunnels/tunnel.toml]:
Enter your local identity name in TOML (e.g., bob): bob
Enter target peer identity name in TOML (e.g., alice): alice
[Setup] Initialized tunnel for self 'bob' on 0.0.0.0:8080
[Tunnel] Bound UDP socket to 0.0.0.0:8080
[Tunnel] Registered target peer endpoint: 192.168.1.50:8080
```



# Pearson Pingpong Two Table Encoding (v5)

====================================================================
PINGPONG TWO-TABLE LOOP SPECIFICATION (54 Bytes, Position i = 0..53)
====================================================================
At a very high level this is like having a sender and receiver
use an inverted Pearson-table to encode/decode each byte
(which each byte is one ASCII character): look up the byte
in the table, quick-lookup, done. Simple, cheap, quick, clean.

This two-table system uses a few added mechanisms:
- two tables, with feedback between the tables
- salts (selected by a user)
- a nonce to begin the message
- a position-counter to give a novel-offset to the table
- mutation of the tables throughout the process
- using the last-byte as additional feedback state
- "bookend validation": timestamp up front and checksums behind

This turns the pearson-table into a streaming-cipher, while
still being computation cheap and relatively easy to maintain
and implement.


Local Variables:
  - prev_cipher_byte: u8 (Initialized to 0 before byte 0)
  - position_counter: usize             (Payload position counter, 0 to 53)


Sender: Encoding Loop (Per Plaintext Byte 'm'):

1. Calculate Table 1 Read Index:
   lookup_index_1 = (prev_cipher_byte ^ m ^ (position_counter as u8)) as usize

2. Double Lookup: (Table-2 lookup is simple)
   x = T1[lookup_index_1]
   c = T2[x as usize]     --> 'c' is the ciphertext byte written to packet[8 + position_counter]

3. Update Ciphertext Feedback:
   prev_cipher_byte = c   --> Saves 'c' to use in step 1 of the NEXT byte

4. Dynamic Table Swaps (2 Swaps in T2, 2 Swaps in T1):
   salt_val = (salts[position_counter & 15] & 0xFF) as u8
   - Mutate T2 using byte 'x' and 'salt_val'
   - Mutate T1 using byte 'c' and 'salt_val'


Receiver: Decoding Loop (Per Ciphertext Byte 'c' from packet[8 + position_counter]):

1. Double Inverse Lookup:
   x = T2_inv[c as usize]
   raw = T1_inv[x as usize]

2. Recover Plaintext Byte 'm':
   m = prev_cipher_byte ^ raw ^ (position_counter as u8)  --> 'm' is the original ASCII character

3. Update previous Ciphertext byte (a feedback mechanism):
   prev_cipher_byte = c   --> Saves 'c' to match sender state for the NEXT byte

4. Dynamic Table Swaps (Identical to Sender):
   salt_val = (salts[position_counter & 15] & 0xFF) as u8
   - Mutate T2 (and T2_inv) using byte 'x' and 'salt_val'
   - Mutate T1 (and T1_inv) using byte 'c' and 'salt_val'
