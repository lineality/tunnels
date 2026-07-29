# Pingpong Two-Table Encoding: UPD Protocol for a Minimal ASCII Packet Stream

## Configuration Guide (`tunnel.toml`)

By default, the application looks for a configuration file named **`tunnel.toml`** located in the **same directory as the executable binary**.

You can also specify a custom path using the `-f` / `--config` CLI flag:
```bash
./tunnel --config /path/to/custom_config.toml --self bob --peer alice
```

---

### TOML Key Naming Specification

Configurations use key prefixes formatted as `{NAME}_<KEY>`, where `{NAME}` represents an identity string (e.g., `bob`, `alice`).

| TOML Key | Format | Description | Example |
| :--- | :--- | :--- | :--- |
| `{NAME}_ip4` | String | IPv4 address (`0.0.0.0` for local listening, or peer IPv4) | `"192.168.1.50"` |
| `{NAME}_port` | Integer / String | UDP port number (`1–65535`) | `"8080"` or `8080` |
| `{NAME}_val` | Hex / Decimal | Static 1-byte validation check byte | `"0x44"` or `68` |
| `{NAME}_salt_1` .. `16` | Hex / Decimal | 16 $\times$ 32-bit secret key salts (512-bit total entropy) | `"0x0F1E2D3C"` |

> **Hex & Decimal Support:** Salt values (`salt_1..16`) and validation bytes (`val`) can be written in standard decimal (`12345678`) or hexadecimal format (`"0x12345678"`).

---

### Complete Example Configuration (`tunnel.toml`)

Below is a complete, production-ready `tunnel.toml` setup for two collaborators (**Bob** and **Alice**):

```toml
# ==============================================================================
# Local Identity: Bob
# ==============================================================================
bob_ip4 = "0.0.0.0"
bob_port = "8080"

# ==============================================================================
# Remote Collaborator: Alice
# ==============================================================================
alice_ip4 = "192.168.1.50"
alice_port = "8080"
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



# Notes:

Slim Ascii Tunnel Rust

### Goal/Specs
- UDP (because TCP is blocked)
- Encrypted
- Probably TCP
- ideally Rust standard Library
- Ascii Tunnel Module
- two-terminal system to maintain robust simple functionality, separating input-buffer-locking from output-stream-display
- follow mode and case management (see below)
- stick with solid-primative ascii (utf-8 is out of scope)
- use safe and robust atomics, concurrency, parallelism e.g. from Mara Bos's 'Atomic Locks' book.
- focus on functional-primatives
- use rust struct-impl-enum to strictly custom-type parts of what is written-send and read-received.


(other features such as audio/video are theoretical future features or other projects)


TODO:
Current system (see below) ~works but uses TCP (so only works in LAN?)
use new 'fail and keep going' system with UDP.
order and lost-packets are fine.




TODO:
- convert TCP-POC below to updated UPD system
- pick/make new UPD protocol: "PingPong Two-Table Pearson Encoding"
- check the 'cryptographic' thresholds of using a pearson-salt-hash-encoding system
- Remove bloat, if any, from code base
- maybe add udp ipv6











## Proposed systems for UPD (currently two under consideration)

an-OPT has the advantage of using OTP, but it has the baggage of having many moving parts.


The "PingPong Two-Table Pearson Encoding" system (for example with a timestamp added to the encoded string) allows for a much more streamlined system.

## Steps that a receiver can use to check and if not ok at any step reject a packet:
The receiver check checklist:
1. fixed known size (if not ok, reject) always 64 bytes total
2. (after decoding) validation-bytes at end of block (various systems, see below) (if not ok, reject)
3. timestamp near front of packet (bytes 4-7) invalid (e.g. future), stale, or hashed-in-memory old timestamp (i32 or i64) (if not ok, reject)
4. Contents must be valid ascii bytes (if not ok, reject)

(note: during encoding the timestamp could also be reversed so that there is less of an issue of messages always starting with 'dear commander' the same way (e.g. not year-end being first and not changing often))

Where the process of pearson-hashing each byte is the process of decoding/decrypting the encoded contents from pingpong-encoding to ascii.









#### Bookend Validation:
For validation there can be bookend-bytes within the N-byte block of contents. e.g. 64-byte block

E.g.
1. start-bookend: inverted unix timestamp at the start (i64(future-proof) or i32(good enough for many cases)) (8 or 4 bytes)

2. first bookend: a single person-salt-hash of the entire original block (one byte)

3. final end-bookend: a static, or a dynamic, 'validation-byte' where the recipient know what that will be for that sender.
A. static: user has in their config that 044 is that users check-byte
B. dynamic: the 5th and 6th decimal-digit of the timestamp (roughly: day of the month) is run though that user's pearson-salt-array-hash, producing that day's 'recipient-known validation byte'
The functionality/feature/value of this bookend-byte is that this can be checked quickly as a disqualifier before any content is read, to minimize the chance of processing any potentially maliciously-crafted content.
(one byte)


The idea is that instead of using a single pearson-salt-hash to create an array of validation-values to be sent alongside encrypted text, the plan here is that the block of ascii characters that are sent are pre-processed and encoded in such a way that the salted-pearson-hash of each byte in turn will result in the decrypted values.


note for packet size:
Because this is an instant-messenger where most text is brief, there are some main factors:
1. How many bookend bytes there are (e.g. 10, post 2036 posix-time is 8 + 2 validation bytes), so 8 bytes per block is too small, and 16 bytes would be more than half-filler, but 64-bytes would be still a small-packet but have only 1/6th padding.
2. The average-size of a message-chunk given fixed-block-size. For example, google says a common/safe UDP packet-size is over a thousand bytes. But having a 1028 sized fixed block when people are typing "Lunch?" "Yes!" "where!" "Cafe?" "ok!" would be very wasteful.
This is admittedly approximate, but The Google says: ~"A typical workplace chat message averages around 50 to 250 characters (roughly 10 to 40 words)." At a glance this looks good for 64 byte blocks (54 bytes of ascii), where small messages fit in one block, and large messages are easily chopped up.






```toml
# {NAME}'s ipv4 N.N.N.N
{}_ip4={}

# maybe {NAME}'s ipv6 ...
{}_ip6={}

# {NAME}'s port ...
{}_port={}

# {NAME}'s key/salt array items
{}_salt_1={}
{}_salt_2={}
{}_salt_3={}
{}_salt_4={}
{}_salt_5={}
{}_salt_6={}
{}_salt_7={}
{}_salt_8={}
{}_salt_9={}
{}_salt_10={}
{}_salt_11={}
{}_salt_12={}
{}_salt_13={}
{}_salt_14={}
{}_salt_15={}
{}_salt_16={}

# {NAME}'s validation byte(s) (potentially more than one)
{}_val={}
```

note:


To read the configuration file automatically without typing IPs, ports, and 16 raw hex salts manually each time, the application needs two identity names and a file location strategy:
Where is the config file?
Who am I? (self)

 To know which local IP/port to bind.
Who am I talking to? (peer)

 To know which remote IP, port, salt array, and validation byte to use for encryption/decryption.

(and there might be a bloom filter or hash-record etc. to block replay attacks?)

Since the pearson hash is created cumulatively, the source of last byte will be different each time.



idea:

using a 'old-posix-time' 4-byte timestamp as the first four bytes
of, e.g. a (for e.g.) 64-byte block packet,
could allow for a time-check and sequence-check for the packets (e.g. for replay-attack protection).

- 4: first is 4 byte nonce (which is not encoded)
- 8: then is inverted u64 timestamp (future proofed, and inverted for better starting-bytes novelty)
- 50: then standard block
- 2: then two check-bytes



note: according to The Google
"A normal and safe size for a UDP packet payload is 1,400 to 1,450 bytes to prevent network fragmentation"

So 64 or even 128 is not 'huge' as UDP packets go.



slow-moving-item: notes, maybe not for mvp-1
the 5th and 6th digit of a posix-timestamp will change the day-of-the-month in the timestamp
with maybe some edge cases around next-day boundaries (e.g. sent a second before the day change, received a second after)
this could be useful for something, such as a non-static validation/check byte at the end





#### Disambiguation of 'stream';

In terms of stream, for UDP there is no guarantee of sequence.

so 'stream' here might mean either of two things:

1. UDP byte stream:
- some packets will be lost
- some packets will be received in a sequence not the sent-sequence
- some packets will be damaged

Because UDP packets can be dropped, duplicated, or arrive out of order, 'cryptographic state' must be stateless across packets: each 64-byte packet must be self-contained

2. byte-stream for encoding the byte-block within a given packet

1. Pearson Salt Array: size N (maybe 4, maybe 256)
2. Initial Pearson Table: size 256
3. Starting Nonce (or IV: Initialization Vector)
4. Dynamic Use of Salts (not (re)used in the same static way): State Machine / Stream Cipher
5. Dynamic Changes to Pearson-Table: Dynamic S-Box / State Permutation, e.g. after (depending on) each byte, N position-pairs in table are swapped
6. Interconnect about items (perhaps related to RC4).


...


1. Packet Structure (e.g., 64 bytes total):
Bytes 0 to 3: 4-byte random noise nonce (how to generate...?)
Bytes 4 to 7: 4-byte unsigned POSIX Timestamp (for replay protection & order-sync)
Bytes 8 to 61: fixed-block 54 byte ASCII Payload (encoded)
Byte 63: Validation-byte / Checksum-byte 2: known value to check
Byte 63: Validation-byte / Checksum-byte 1: pearson hash of first 63 bytes (Q: which table state?)




v5: Two Table Pearson Pingpong Encoding:

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
- mutation of the table through the process
- using the last-byte as additional feedback

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
