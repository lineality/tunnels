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
Bytes 4 to 7: 4-byte POSIX Timestamp (for replay protection & order-sync)
Bytes 8 to 61: fixed-block 54 byte ASCII Payload (encoded)
Byte 63: Validation-byte / Checksum-byte 2: known value to check
Byte 63: Validation-byte / Checksum-byte 1: pearson hash of first 63 bytes (Q: which table state?)




v4: Two Table Pearson Pingpong Encoding:
- Remote-Collaborator Salt Array / "Secrete-Key"
- Novel system-entropy based Nonce
- per-block combination of secrete-key-array and Nonce
- Two Tables
- Table 1 initialized with:
initial_seed_key = secret-key-array + nonce
Initialize a 256-byte state table 'S1' using Fisher-Yates shuffle seeded by initial_seed_key

only one secrete-key-array needed:

seed_1 = secret-key-array + nonce
seed_2 = secret-key-array + nonce + bitwise NOT !seed_1

- posix: system entropy (/dev/urandom or OS time + CPU counters)

- selection of which two indices i & j to swap is calculated using running pointers.
Pointer i moves sequentially so every table position gets mutated.
Pointer j accumulates state and feedback from the data





Two-Table Ping-Pong Encoding and Table-Mutation:

1.  Two Tables (T_1 and T_2): Both 256-byte tables are pre-scrambled at packet
    start using the secret-key-array + nonce.
2.  Double Lookup: To encrypt a byte M:
      - Step A: Pass input through T_1 to get an intermediate byte X:
        X = T_1[\text{state} \oplus M]
      - Step B: Pass intermediate byte X through T_2 to get the ciphertext byte
        C: C = T_2[X]
3.  Cross-Mutation Feedback:
MVP-1 target is 2-swaps per byte, e.g. for a normal-short text of 55-bytes, 110/265 values are shuffled (applies to both tables).

      - The value X from Table 1 selects which elements to swap in Table 2.
      - The value C from Table 2 selects which elements to swap in Table 1.
Table 2 selects which elements to swap in Table 1.


Encode-Decode Flip:


...

Sender uses T_1 and T_2 to encrypt, and the Receiver uses inverse tables T_1^{-1} and T_2^{-1} to decrypt.

...


Mechanics: Sender vs. Receiver

Because T_1 and T_2 are lookup permutations, the Sender uses T_1 and T_2 to
encrypt, while the Receiver uses inverse tables T_1^{-1} and T_2^{-1} to
decrypt.

1. Packet Pre-Scrambling Phase (Both Sender and Receiver)

1.  Read/Write 4-byte nonce at Bytes 0..3 of the 64-byte packet.
2.  Generate seed_1 and seed_2.
3.  Pre-scramble T_1 (256 swaps using seed_1).
4.  Pre-scramble T_2 (256 swaps using seed_2).
5.  Build inverse tables T_1^{-1} and T_2^{-1} (takes 256 assignments:
    T_inv[T[i]] = i).

2. Sender Encoding Loop (Per ASCII Byte M)

For each plaintext byte M:

1.  Step A (Table 1 Lookup): X = T_1[{state} + M]
2.  Step B (Table 2 Lookup):
    C = T_2[X] \quad {(This is the ciphertext byte sent on the wire)}
3.  Step C (State Update): {state} = M
4.  Step D (Cross-Mutation Swaps):
      - Use X to perform 2 swaps in T_2.
      - Use C to perform 2 swaps in T_1.

3. Receiver Decoding Loop (Per Ciphertext Byte C)

When receiver reads C from the wire:

1.  Step A (Table 2 Inverse Lookup): X = T_2^{-1}[C]
2.  Step B (Table 1 Inverse Lookup): {Raw} = T_1^{-1}[X]
    M = {state} + {Raw} \quad {(Original ASCII byte recovered!)}
3.  Step C (State Update): {state} = M
4.  Step D (Cross-Mutation Swaps):
      - Use X to perform the same 2 swaps in T_2 (and update T_2^{-1}).
      - Use C to perform the same 2 swaps in T_1 (and update T_1^{-1}).


## design requirements:

1.  Zero Heap Allocation: Fixed 256-byte stack arrays ([u8; 256]) for
    T_1, T_2, T_1^{-1}, T_2^{-1}.

2.  Independed Packets are Resilient to Packet Loss:
    Every 64-byte UDP packet re-seeds T_1 and T_2 from
    its own nonce. If Packet #3 is lost, Packet #4 still decrypts cleanly.

3.  High Diffusion: Double-stage non-linear mapping (T_1 -> T_2) makes
    known-plaintext attack equation-solving impossible even on
    short 10-character messages.



Kerckhoffs's Principle or Shannon's Maxim: "The enemy knows the system"

  - code is public
  - 4-byte nonce is sent in cleartext at Bytes 0..3 of each packet
  - secret that keeps the system secure is the secret-key-array

Making the key array larger directly increases the brute-force search
space


| Key Array Size                   | Bit Security | Search Space ($2^N$)                      | Quantum Resistance (Grover's)   |
| :------------------------------- | :----------- | :---------------------------------------- | :------------------------------ |
| **4 $\times$ `u32` (16 bytes)**  | 128-bit      | $2^{128} \approx 3.4 \times 10^{38}$      | 64-bit (Weak against quantum)   |
| **8 $\times$ `u32` (32 bytes)**  | **256-bit**  | **$2^{256} \approx 1.15 \times 10^{77}$** | **128-bit (Post-Quantum Safe)** |
| **16 $\times$ `u32` (64 bytes)** | 512-bit      | $2^{512} \approx 1.34 \times 10^{154}$    | 256-bit (Overkill)              |


mvp1 may use 8 bytes, but the system should be flexible to increase that to N size array as users choose

16 might be a better default / Nudge - the "tyranny of the default" where "temporary things end up becoming permanent".
