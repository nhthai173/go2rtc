# EZVIZ / Hik-Connect cloud P2P wire protocol

Self-contained reference for the protocol `pkg/ezviz` implements. It was
reverse-engineered from Hikvision's `libezstreamclient.so` and the iVMS-4200
desktop client with Ghidra, and validated against live packet captures from a
4K NVR. Opcodes and field tags below are exactly what the code emits and parses.

## V3 control protocol

The control plane ("V3") is a small binary request/response protocol carried in
UDP datagrams. Every message is a 12-byte header followed by an optional body of
TLV attributes (which may be AES-128-CBC encrypted).

### Header (12 bytes, big-endian multi-byte fields)

```
off  size  field
0    1     magic     high nibble 0xE; first byte emitted is 0xE2
1    1     mask      flag bitfield (see below)
2    2     msgType   opcode
4    4     seqNum    sequence number
8    2     reserved  protocol-version constant 0x6234
10   1     headerLen 0x0C (12); larger when an expand header is present
11   1     crc8      CRC-8 over the whole packet with this byte zeroed
12   ..    body      TLV attributes, optionally AES-128-CBC encrypted
```

### Mask byte

```
bit 7  encrypt        body is AES-128-CBC encrypted
bit 6  saltVersion
bit 5..3  saltIndex   3-bit server salt index
bit 2  expandHeader   an expand header follows the 12-byte base header
bit 1  is2BLen        tag 0x07 attributes use a 2-byte length
bit 0  unused
```

### CRC-8

A custom Hikvision bitwise CRC-8 (not a standard polynomial). Computed over the
entire packet with byte 11 zeroed, then written back to byte 11. See `CRC8` in
`v3.go`; the test vectors in `v3_test.go` pin the exact output.

### TLV attributes

```
tag(1) len(1) value(len)                      # normal attributes
tag(0x07) len_be16(2) value(len)              # only when the is2BLen mask bit is set
```

### Encryption

When the encrypt mask bit is set the body is AES-128-CBC with a fixed IV of
`"01234567"` followed by 8 zero bytes (PKCS#7 padding). Two distinct keys are in
play, each used as its first 16 bytes; both are fetched from the cloud per
session and never hardcoded (see "Cloud bootstrap"):

- **P2P server key** — the account-level rotating key from `POST /api/p2p/configurations`.
  The server keeps eight salt-indexed keys and hands one back per call; the
  `saltIndex`/`saltVersion` echoed in the mask byte tell it which one we used, and
  any of the eight is accepted, so a freshly fetched pair always works. It
  encrypts the **outer** layer — P2P_SETUP (0x0B02) and the TRANSFOR_DATA (0x0B04)
  relay envelope.
- **Link key** — the per-device key: the first 32 ASCII characters of the KMS
  `secretKey` from the device pagelist. It encrypts the **inner** PLAY_REQUEST
  body (0x0C02), whether sent direct or wrapped in TRANSFOR_DATA.

### Expand header

When the mask's `expandHeader` bit is set, a TLV block sits between the 12-byte
base header and the (encrypted) body and `headerLen` grows to `0x0C + len(expand)`.
The inner PLAY_REQUEST carries one; it pins the key version and routes the
message:

```
tag   size  field
0x00  2     key version (big-endian; matches the KMS key version)
0x01  var   account user id (the JWT `aud` claim)
0x02  4     client id (big-endian; a client-side correlation id, not validated)
0x03  2     device channel (big-endian)
```

These tag numbers are exactly what the code emits; some reverse-engineering notes
label `0x00`/`0x01` the other way around — the bytes above are authoritative.

### Opcodes used by this implementation

| Opcode   | Name           | Role                                                        |
| -------- | -------------- | ----------------------------------------------------------- |
| `0x0B02` | P2P_SETUP      | Register our NAT-mapped address with a P2P server           |
| `0x0B03` | TRANSFOR_CTRL  | Server response carrying the device's stream port           |
| `0x0B04` | TRANSFOR_DATA  | Wrapper used to relay a control message through the server  |
| `0x0C00` | hole-punch req | Sent by the device to open the NAT path to us               |
| `0x0C01` | hole-punch rsp | Our reply (sent 10×) that completes the punch               |
| `0x0C02` | PLAY_REQUEST   | Start the stream (busType/channel/streamType/session)       |
| `0x0C04` | TEARDOWN       | Stop the stream                                             |

### Other opcodes seen in the protocol (not implemented)

These exist in `libezstreamclient.so` but are not needed for cloud streaming, so
the code does not define or send them. Kept here as a reverse-engineering
reference:

| Opcode   | Name            | Purpose (observed)                          |
| -------- | --------------- | ------------------------------------------- |
| `0x0B00` | TRANSFOR_SETUP  | Alternate setup variant                     |
| `0x0B05` | TRANSFOR_DATA2  | Alternate relay-data variant                |
| `0x0C07` | VOICE_TALK      | Two-way audio backchannel                   |
| `0x0C08` | CT_CHECK        | Capability/connection check                 |
| `0x0C0A` | STREAM_CTRL     | In-stream control (pause/seek family)       |
| `0x0C0B` | DATA_LINK       | Data-link negotiation                       |
| `0x0D00` | TRANSPARENT     | Transparent ISAPI passthrough               |
| `0x0D02` | TRANSPARENT2    | Transparent passthrough variant             |

The two SRT control subtypes `0x8003` (DATA_REF / NAK) and `0x8006` (SHORT_ACK /
ACK2) are likewise part of the dialect but are only ever received and ignored,
so they have no dedicated constant.

### Other attribute tags seen in the protocol (not used)

PLAY_REQUEST and the setup messages only populate the tags listed in `v3.go`.
The wider tag space observed during reverse engineering, for reference:

| Tag    | Name             | Tag    | Name             |
| ------ | ---------------- | ------ | ---------------- |
| `0x09` | CT_STEP          | `0x87` | DATA_LINK_VAL    |
| `0x0A` | CT_DATA          | `0x8D` | TRANSPARENT_EXT  |
| `0x79` | STREAM_INFO      | `0xAE` | EXT_PARAM1       |
| `0x7C` | STREAM_PARAM     | `0xAF` | EXT_PARAM2       |
| `0x80` | STREAM_CONTROL   | `0xB4` | OPT_META3        |
| `0x81` | VOICE_ENCODING   | `0xB5` | STREAM_FLAG      |
| `0xB6` | OPT_META4        | `0xB8` | SEARCH_EXT       |

## Cloud bootstrap (REST)

Before any P2P traffic, three HTTPS calls to the Hik-Connect account API resolve
everything the session needs — both encryption keys and the device's NAT-mapped
endpoint:

1. **Login** — `POST /v3/users/login/v2` with the account and the **lowercase hex
   MD5** of the password. Returns a session id (a JWT whose `aud` claim is the
   account user id) and the region API domain to use for the remaining calls.
2. **Device config** — `GET /v3/userdevices/v1/resources/pagelist?filter=P2P,KMS,CONNECTION`.
   Per device: the P2P server list, the KMS `secretKey` (its first 32 ASCII chars
   are the link key) and the CONNECTION entry (the device's NAT-mapped stream
   endpoint).
3. **P2P secret** — `POST /api/p2p/configurations`. The rotating account P2P
   server key, delivered as a decimal byte-array string (`"[12,34,…]"`, 32 signed
   bytes) plus its `saltIndex`/`version`.

This path uses plain HTTPS and an MD5 password digest only — there is no ECDH,
CAS-broker or certificate handshake (see "Deliberately out of scope").

## P2P session flow

```
1. P2P_SETUP (0x0B02) to every P2P server registers our NAT-mapped address
   (the server reads the source of our UDP packet, STUN-style — no public IP
   needed).
2. The 0x0B03 response carries the device's stream port; we pre-punch to it
   (the punch payload is a single 0x00 byte, sent five times).
3. The device sends a hole-punch request (0x0C00); we reply 0x0C01 ten times.
4. PLAY_REQUEST (0x0C02) is sent two ways (see "Transport mix" below).
5. The device opens an SRT connection and streams media; we ACK and reassemble.
```

### Error codes

A P2P server rejects P2P_SETUP with a status code when it cannot bring the
session up. The ones worth recognizing (received, not parsed by the code):

| Code       | Meaning                                                     |
| ---------- | ---------------------------------------------------------- |
| `0x101011` | device offline                                             |
| `0x101012` | device unavailable for P2P (server-side, before any punch) |
| `0x0E48`   | key-info mismatch                                          |
| `0x0E16`   | decrypt with empty key                                     |
| `0x0E4C`   | P2P-server decrypt failure                                 |

The `0x0Exx` range is key/crypto rejection — a stale or wrong P2P server
key/salt; fetch a fresh secret. The `0x1010xx` range is device availability, not
crypto.

### Transport mix: direct vs relayed

The media path is always **direct, hole-punched P2P** — once the NAT punch
completes, SRT media flows device → client over the punched UDP socket. There is
no TCP media-relay fallback in this implementation.

PLAY_REQUEST itself is sent on **two paths** for reliability:

- **Path A — direct:** PLAY_REQUEST (0x0C02) straight to the device over the
  punched socket.
- **Path B — relayed control:** the same request wrapped in a TRANSFOR_DATA
  (0x0B04) message addressed to the P2P server, which forwards it to the device.

Path B only relays the *control* message (a belt-and-suspenders so the device
still receives the play request if the first direct datagram is dropped). Media
never traverses the relay.

### PLAY_REQUEST wire structure

Path A is a single V3 message: 12-byte header + expand header + a body encrypted
with the **link key**. Path B wraps that whole inner message inside a
TRANSFOR_DATA (0x0B04) envelope encrypted with the **P2P server key**:

```
TRANSFOR_DATA (0x0B04) — P2P-server-key-encrypted body:
  tag 0x00  device serial      (routing)
  tag 0x07  inner V3 message   (2-byte length; the link-key-encrypted
                                PLAY_REQUEST above, header and all)
```

The inner PLAY_REQUEST body (link-key encrypted) carries: busType (0x76), session
key (0x05), stream type (0x78), channel (0x77), stream session (0x7e), a 4-byte
session/timeout value (0x7d), start/stop time (0x7a/0x7b), serial (0x83), a
session UUID (0xb2) and a millisecond timestamp (0xb3).

## Device SRT dialect

The device speaks a proprietary SRT variant: an induction → conclusion handshake,
then media data packets. The device sends an induction (handshake type 1, UDT
version 4); we answer with version 5, encryption none and the SRT magic `0x4a17`.
The device follows with a conclusion (handshake type `0xFFFFFFFF`) and we reply
with an HSRSP extension advertising SRT 1.4.1 (`0x00010401`). Media is never
SRT-encrypted (the handshake encryption field is 0).

It multiplexes **two SRT sub-sessions on one socket** —
a control sub-session (type `0x807f` keepalives) and the video sub-session — with
**independent sequence spaces**. ACKs must be routed by inner payload type so the
control sequence space cannot pollute the video flow-control window; mixing them
stalls the device's sender. See `handleSrtDataPacket` / `sendSrtAck` in
`session.go`.

## Media framing (Hik-RTP)

Media data packets carry a Hik-RTP framing layer. `hikrtp.go` strips the
Hik-RTP/sub headers and reassembles RFC 7798 fragmentation units (FU, NAL type
49) into Annex-B H.265 access units. Interleaved G.711 A-law (PCMA) audio is
demuxed onto a second track. Codec parameters are probed from the live stream.

## Live preview vs. recording playback (busType)

PLAY_REQUEST carries a `busType` attribute (`0x76`) selecting the source:

| busType | Source            | `AttrStartTime`/`AttrStopTime` (`0x7a`/`0x7b`) |
| ------- | ----------------- | ---------------------------------------------- |
| 1       | live preview      | a "today so far" date; live plays correctly with it (its effect on live is untested) |
| 2       | recording playback| the requested window, camera-local wall clock  |

The device also defines `busType` 3 (two-way talk) and 4 (a playback variant);
this implementation only uses 1 and 2.

The two modes also differ on the wire:

- **Live (busType=1)** streams Hik-RTP-framed H.265 NAL units (see above).
- **Playback (busType=2)** streams the recording as an **MPEG Program Stream**:
  each SRT data packet is the 12-byte Hik-RTP header followed by a raw PS
  fragment (no sub-header, no FU framing). Concatenating the fragments
  reconstructs the PS, which `mpegps.go` demuxes — pack/system/PSM headers,
  then PES packets (`0xE0`–`0xEF` H.265 video, `0xC0`–`0xDF` G.711 audio) — back
  into the same Annex-B + PCMA Frame stream the live path produces, so the
  Producer is unchanged. Video access units are delimited by the PES PTS.

### Playback transport control (not implemented)

This implementation streams the fixed `[start, stop]` window in one shot: there
is no pause, resume, seek or speed control. The device exposes a dedicated set of
in-stream playback-control opcodes for that, kept here as a reverse-engineering
reference:

| Opcode   | Name             | Purpose (observed)        |
| -------- | ---------------- | ------------------------- |
| `0x0C10` | PLAYBACK_PAUSE   | pause playback            |
| `0x0C12` | PLAYBACK_RESUME  | resume playback           |
| `0x0C14` | PLAYBACK_SEEK    | seek / set playback rate  |
| `0x0C16` | PLAYBACK_SEARCH  | search by time segment    |
| `0x0C18` | PLAYBACK_CTRL3   | further playback control  |

## Deliberately out of scope

These were reverse-engineered but are not part of this implementation's path:

- **ECDH / CAS-broker relay.** The vendor SDK can fall back to a VTM relay over an
  ECDH-negotiated, ChaCha20 + HMAC-SHA256 channel. This implementation is
  direct-P2P only and never relays media, so none of that crypto is needed; the
  account API path above uses plain HTTPS + an MD5 password digest.
- **Media-payload encryption.** When "stream encryption" is enabled on the NVR the
  device scrambles slice data (parameter sets stay in the clear) under a
  verification-code key schedule. This path assumes unencrypted media and does not
  carry that schedule.
