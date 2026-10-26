# EZVIZ / Hik-Connect (cloud P2P)

Streams Hikvision / EZVIZ cameras and NVRs through the cloud using the proprietary
P2P protocol — no LAN access, port-forwarding, or RTSP required. Fills the gap
noted in the main README ("Hikvision — a lot of proprietary streaming
technologies"); the existing `isapi:` source is two-way-audio backchannel only.

**EZVIZ and Hik-Connect are the same Hikvision consumer cloud** (Hik-Connect is the
current name; EZVIZ the older/retail brand). One account and this one source cover
both — register the device in whichever app you have, then use the credentials here.

```yaml
streams:
  camera1: ezviz://ACCOUNT:PASSWORD@api.hik-connect.com/SERIAL?channel=1&subtype=main
```

- `ACCOUNT:PASSWORD` — Hik-Connect / EZVIZ account credentials
- `SERIAL` — device serial
- `channel` — 1-based channel (default `1`)
- `subtype` — `main` (full resolution) or `sub` (low-res substream) (default `main`)

`hikconnect:` and `ezviz:` are interchangeable aliases for the same source — use
whichever matches the app you registered the device in.

## Playback (recordings)

Add a `start` time to stream the device's recording instead of live preview —
the same pattern as the Milestone source, which switches to playback when given a
playback time:

```yaml
streams:
  lobby_replay: ezviz://ACCOUNT:PASSWORD@api.hik-connect.com/SERIAL?channel=1&start=2026-06-05T19:00:00&end=2026-06-05T19:01:00
```

- `start` — recording window start (required to enter playback). Accepts
  `2026-06-05T19:00:00`, `2026-06-05 19:00:00`, or RFC 3339.
- `end` — window end (**optional**). With `end`, the fixed `[start, end]` window
  is streamed. Without `end`, playback is **open-ended**: it streams from `start`
  through all recorded footage up to the live edge, then the stream ends. (Omit
  `end` only when you mean open-ended — there is no host-clock default, since the
  times are camera-local and the go2rtc host is often UTC under Docker.)

```yaml
streams:
  # open-ended: everything from 19:00 onward, up to the live edge
  lobby_since_7pm: ezviz://ACCOUNT:PASSWORD@api.hik-connect.com/SERIAL?channel=1&start=2026-06-05T19:00:00
```

Times are **camera-local** — they are sent to the device verbatim with no
timezone conversion, so use the wall-clock shown on the camera's own overlay.

The device sends no end-of-stream marker when a window finishes or playback
reaches the live edge — it simply stops. go2rtc detects that silence and ends the
stream cleanly (rather than hanging), so a fixed window plays its clip and then
the stream closes.

Recordings stream as HEVC over an MPEG Program Stream that this source demuxes
back into the same H.265 + G.711 tracks as live, so the `ffmpeg:` transcode
recipe below applies unchanged (point it at the playback stream).

## Discovery

You don't need to know serials or channel numbers up front. On the **Add** page the
"EZVIZ / Hik-Connect" wizard logs in to your account and lists every device,
channel, and stream quality as a ready-to-add source — each channel is offered at
both `main` and `sub` so you can pick the resolution per stream.

The same listing is available read-only at `GET /api/ezviz?account=…&password=…`
(optional `&host=…` for a non-default region). It only reads the account — nothing
about the account or devices is changed.

## Browser playback

The device streams HEVC (H.265). Browsers play H.264 over WebRTC/MSE but generally
not raw H.265, so for a browser-facing stream transcode to H.264 with an `ffmpeg:`
source — hardware-accelerated where available:

```yaml
streams:
  garage:      ezviz://ACCOUNT:PASSWORD@api.hik-connect.com/SERIAL?channel=4&subtype=main
  garage_h264: ffmpeg:garage#video=h264#audio=copy#hardware=cuda   # drop #hardware=cuda for software
```

Keep an `#audio=` directive: `ffmpeg:` drops audio without one. Which codec
depends on the player:

- **WebRTC** plays the interleaved G.711 (PCMA) track as-is, so `#audio=copy`
  works and avoids re-encoding.
- **MSE** (the default `stream.html` player in most browsers) cannot decode
  PCMA, so a `#audio=copy` stream plays silently there. Transcode to AAC with
  `#audio=aac` for an MSE-audible stream:

  ```yaml
  garage_mse: ffmpeg:garage#video=h264#audio=aac#hardware=cuda
  ```

The `ffmpeg:` source pulls its input over go2rtc's internal RTSP, so the `rtsp:`
module must stay enabled (it is by default).

## How it works

`pkg/ezviz` speaks the cloud P2P protocol end to end:

1. REST login to the Hik-Connect / EZVIZ account, fetch the per-session P2P
   secret and device routing config (credentials-only — no hardcoded keys).
2. `P2P_SETUP` against the cloud, UDP hole-punch to reach the device directly.
3. `PLAY_REQUEST` → SRT handshake → encrypted media.
4. De-frame Hik-RTP, reassemble fragmented NALs, and hand whole H.265 / H.264
   access units to go2rtc via the RAW path; codec parameters are probed from the
   live stream. Interleaved G.711 A-law audio is surfaced on a second track.

## Status

Verified end to end against real hardware (4K NVR): login → P2P → SRT → HEVC,
sustained live preview at full resolution, `main` and `sub` both working, with
interleaved G.711 (A-law / PCMA) audio.

### Transport mix tested

Media flowed over the **direct, hole-punched P2P path** in every verified run:
once the UDP hole-punch completes, SRT media goes device → client over the
punched socket. The client was behind a normal home/office NAT; testing a
symmetric-NAT setup did not force a different path for this device.

`PLAY_REQUEST` is sent on two paths for reliability — directly to the device and,
in parallel, wrapped in a `TRANSFOR_DATA` message relayed through the P2P server.
That relay carries only the *control* request as a belt-and-suspenders; **media
itself never traverses a relay**, and there is no TCP media-relay fallback in
this implementation. So "relayed" here means relayed control, not relayed video.

See `pkg/ezviz/PROTOCOL.md` for the full wire format and the direct-vs-relayed
breakdown.
