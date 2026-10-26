package ezviz

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func nalTypeOf(annexB []byte) byte { return (annexB[4] >> 1) & 0x3f }

func TestHikRTPExtractor_IgnoresNonVideoTypes(t *testing.T) {
	e := newHikRTPExtractor()

	// 0x807f = control packet (not video).
	ctrl := make([]byte, 64)
	binary.BigEndian.PutUint16(ctrl, 0x807f)

	if nals := e.process(ctrl); len(nals) != 0 {
		t.Fatalf("expected no NALs, got %d", len(nals))
	}
}

func TestHikRTPExtractor_SubHeaderVPS(t *testing.T) {
	e := newHikRTPExtractor()

	// 12B Hik-RTP + 13B sub-header (0x0d, 0x90 first, …) + VPS NAL.
	p := make([]byte, 12+13+4)
	binary.BigEndian.PutUint16(p, 0x8060)
	p[12] = 0x0d // sub-header marker
	p[13] = 0x90 // first fragment
	p[25] = 0x40 // VPS NAL type (32 << 1)
	p[26] = 0x01
	p[27] = 0x0c
	p[28] = 0x01

	nals := e.process(p)
	if len(nals) != 1 {
		t.Fatalf("expected 1 NAL, got %d", len(nals))
	}
	if !bytes.Equal(nals[0][:4], []byte{0, 0, 0, 1}) {
		t.Fatalf("missing Annex-B start code: %x", nals[0][:4])
	}
	if got := nalTypeOf(nals[0]); got != 32 {
		t.Fatalf("expected VPS (32), got %d", got)
	}
}

func TestHikRTPExtractor_NoSubHeader(t *testing.T) {
	e := newHikRTPExtractor()

	// 12B Hik-RTP + direct NAL data (no 0x0d sub-header).
	p := make([]byte, 12+4)
	binary.BigEndian.PutUint16(p, 0x8060)
	p[12] = 0x42 // SPS NAL type (33 << 1)
	p[13] = 0x01
	p[14] = 0x01
	p[15] = 0x60

	nals := e.process(p)
	if len(nals) != 1 {
		t.Fatalf("expected 1 NAL, got %d", len(nals))
	}
	if got := nalTypeOf(nals[0]); got != 33 {
		t.Fatalf("expected SPS (33), got %d", got)
	}
}

func TestHikRTPExtractor_LengthPrefixed(t *testing.T) {
	e := newHikRTPExtractor()

	// 12B Hik-RTP + 13B sub-header + length-prefixed NAL: 00 01 00 04 [4B VPS].
	p := make([]byte, 12+13+8)
	binary.BigEndian.PutUint16(p, 0x8060)
	p[12] = 0x0d // sub-header
	p[13] = 0x90 // first fragment
	p[25] = 0x00 // length-prefix type
	p[26] = 0x01 // type counter
	p[27] = 0x00 // length high
	p[28] = 0x04 // length low (4 bytes)
	p[29] = 0x40 // VPS data
	p[30] = 0x0e
	p[31] = 0x48
	p[32] = 0x4b

	nals := e.process(p)
	if len(nals) != 1 {
		t.Fatalf("expected 1 NAL, got %d", len(nals))
	}
	if len(nals[0]) != 4+4 { // 4 start code + 4 data
		t.Fatalf("expected 8 bytes, got %d", len(nals[0]))
	}
	if got := nalTypeOf(nals[0]); got != 32 {
		t.Fatalf("expected VPS (32), got %d", got)
	}
}

// buildFUPacket wraps raw NAL data (no sub-header) in a Hik-RTP video packet.
func buildFUPacket(nal []byte) []byte {
	p := make([]byte, 12+len(nal))
	binary.BigEndian.PutUint16(p, 0x8060)
	copy(p[12:], nal)
	return p
}

func TestHikRTPExtractor_FUStartEnd(t *testing.T) {
	e := newHikRTPExtractor()

	// FU start: PayloadHdr(type=49) + FU header(S=1, E=0, fuType=19=IDR).
	start := make([]byte, 20)
	start[0] = 0x62 // type 49 PayloadHdr byte 1
	start[1] = 0x01 // PayloadHdr byte 2
	start[2] = 0x93 // FU: S=1(0x80) | fuType=19(0x13) → 0x93
	for i := 3; i < len(start); i++ {
		start[i] = 0xaa
	}
	if out := e.process(buildFUPacket(start)); len(out) != 0 {
		t.Fatalf("FU start emitted early: %d", len(out))
	}

	// FU end: PayloadHdr(type=49) + FU header(S=0, E=1, fuType=19).
	end := make([]byte, 12)
	end[0], end[1] = 0x62, 0x01
	end[2] = 0x53 // FU: E=1(0x40) | fuType=19(0x13) → 0x53
	for i := 3; i < len(end); i++ {
		end[i] = 0xbb
	}
	out := e.process(buildFUPacket(end))

	if len(out) != 1 {
		t.Fatalf("expected 1 NAL, got %d", len(out))
	}
	if got := nalTypeOf(out[0]); got != 19 {
		t.Fatalf("expected IDR (19), got %d", got)
	}
	// start code(4) + reconstructed header(2) + start payload(17) + end payload(9).
	if len(out[0]) != 4+2+17+9 {
		t.Fatalf("expected %d bytes, got %d", 4+2+17+9, len(out[0]))
	}
}

func TestHikRTPExtractor_FUStartContEnd(t *testing.T) {
	e := newHikRTPExtractor()

	// Start (S=1, fuType=19).
	e.process(buildFUPacket([]byte{0x62, 0x01, 0x93, 0x11, 0x22, 0x33}))

	// Continuation (S=0, E=0).
	if out := e.process(buildFUPacket([]byte{0x62, 0x01, 0x13, 0x44, 0x55, 0x66})); len(out) != 0 {
		t.Fatalf("continuation emitted early: %d", len(out))
	}

	// End (S=0, E=1).
	out := e.process(buildFUPacket([]byte{0x62, 0x01, 0x53, 0x77, 0x88, 0x99}))
	if len(out) != 1 {
		t.Fatalf("expected 1 NAL, got %d", len(out))
	}
	if got := nalTypeOf(out[0]); got != 19 {
		t.Fatalf("expected IDR (19), got %d", got)
	}
	want := []byte{
		0x26, 0x01, // reconstructed IDR header
		0x11, 0x22, 0x33, // start payload
		0x44, 0x55, 0x66, // cont payload (FU header stripped)
		0x77, 0x88, 0x99, // end payload (FU header stripped)
	}
	if !bytes.Equal(out[0][4:], want) {
		t.Fatalf("payload mismatch: got %x want %x", out[0][4:], want)
	}
}

func TestHikRTPExtractor_DiscardsIncompleteFU(t *testing.T) {
	e := newHikRTPExtractor()

	// Start fragment (no end) — incomplete FU.
	e.process(buildFUPacket([]byte{0x62, 0x01, 0x93, 0xaa, 0xbb}))

	// PPS NAL triggers discard of the incomplete FU.
	out := e.process(buildFUPacket([]byte{0x44, 0x01, 0xe0, 0x76}))
	if len(out) != 1 {
		t.Fatalf("expected 1 NAL (PPS only), got %d", len(out))
	}
	if got := nalTypeOf(out[0]); got != 34 {
		t.Fatalf("expected PPS (34), got %d", got)
	}
}

func TestHikRTPExtractor_ConsecutiveFUs(t *testing.T) {
	e := newHikRTPExtractor()

	var all [][]byte
	// FU 1: IDR slice (fuType=19).
	all = append(all, e.process(buildFUPacket([]byte{0x62, 0x01, 0x93, 0x11}))...) // S=1
	all = append(all, e.process(buildFUPacket([]byte{0x62, 0x01, 0x53, 0x22}))...) // E=1
	// FU 2: TRAIL_R slice (fuType=1).
	all = append(all, e.process(buildFUPacket([]byte{0x62, 0x01, 0x81, 0x33}))...) // S=1
	all = append(all, e.process(buildFUPacket([]byte{0x62, 0x01, 0x41, 0x44}))...) // E=1

	if len(all) != 2 {
		t.Fatalf("expected 2 NALs, got %d", len(all))
	}
	if got := nalTypeOf(all[0]); got != 19 {
		t.Fatalf("expected IDR (19), got %d", got)
	}
	if got := nalTypeOf(all[1]); got != 1 {
		t.Fatalf("expected TRAIL_R (1), got %d", got)
	}
}

// audioPacket builds a live audio Hik-RTP packet: 12B header + 13B sub-header
// (0x0d, 0x80, 0x88=audio, …) + raw G.711 samples.
func audioPacket(samples []byte) []byte {
	rtp := make([]byte, subHeaderLen)
	rtp[0] = 0x0d
	rtp[1] = 0x80
	rtp[2] = audioSubType
	rtp = append(rtp, samples...)
	packet := append(make([]byte, hikRTPHeaderLen), rtp...)
	binary.BigEndian.PutUint16(packet, 0x8060)
	return packet
}

func TestExtractAudioPayload_StripsSubHeader(t *testing.T) {
	samples := []byte{0x65, 0xe5, 0x64, 0xe4}
	if out := extractAudioPayload(audioPacket(samples)); !bytes.Equal(out, samples) {
		t.Fatalf("got %x want %x", out, samples)
	}
}

func TestExtractAudioPayload_VideoReturnsNil(t *testing.T) {
	// A video sub-header (byte 2 != 0x88) must not be treated as audio.
	rtp := make([]byte, subHeaderLen+2)
	rtp[0] = 0x0d
	rtp[1] = 0x90
	packet := append(make([]byte, hikRTPHeaderLen), rtp...)
	binary.BigEndian.PutUint16(packet, 0x8060)
	if out := extractAudioPayload(packet); out != nil {
		t.Fatalf("expected nil for video packet, got %x", out)
	}
}

func TestProcess_SkipsAudio(t *testing.T) {
	// The video extractor must keep dropping audio so the NAL stream stays clean.
	e := newHikRTPExtractor()
	if nals := e.process(audioPacket([]byte{0x65, 0xe5, 0x64, 0xe4})); nals != nil {
		t.Fatalf("video extractor must skip audio, got %d NALs", len(nals))
	}
}

func TestExtractPlaybackPayload_StripsHeader(t *testing.T) {
	// 12B Hik-RTP header + MPEG-PS pack start (00 00 01 BA …).
	ps := []byte{0x00, 0x00, 0x01, 0xba, 0x44, 0x00, 0x04, 0x00}
	packet := append(make([]byte, 12), ps...)
	binary.BigEndian.PutUint16(packet, 0x8050)

	if out := extractPlaybackPayload(packet); !bytes.Equal(out, ps) {
		t.Fatalf("got %x want %x", out, ps)
	}
}

func TestExtractPlaybackPayload_DoesNotStripSubHeader(t *testing.T) {
	// A pack-header byte at offset 12 must survive — the live path would treat
	// 0x0d as a sub-header marker; playback must not.
	ps := []byte{0x0d, 0x00, 0x00, 0x01, 0xe0, 0x10, 0x00}
	packet := append(make([]byte, 12), ps...)
	binary.BigEndian.PutUint16(packet, 0x8060)

	if out := extractPlaybackPayload(packet); !bytes.Equal(out, ps) {
		t.Fatalf("got %x want %x", out, ps)
	}
}

func TestExtractPlaybackPayload_AllVideoTypes(t *testing.T) {
	for _, typ := range []uint16{0x8050, 0x8060, 0x8051} {
		packet := make([]byte, 12+4)
		binary.BigEndian.PutUint16(packet, typ)
		for i := 12; i < 16; i++ {
			packet[i] = 0xab
		}
		want := []byte{0xab, 0xab, 0xab, 0xab}
		if out := extractPlaybackPayload(packet); !bytes.Equal(out, want) {
			t.Fatalf("type %#x: got %x want %x", typ, out, want)
		}
	}
}

func TestExtractPlaybackPayload_IgnoresControl(t *testing.T) {
	ctrl := make([]byte, 64)
	binary.BigEndian.PutUint16(ctrl, 0x807f)
	if out := extractPlaybackPayload(ctrl); out != nil {
		t.Fatalf("expected nil, got %x", out)
	}
}

func TestExtractPlaybackPayload_IgnoresEmpty(t *testing.T) {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet, 0x8050)
	if out := extractPlaybackPayload(packet); out != nil {
		t.Fatalf("expected nil, got %x", out)
	}
}
