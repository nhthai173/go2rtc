package ezviz

import (
	"bytes"
	"testing"
)

// -- PS construction helpers (mirror the real NVR stream layout) --

func psPackHeader() []byte {
	// 00 00 01 BA + 10 bytes; low 3 bits of byte 13 = stuffing count (0 here).
	return []byte{0x00, 0x00, 0x01, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

// encodePTS is the inverse of parsePTS: it lays a 33-bit PTS into the 5-byte PES
// field with the marker bits set.
func encodePTS(pts uint64) []byte {
	return []byte{
		byte((pts>>30)&0x07)<<1 | 0x21,
		byte(pts >> 22),
		byte((pts>>15)&0x7F)<<1 | 0x01,
		byte(pts >> 7),
		byte(pts&0x7F)<<1 | 0x01,
	}
}

func psPES(streamID byte, es []byte, pts uint64) []byte {
	body := append([]byte{0x80, 0x80, 0x05}, encodePTS(pts)...)
	body = append(body, es...)
	pkt := []byte{0x00, 0x00, 0x01, streamID, byte(len(body) >> 8), byte(len(body))}
	return append(pkt, body...)
}

// nal builds an Annex-B HEVC NAL unit of the given type with a 4-byte start code.
func nal(nalType byte, payload ...byte) []byte {
	out := []byte{0x00, 0x00, 0x00, 0x01, nalType << 1, 0x01}
	return append(out, payload...)
}

const (
	hevcVPS  = 32
	hevcSPS  = 33
	hevcPPS  = 34
	hevcIDR  = 19
	hevcTRL  = 1
	pesVideo = 0xE0
	pesAudio = 0xC0
)

func TestParsePTSRoundTrip(t *testing.T) {
	// Include 33-bit values (>0xFFFFFFFF) to prove the full PTS width survives:
	// audio rescaling must see the untruncated value, not a 32-bit wrap.
	for _, pts := range []uint64{0, 1, 9000, 90000, 0x1FFFFFFF, 0xFFFFFFFF, 1 << 32, 0x1FFFFFFFF} {
		if got := parsePTS(encodePTS(pts)); got != pts {
			t.Errorf("parsePTS(encodePTS(%d)) = %d", pts, got)
		}
	}
}

func TestRescale(t *testing.T) {
	if got := rescale(90000, 90000, 8000); got != 8000 {
		t.Errorf("90 kHz->8 kHz: %d", got)
	}
	if got := rescale(0, 90000, 8000); got != 0 {
		t.Errorf("zero: %d", got)
	}
	// A 33-bit PTS must rescale from its full value, not a 32-bit truncation:
	// 0x1_0000_2710 (1<<32 + 10000) at 90 kHz -> 8 kHz.
	if got := rescale(1<<32+10000, 90000, 8000); got != uint32(uint64(1<<32+10000)*8000/90000) {
		t.Errorf("33-bit: %d", got)
	}
}

func TestSplitAnnexB(t *testing.T) {
	buf := append(nal(hevcVPS), nal(hevcSPS, 0xaa, 0xbb)...)
	nals := splitAnnexB(buf)
	if len(nals) != 2 {
		t.Fatalf("got %d NALs, want 2", len(nals))
	}
	if nalTypeOf(nals[0]) != hevcVPS || nalTypeOf(nals[1]) != hevcSPS {
		t.Errorf("types = %d, %d", nalTypeOf(nals[0]), nalTypeOf(nals[1]))
	}
	for _, n := range nals {
		if !bytes.HasPrefix(n, annexBStartCode) {
			t.Errorf("NAL missing start code: %x", n)
		}
	}
}

func TestPSDemuxerVideoAccessUnit(t *testing.T) {
	es := bytes.Join([][]byte{nal(hevcVPS), nal(hevcSPS), nal(hevcPPS), nal(hevcIDR, 0x99)}, nil)
	ps := append(psPackHeader(), psPES(pesVideo, es, 9000)...)

	d := newPSDemuxer()
	frames := d.write(ps)
	frames = append(frames, d.flush()...) // last AU flushes on stream end

	want := []byte{hevcVPS, hevcSPS, hevcPPS, hevcIDR}
	if len(frames) != len(want) {
		t.Fatalf("got %d frames, want %d", len(frames), len(want))
	}
	for i, f := range frames {
		if f.Codec != CodecH265 {
			t.Errorf("frame %d codec = %d", i, f.Codec)
		}
		if f.Timestamp != 9000 {
			t.Errorf("frame %d ts = %d, want 9000", i, f.Timestamp)
		}
		if nalTypeOf(f.Payload) != want[i] {
			t.Errorf("frame %d NAL type = %d, want %d", i, nalTypeOf(f.Payload), want[i])
		}
	}
}

func TestPSDemuxerAudio(t *testing.T) {
	samples := []byte{0x11, 0x22, 0x33, 0x44}
	ps := append(psPackHeader(), psPES(pesAudio, samples, 90000)...)

	d := newPSDemuxer()
	frames := d.write(ps)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	f := frames[0]
	if f.Codec != CodecPCMA || !bytes.Equal(f.Payload, samples) {
		t.Errorf("codec=%d payload=%x", f.Codec, f.Payload)
	}
	if f.Timestamp != 8000 { // 90 kHz PTS rescaled to the 8 kHz audio clock
		t.Errorf("ts = %d, want 8000", f.Timestamp)
	}
}

func TestPSDemuxerAccessUnitBoundary(t *testing.T) {
	au1 := append(nal(hevcVPS), nal(hevcIDR, 0x01)...)
	au2 := nal(hevcTRL, 0x02)
	ps := append(psPackHeader(), psPES(pesVideo, au1, 1000)...)
	ps = append(ps, psPES(pesVideo, au2, 4000)...)

	d := newPSDemuxer()
	frames := d.write(ps) // the second PTS closes AU1; AU2 waits for flush
	if len(frames) != 2 {
		t.Fatalf("after write got %d frames, want 2 (AU1)", len(frames))
	}
	if frames[0].Timestamp != 1000 || frames[1].Timestamp != 1000 {
		t.Errorf("AU1 timestamps = %d, %d", frames[0].Timestamp, frames[1].Timestamp)
	}
	rest := d.flush()
	if len(rest) != 1 || rest[0].Timestamp != 4000 {
		t.Fatalf("AU2 = %+v", rest)
	}
}

// TestPSDemuxerProgramEndFlushes proves the in-band MPEG program-end code
// (00 00 01 B9) releases the final access unit through write() — no caller flush
// needed — so a recording's tail (or a one-AU window) is not dropped.
func TestPSDemuxerProgramEndFlushes(t *testing.T) {
	es := bytes.Join([][]byte{nal(hevcVPS), nal(hevcSPS), nal(hevcPPS), nal(hevcIDR, 0x99)}, nil)
	ps := append(psPackHeader(), psPES(pesVideo, es, 9000)...)
	ps = append(ps, 0x00, 0x00, 0x01, sidProgramEnd)

	frames := newPSDemuxer().write(ps)

	want := []byte{hevcVPS, hevcSPS, hevcPPS, hevcIDR}
	if len(frames) != len(want) {
		t.Fatalf("got %d frames, want %d", len(frames), len(want))
	}
	for i, n := range want {
		if nalTypeOf(frames[i].Payload) != n || frames[i].Timestamp != 9000 {
			t.Errorf("frame %d: type=%d ts=%d", i, nalTypeOf(frames[i].Payload), frames[i].Timestamp)
		}
	}
}

// TestPSDemuxerFragmented feeds the stream one byte per write() call: the result
// must match a single-shot parse, proving the buffer survives PES packets split
// across SRT packets (the real arrival pattern).
func TestPSDemuxerFragmented(t *testing.T) {
	es := bytes.Join([][]byte{nal(hevcVPS), nal(hevcSPS), nal(hevcPPS), nal(hevcIDR, 0x99)}, nil)
	ps := append(psPackHeader(), psPES(pesVideo, es, 9000)...)

	d := newPSDemuxer()
	var got []*Frame
	for i := 0; i < len(ps); i++ {
		got = append(got, d.write(ps[i:i+1])...)
	}
	got = append(got, d.flush()...)

	if len(got) != 4 {
		t.Fatalf("fragmented got %d frames, want 4", len(got))
	}
	for i, want := range []byte{hevcVPS, hevcSPS, hevcPPS, hevcIDR} {
		if nalTypeOf(got[i].Payload) != want {
			t.Errorf("frame %d type = %d, want %d", i, nalTypeOf(got[i].Payload), want)
		}
	}
}
