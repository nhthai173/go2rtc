package ezviz

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDeriveAuthBase(t *testing.T) {
	for in, want := range map[string]string{
		"https://apiivn.hik-connect.com": "https://vnauth.hik-connect.com",
		"https://apiieu.ezvizlife.com":   "https://euauth.ezvizlife.com",
	} {
		got, err := deriveAuthBase(in)
		if err != nil || got != want {
			t.Errorf("deriveAuthBase(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := deriveAuthBase("https://api.hik-connect.com"); err == nil {
		t.Error("expected error for a host without the apii<region> prefix")
	}
}

func TestSessionSign(t *testing.T) {
	jwt := "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"s":"abc123","aud":"u"}`)) + ".sig"
	if got, err := sessionSign(jwt); err != nil || got != "abc123" {
		t.Errorf("sessionSign = %q, %v", got, err)
	}
	if _, err := sessionSign("not-a-jwt"); err == nil {
		t.Error("expected error for a non-JWT session")
	}
}

func TestParseURLRelay(t *testing.T) {
	cfg, err := parseURL("hikconnect://a%40b.c:pw@api.hik-connect.com/FN123?channel=2&code=ABCDEF")
	if err != nil || !cfg.relay || cfg.code != "ABCDEF" || cfg.channel != 2 {
		t.Errorf("code= should select the relay: %+v, %v", cfg, err)
	}
	cfg, _ = parseURL("ezviz://a:pw@api.hik-connect.com/FN123")
	if cfg.relay {
		t.Error("plain URL must stay on direct P2P")
	}
}

func TestProtobufRoundTrip(t *testing.T) {
	b := appendVarintField(appendStringField(appendStringField(nil, 4, "ssn-1"), 7, "ysproto://h:1/x"), 1, 5302)
	f, err := readFields(b)
	if err != nil || f[1].n != 5302 || string(f[4].b) != "ssn-1" || string(f[7].b) != "ysproto://h:1/x" {
		t.Errorf("readFields = %+v, %v", f, err)
	}
	if _, err = readFields([]byte{0x22, 0x09, 'x'}); err == nil {
		t.Error("expected error for a truncated length-delimited field")
	}
}

func encryptECB(key, b []byte) {
	block, _ := aes.NewCipher(key)
	for i := 0; i+16 <= len(b); i += 16 {
		block.Encrypt(b[i:i+16], b[i:i+16])
	}
}

func TestDecryptNAL(t *testing.T) {
	key := make([]byte, 16)
	copy(key, "ABCDEF")
	block, _ := aes.NewCipher(key)

	clear := make([]byte, 2+5000)
	clear[0], clear[1] = 0x26, 0x01 // IDR_W_RADL
	for i := 2; i < len(clear); i++ {
		clear[i] = byte(i * 7)
	}

	enc := bytes.Clone(clear)
	encryptECB(key, enc[2:2+nalEncryptedPrefix])
	if bytes.Equal(enc, clear) {
		t.Fatal("test setup: encryption changed nothing")
	}

	decryptNAL(block, enc)
	if !bytes.Equal(enc, clear) {
		t.Error("decryptNAL did not restore the original NAL")
	}
}

// rtpPacket builds an RTP packet; ext adds the 0x4000 scrambled-payload marker.
func rtpPacket(pt byte, ts uint32, ext bool, payload []byte) []byte {
	b := make([]byte, 12)
	b[0], b[1] = 0x80, pt
	binary.BigEndian.PutUint32(b[4:], ts)
	if ext {
		b[0] |= 0x10
		b = append(b, 0x40, 0x00, 0x00, 0x02, 0x80, 0x06, 0x00, 0x01, 0x11, 0x21, 0x02, 0x01)
	}
	return append(b, payload...)
}

func vtmPacket(channel byte, code uint16, body []byte) []byte {
	h := make([]byte, 8)
	h[0], h[1] = vtmMagic, channel
	binary.BigEndian.PutUint16(h[2:], uint16(len(body)))
	binary.BigEndian.PutUint16(h[6:], code)
	return append(h, body...)
}

// TestRelayEndToEnd runs the client against a fake relay: VTM answers with a
// redirect to a "VTDU" (same listener), which accepts the stream and sends a
// fragmented scrambled NAL plus scrambled audio.
func TestRelayEndToEnd(t *testing.T) {
	key := make([]byte, 16)
	copy(key, "ABCDEF")

	// Scrambled HEVC slice NAL: 2-byte header + 100-byte body, split in two FUs.
	nal := make([]byte, 102)
	nal[0], nal[1] = 0x02, 0x01 // TRAIL_R
	for i := 2; i < len(nal); i++ {
		nal[i] = byte(i)
	}
	want := bytes.Clone(nal)
	encryptECB(key, nal[2:])

	audio := make([]byte, 320)
	for i := range audio {
		audio[i] = byte(i)
	}
	wantAudio := bytes.Clone(audio)
	encryptECB(key, audio)

	fu := func(start, end bool, data []byte) []byte {
		f := byte(1) // original NAL type 1
		if start {
			f |= 0x80
		}
		if end {
			f |= 0x40
		}
		return append([]byte{49 << 1, 0x01, f}, data...)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	go func() {
		// hop 1: VTM -> redirect
		c1, _ := ln.Accept()
		readVTM(bufio.NewReader(c1))
		rsp := appendVarintField(nil, 1, 5302)
		rsp = appendStringField(rsp, 5, "vtmkey")
		rsp = appendStringField(rsp, 7, "ysproto://"+addr+"/live?hop=2")
		c1.Write(vtmPacket(0, vtmStreamInfoRsp, rsp))
		c1.Close()

		// hop 2: VTDU -> success + media
		c2, _ := ln.Accept()
		br := bufio.NewReader(c2)
		_, _, req, _ := readVTM(br)
		if f, _ := readFields(req); string(f[2].b) != "vtmkey" {
			t.Errorf("redirect key not echoed: %q", f[2].b)
		}
		rsp = appendVarintField(nil, 1, 0)
		rsp = appendStringField(rsp, 4, "the-ssn")
		c2.Write(vtmPacket(0, vtmStreamInfoRsp, rsp))
		c2.Write(vtmPacket(vtmChanStream, 0x73ff, rtpPacket(rtpPayloadVideo, 9000, true, fu(true, false, nal[2:52]))))
		c2.Write(vtmPacket(vtmChanStream, 0x73ff, rtpPacket(rtpPayloadVideo, 9000, false, fu(false, true, nal[52:]))))
		c2.Write(vtmPacket(vtmChanStream, 0x73ff, rtpPacket(rtpPayloadAudio, 160, true, audio)))
		time.Sleep(time.Second)
		c2.Close()
	}()

	c := &relayClient{frames: make(chan *Frame, 8), done: make(chan struct{})}
	c.block, _ = aes.NewCipher(key)
	if err = c.connect("ysproto://" + addr + "/live?hop=1"); err != nil {
		t.Fatal(err)
	}
	if c.ssn != "the-ssn" {
		t.Errorf("ssn = %q", c.ssn)
	}
	go c.readLoop()
	defer c.Close()

	got := map[byte]*Frame{}
	for len(got) < 2 {
		f, err := c.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		got[f.Codec] = f
	}

	v := got[CodecH265]
	if !bytes.Equal(v.Payload, append([]byte{0, 0, 0, 1}, want...)) || v.Timestamp != 9000 {
		t.Errorf("video frame wrong: ts=%d payload=% x...", v.Timestamp, v.Payload[:12])
	}
	if a := got[CodecPCMU]; !bytes.Equal(a.Payload, wantAudio) || a.Timestamp != 160 {
		t.Errorf("audio frame wrong: ts=%d", a.Timestamp)
	}
}

func TestRelayEncryptedWithoutCode(t *testing.T) {
	c := &relayClient{frames: make(chan *Frame, 1), done: make(chan struct{}), conn: nopConn{}}
	err := c.handleRTP(rtpPacket(rtpPayloadVideo, 1, true, []byte{0x02, 0x01, 0xaa, 0xbb}))
	if err == nil {
		t.Fatal("expected an error asking for the verification code")
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

func TestPlaybackURL(t *testing.T) {
	r := &relayInfo{host: "h", port: 8554, token: "tk", biz: url.Values{"biz": {"2"}}}
	u, err := r.playbackURL(config{serial: "S", channel: 2, start: "2026-10-26T12:28:34", stop: "2026-10-26T12:29:10"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/playback?", "begin=20261026T122834Z", "end=20261026T122910Z", "serial=S", "chn=2", "tls=0", "lid="} {
		if !strings.Contains(u, want) {
			t.Errorf("%q missing %q", u, want)
		}
	}
}
