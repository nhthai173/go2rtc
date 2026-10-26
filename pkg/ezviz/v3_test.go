package ezviz

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func endMarker() V3Attr { return V3Attr{Tag: AttrEndMarker, Value: []byte{}} }

func TestCRC8Empty(t *testing.T) {
	if got := CRC8(nil); got != 0x00 {
		t.Errorf("CRC8(empty) = 0x%02x, want 0x00", got)
	}
}

func TestCRC8ServerVector(t *testing.T) {
	// Verified against a real P2P server response:
	//   e2020b030000000200000c23020400000003  (CRC at byte 11 = 0x23)
	// Here byte 11 is zeroed before computing.
	resp := mustHex(t, "e2020b030000000200000c00020400000003")
	if got := CRC8(resp); got != 0x23 {
		t.Errorf("CRC8(server vector) = 0x%02x, want 0x23", got)
	}
}

func TestHeaderEncoding(t *testing.T) {
	buf, err := EncodeV3Message(V3Message{
		MsgType: OpPlayRequest, SeqNum: 1, Mask: DefaultMask(),
		Attrs: []V3Attr{endMarker()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if buf[0] != V3Magic {
		t.Errorf("magic = 0x%02x, want 0x%02x", buf[0], V3Magic)
	}
	if buf[10] != V3HeaderLen {
		t.Errorf("headerLen = 0x%02x, want 0x%02x", buf[10], V3HeaderLen)
	}
}

func TestMsgTypeAndSeqBigEndian(t *testing.T) {
	buf, err := EncodeV3Message(V3Message{
		MsgType: 0x0c02, SeqNum: 0x12345678, Mask: DefaultMask(),
		Attrs: []V3Attr{endMarker()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if buf[2] != 0x0c || buf[3] != 0x02 {
		t.Errorf("msgType bytes = %02x%02x, want 0c02", buf[2], buf[3])
	}
	if !bytes.Equal(buf[4:8], []byte{0x12, 0x34, 0x56, 0x78}) {
		t.Errorf("seqNum bytes = % x, want 12 34 56 78", buf[4:8])
	}
}

func TestCRCSelfConsistent(t *testing.T) {
	buf, err := EncodeV3Message(V3Message{
		MsgType: OpP2PSetup, SeqNum: 7, Mask: DefaultMask(),
		Attrs: []V3Attr{endMarker()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	stored := buf[11]
	check := append([]byte{}, buf...)
	check[11] = 0
	if got := CRC8(check); got != stored {
		t.Errorf("recomputed CRC = 0x%02x, want stored 0x%02x", got, stored)
	}
}

func TestMaskBits(t *testing.T) {
	enc, _ := EncodeV3Message(V3Message{MsgType: 0x0c02, Mask: V3Mask{Encrypt: true, Is2BLen: true},
		Attrs: []V3Attr{endMarker()}}, nil)
	if enc[1]&0x80 != 0x80 {
		t.Errorf("encrypt bit not set: 0x%02x", enc[1])
	}
	if enc[1]&0x02 != 0x02 {
		t.Errorf("is2BLen bit not set: 0x%02x", enc[1])
	}

	si, _ := EncodeV3Message(V3Message{MsgType: 0x0c02, Mask: V3Mask{SaltIndex: 5, Is2BLen: true},
		Attrs: []V3Attr{endMarker()}}, nil)
	if (si[1]>>3)&7 != 5 {
		t.Errorf("saltIndex = %d, want 5", (si[1]>>3)&7)
	}
}

func TestMaskRoundTrip(t *testing.T) {
	m := V3Mask{Encrypt: true, SaltVersion: 1, SaltIndex: 7, ExpandHeader: true, Is2BLen: true}
	buf, err := EncodeV3Message(V3Message{MsgType: 0x0c02, Mask: m, Attrs: []V3Attr{endMarker()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeV3Message(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Mask != m {
		t.Errorf("mask round-trip = %+v, want %+v", dec.Mask, m)
	}
}

func TestStandardAttrsRoundTrip(t *testing.T) {
	buf, err := EncodeV3Message(V3Message{
		MsgType: OpPlayRequest, SeqNum: 1, Mask: DefaultMask(),
		Attrs: []V3Attr{
			{Tag: AttrBusType, Value: []byte{0x01}},
			{Tag: AttrChannelNo, Value: []byte{0x00, 0x01}},
			{Tag: AttrStreamType, Value: []byte{0x00}},
			endMarker(),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeV3Message(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Attrs) != 4 {
		t.Fatalf("got %d attrs, want 4", len(dec.Attrs))
	}
	if dec.Attrs[0].Tag != AttrBusType || !bytes.Equal(dec.Attrs[0].Value, []byte{0x01}) {
		t.Errorf("attr0 = %+v", dec.Attrs[0])
	}
	if dec.Attrs[1].Tag != AttrChannelNo || !bytes.Equal(dec.Attrs[1].Value, []byte{0x00, 0x01}) {
		t.Errorf("attr1 = %+v", dec.Attrs[1])
	}
}

func TestLargeData2ByteLen(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 300)
	buf, err := EncodeV3Message(V3Message{
		MsgType: OpTransforData, SeqNum: 10, Mask: V3Mask{Is2BLen: true},
		Attrs: []V3Attr{{Tag: AttrLargeData, Value: payload}, endMarker()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if buf[V3HeaderLen] != 0x07 {
		t.Errorf("tag at body start = 0x%02x, want 0x07", buf[V3HeaderLen])
	}
	if l := int(buf[V3HeaderLen+1])<<8 | int(buf[V3HeaderLen+2]); l != 300 {
		t.Errorf("encoded len = %d, want 300", l)
	}
	dec, err := DecodeV3Message(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Attrs[0].Value) != 300 || dec.Attrs[0].Value[0] != 0xab {
		t.Errorf("decoded large data len=%d first=0x%02x", len(dec.Attrs[0].Value), dec.Attrs[0].Value[0])
	}
}

func TestLargeData1ByteLen(t *testing.T) {
	payload := bytes.Repeat([]byte{0xcd}, 100)
	buf, err := EncodeV3Message(V3Message{
		MsgType: OpTransforData, SeqNum: 10, Mask: V3Mask{Is2BLen: false},
		Attrs: []V3Attr{{Tag: AttrLargeData, Value: payload}, endMarker()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if buf[V3HeaderLen] != 0x07 || buf[V3HeaderLen+1] != 100 {
		t.Errorf("tag/len = %02x %02x, want 07 64", buf[V3HeaderLen], buf[V3HeaderLen+1])
	}
	dec, err := DecodeV3Message(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Attrs[0].Value) != 100 {
		t.Errorf("decoded len = %d, want 100", len(dec.Attrs[0].Value))
	}
}

func TestStringAttrsRoundTrip(t *testing.T) {
	buf, err := EncodeV3Message(V3Message{
		MsgType: OpPlayRequest, SeqNum: 5, Mask: DefaultMask(),
		Attrs: []V3Attr{
			{Tag: AttrSessionKey, Value: []byte("abc123session")},
			{Tag: AttrStartTime, Value: []byte("2024-01-15T10:30:00Z")},
			{Tag: AttrStopTime, Value: []byte("2024-01-15T11:30:00Z")},
			endMarker(),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeV3Message(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := GetStringAttr(dec.Attrs, AttrSessionKey); !ok || s != "abc123session" {
		t.Errorf("session key = %q ok=%v", s, ok)
	}
	if s, ok := GetStringAttr(dec.Attrs, AttrStartTime); !ok || s != "2024-01-15T10:30:00Z" {
		t.Errorf("start time = %q ok=%v", s, ok)
	}
}

func TestIntAttrsRoundTrip(t *testing.T) {
	buf, err := EncodeV3Message(V3Message{
		MsgType: OpTeardown, SeqNum: 99, Mask: DefaultMask(),
		Attrs: []V3Attr{
			{Tag: AttrStreamSession, Value: []byte{0xde, 0xad, 0xbe, 0xef}},
			{Tag: AttrDeviceSession, Value: []byte{0x00, 0x01, 0x02, 0x03}},
			endMarker(),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeV3Message(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := GetIntAttr(dec.Attrs, AttrStreamSession); !ok || v != 0xdeadbeef {
		t.Errorf("stream session = 0x%x ok=%v", v, ok)
	}
	if v, ok := GetIntAttr(dec.Attrs, AttrDeviceSession); !ok || v != 0x00010203 {
		t.Errorf("device session = 0x%x ok=%v", v, ok)
	}
}

func TestPlayRequestRoundTrip(t *testing.T) {
	buf, err := EncodeV3Message(V3Message{
		MsgType: OpPlayRequest, SeqNum: 42, Mask: DefaultMask(),
		Attrs: []V3Attr{
			{Tag: AttrBusType, Value: []byte{0x01}},
			{Tag: AttrSessionKey, Value: []byte("L38239367")},
			{Tag: AttrStreamType, Value: []byte{0x00}},
			{Tag: AttrChannelNo, Value: []byte{0x00, 0x01}},
			{Tag: AttrStreamSession, Value: []byte{0x00, 0x00, 0x23, 0x28}}, // 9000
			endMarker(),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeV3Message(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec.MsgType != OpPlayRequest || dec.SeqNum != 42 {
		t.Errorf("msgType=0x%04x seq=%d", dec.MsgType, dec.SeqNum)
	}
	if len(dec.Attrs) != 6 {
		t.Fatalf("got %d attrs, want 6", len(dec.Attrs))
	}
	if s, _ := GetStringAttr(dec.Attrs, AttrSessionKey); s != "L38239367" {
		t.Errorf("session key = %q", s)
	}
	if v, _ := GetIntAttr(dec.Attrs, AttrStreamSession); v != 9000 {
		t.Errorf("stream session = %d, want 9000", v)
	}
	if v, _ := GetIntAttr(dec.Attrs, AttrBusType); v != 1 {
		t.Errorf("bus type = %d, want 1", v)
	}
	if v, _ := GetIntAttr(dec.Attrs, AttrChannelNo); v != 1 {
		t.Errorf("channel = %d, want 1", v)
	}
}

func TestTeardownRoundTrip(t *testing.T) {
	buf, err := EncodeV3Message(V3Message{
		MsgType: OpTeardown, SeqNum: 100, Mask: DefaultMask(),
		Attrs: []V3Attr{
			{Tag: AttrSessionKey, Value: []byte("sess_key_123")},
			{Tag: AttrBusType, Value: []byte{0x02}},
			{Tag: AttrChannelNo, Value: []byte{0x00, 0x03}},
			{Tag: AttrStreamType, Value: []byte{0x01}},
			{Tag: AttrDeviceSession, Value: []byte{0x00, 0x00, 0x00, 0x07}},
			endMarker(),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeV3Message(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec.MsgType != OpTeardown {
		t.Errorf("msgType = 0x%04x, want 0x0c04", dec.MsgType)
	}
	if v, _ := GetIntAttr(dec.Attrs, AttrDeviceSession); v != 7 {
		t.Errorf("device session = %d, want 7", v)
	}
}

func TestDecodeRejectsShort(t *testing.T) {
	if _, err := DecodeV3Message(make([]byte, 5), nil); err == nil {
		t.Error("expected error for short message")
	}
}

func TestDecodeRejectsBadMagic(t *testing.T) {
	buf := make([]byte, 14)
	buf[0] = 0xa2
	buf[10] = 0x0c
	if _, err := DecodeV3Message(buf, nil); err == nil {
		t.Error("expected error for bad magic")
	}
}

func TestDecodeRejectsBadCRC(t *testing.T) {
	buf, err := EncodeV3Message(V3Message{
		MsgType: OpP2PSetup, SeqNum: 1, Mask: DefaultMask(),
		Attrs: []V3Attr{endMarker()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	buf[11] ^= 0xff
	if _, err := DecodeV3Message(buf, nil); err == nil {
		t.Error("expected error for corrupted CRC")
	}
}

func TestGetStringAttrMissing(t *testing.T) {
	if _, ok := GetStringAttr(nil, 0x05); ok {
		t.Error("expected ok=false for missing tag")
	}
}

func TestGetIntAttrSizes(t *testing.T) {
	attrs := []V3Attr{
		{Tag: 0x01, Value: []byte{0x42}},
		{Tag: 0x02, Value: []byte{0x01, 0x00}},
		{Tag: 0x03, Value: []byte{0x00, 0x00, 0x01, 0x00}},
	}
	if v, _ := GetIntAttr(attrs, 0x01); v != 0x42 {
		t.Errorf("1-byte = %d", v)
	}
	if v, _ := GetIntAttr(attrs, 0x02); v != 256 {
		t.Errorf("2-byte = %d", v)
	}
	if v, _ := GetIntAttr(attrs, 0x03); v != 256 {
		t.Errorf("4-byte = %d", v)
	}
}

func TestGetIntAttrNonStandardSize(t *testing.T) {
	attrs := []V3Attr{{Tag: 0x01, Value: []byte{0x01, 0x02, 0x03}}}
	if _, ok := GetIntAttr(attrs, 0x01); ok {
		t.Error("expected ok=false for 3-byte value")
	}
}

func TestOpcodeConstants(t *testing.T) {
	cases := []struct {
		got, want uint16
		name      string
	}{
		{OpPlayRequest, 0x0c02, "PlayRequest"},
		{OpTeardown, 0x0c04, "Teardown"},
		{OpP2PSetup, 0x0b02, "P2PSetup"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = 0x%04x, want 0x%04x", c.name, c.got, c.want)
		}
	}
}

func TestAESBodyRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	buf, err := EncodeV3Message(V3Message{
		MsgType: OpPlayRequest, SeqNum: 3, Mask: V3Mask{Encrypt: true, Is2BLen: true},
		Attrs: []V3Attr{
			{Tag: AttrSessionKey, Value: []byte("secret")},
			endMarker(),
		},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if (len(buf)-V3HeaderLen)%16 != 0 {
		t.Fatalf("ciphertext not block-aligned: %d", len(buf)-V3HeaderLen)
	}
	dec, err := DecodeV3Message(buf, key)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := GetStringAttr(dec.Attrs, AttrSessionKey); !ok || s != "secret" {
		t.Errorf("decrypted session key = %q ok=%v", s, ok)
	}
}

func TestAESKnownVector(t *testing.T) {
	// AES-128-CBC, key=ASCII "0123456789abcdef", IV="01234567"+8 zeros,
	// plaintext "hello world v3!!" (16 bytes) with PKCS#7 padding.
	// Cross-checked against openssl enc -aes-128-cbc.
	got, err := aesEncrypt([]byte("hello world v3!!"), []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "1e1e156286288d471d4692cae99c529f2a6bdf16eb5d4227397bb27eed4272b7")
	if !bytes.Equal(got, want) {
		t.Errorf("aesEncrypt = %x, want %x", got, want)
	}
}
