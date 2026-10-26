package ezviz

// V3 is the Hik-Connect/EZVIZ binary control protocol spoken over UDP between
// the client and the device during P2P_SETUP, hole-punch and PLAY_REQUEST. The
// wire format was reverse-engineered from Hikvision's libezstreamclient.so with
// Ghidra. See PROTOCOL.md in this package for the full specification.
//
// Frame layout (big-endian multi-byte fields):
//
//	off  size  field
//	0    1     magic   (high nibble 0xE)
//	1    1     mask    (flag bitfield, see V3Mask)
//	2    2     msgType (opcode)
//	4    4     seqNum
//	8    2     reserved
//	10   1     headerLen (always 0x0C)
//	11   1     crc8 (over the whole packet with this byte zeroed)
//	12   ..    body (TLV attributes, optionally AES-128-CBC encrypted)

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

const (
	// V3Magic is the value of the first packet byte. Only its high nibble
	// (0xE) is validated on decode.
	V3Magic byte = 0xe2
	// V3HeaderLen is the fixed control-message header length.
	V3HeaderLen = 12
)

// Opcodes (message types, big-endian at offset 2). Only the opcodes this
// implementation sends or handles are defined; PROTOCOL.md lists the wider set
// the device protocol defines.
const (
	OpP2PSetup      uint16 = 0x0b02
	OpTransforCtrl  uint16 = 0x0b03
	OpTransforData  uint16 = 0x0b04
	OpPunchRequest  uint16 = 0x0c00 // device -> client: hole-punch request
	OpPunchResponse uint16 = 0x0c01 // client -> device: hole-punch response
	OpPlayRequest   uint16 = 0x0c02
	OpTeardown      uint16 = 0x0c04
)

// Attribute tags (the T in the body TLVs). Only the tags this implementation
// emits or reads are defined; PROTOCOL.md documents the wider tag space.
const (
	AttrTransforData     byte = 0x00
	AttrExpandKeyVersion byte = 0x01
	AttrClientID         byte = 0x02
	AttrDeviceChannel    byte = 0x03
	AttrBusTypeEnc       byte = 0x04
	AttrSessionKey       byte = 0x05
	AttrSessionInfo      byte = 0x06
	AttrLargeData        byte = 0x07
	AttrBusType          byte = 0x76
	AttrChannelNo        byte = 0x77
	AttrStreamType       byte = 0x78
	AttrStartTime        byte = 0x7a
	AttrStopTime         byte = 0x7b
	AttrDeviceSessionAlt byte = 0x7d
	AttrStreamSession    byte = 0x7e
	AttrPortCount        byte = 0x82
	AttrStreamMeta       byte = 0x83
	AttrDeviceSession    byte = 0x84
	AttrOptMeta1         byte = 0xb2
	AttrOptMeta2         byte = 0xb3
	AttrEndMarker        byte = 0xff
)

// V3Attr is one body TLV: a single-byte tag and its raw value bytes.
type V3Attr struct {
	Tag   byte
	Value []byte
}

// V3Mask is the decoded form of the mask flag byte at offset 1.
type V3Mask struct {
	Encrypt      bool
	SaltVersion  byte // 1 bit
	SaltIndex    byte // 3 bits, selects one of 8 salt-indexed keys
	ExpandHeader bool
	Is2BLen      bool // tag 0x07 uses a 2-byte length when set
}

// V3Message is a decoded control message.
type V3Message struct {
	MsgType  uint16
	SeqNum   uint32
	Reserved uint16
	Mask     V3Mask
	Attrs    []V3Attr
}

// DefaultMask returns a mask with all flags off except Is2BLen, the common case.
func DefaultMask() V3Mask {
	return V3Mask{Is2BLen: true}
}

// Encode serializes the mask into its flag byte.
func (m V3Mask) Encode() byte {
	var b byte
	if m.Encrypt {
		b |= 1 << 7
	}
	b |= (m.SaltVersion & 1) << 6
	b |= (m.SaltIndex & 7) << 3
	if m.ExpandHeader {
		b |= 1 << 2
	}
	if m.Is2BLen {
		b |= 1 << 1
	}
	return b
}

// DecodeMask parses a mask flag byte.
func DecodeMask(b byte) V3Mask {
	return V3Mask{
		Encrypt:      b&0x80 != 0,
		SaltVersion:  (b >> 6) & 1,
		SaltIndex:    (b >> 3) & 7,
		ExpandHeader: b&0x04 != 0,
		Is2BLen:      b&0x02 != 0,
	}
}

// CRC8 is Hikvision's custom bitwise CRC-8 from libezstreamclient.so. It is not
// a standard polynomial CRC; the bit operations are reproduced exactly.
func CRC8(data []byte) byte {
	var crc uint
	for _, d := range data {
		x := uint(d^byte(crc)) & 0xff

		if x&1 != 0 {
			crc = 0x23
		} else {
			crc = 0
		}
		if x&2 != 0 {
			crc ^= 0x46
		}
		if x&4 != 0 {
			crc ^= 0x8c
		}

		tmp := crc >> 1
		if (crc^(x>>3))&1 != 0 {
			tmp = (crc >> 1) ^ 0x8c
		}

		crc = tmp >> 1
		if (tmp^(x>>4))&1 != 0 {
			crc = ((tmp >> 1) | 0x80) ^ 0x0c
		}

		tmp = crc >> 1
		if (crc^(x>>5))&1 != 0 {
			tmp = ((crc >> 1) | 0x80) ^ 0x0c
		}

		crc = tmp >> 1
		if (tmp^(x>>6))&1 != 0 {
			crc = ((tmp >> 1) | 0x80) ^ 0x0c
		}

		tmp = crc >> 1
		if (crc & 1) != (x >> 7) {
			tmp = ((crc >> 1) | 0x80) ^ 0x0c
		}

		crc = tmp
	}
	return byte(crc & 0xff)
}

// encodeAttrs serializes TLV attributes. Tag 0x07 carries a 2-byte length when
// is2BLen is set, every other tag uses a single length byte.
func encodeAttrs(attrs []V3Attr, is2BLen bool) []byte {
	var out []byte
	for _, a := range attrs {
		if a.Tag == AttrLargeData && is2BLen {
			hdr := make([]byte, 3)
			hdr[0] = a.Tag
			binary.BigEndian.PutUint16(hdr[1:], uint16(len(a.Value)))
			out = append(out, hdr...)
			out = append(out, a.Value...)
			continue
		}
		out = append(out, a.Tag, byte(len(a.Value)))
		out = append(out, a.Value...)
	}
	return out
}

// decodeAttrs parses TLV attributes out of a body buffer.
func decodeAttrs(buf []byte, is2BLen bool) []V3Attr {
	var attrs []V3Attr
	off := 0
	for off < len(buf) {
		tag := buf[off]

		// Tag 0xFF is either an end marker (length 0, terminates the list)
		// or a sub-TLV container (length > 0, e.g. in P2P_SETUP). The length
		// byte distinguishes them.
		if tag == AttrEndMarker && off+1 < len(buf) && buf[off+1] == 0 {
			attrs = append(attrs, V3Attr{Tag: tag, Value: []byte{}})
			break
		}

		if tag == AttrLargeData && is2BLen {
			if off+3 > len(buf) {
				break
			}
			n := int(binary.BigEndian.Uint16(buf[off+1:]))
			end := off + 3 + n
			if end > len(buf) {
				end = len(buf)
			}
			attrs = append(attrs, V3Attr{Tag: tag, Value: cloneBytes(buf[off+3 : end])})
			off = end
			continue
		}

		if off+2 > len(buf) {
			break
		}
		n := int(buf[off+1])
		end := off + 2 + n
		if end > len(buf) {
			end = len(buf)
		}
		attrs = append(attrs, V3Attr{Tag: tag, Value: cloneBytes(buf[off+2 : end])})
		off = end
	}
	return attrs
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// hikV3IV is the fixed AES IV for all V3 encryption: ASCII "01234567" followed
// by 8 zero bytes.
var hikV3IV = []byte{
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

const aesBlock = 16

// aesEncrypt applies AES-128-CBC with PKCS#7 padding. The key is the first 16
// bytes of the supplied key.
func aesEncrypt(body, key []byte) ([]byte, error) {
	if len(key) < aesBlock {
		return nil, fmt.Errorf("ezviz: v3 key too short: %d bytes", len(key))
	}
	block, err := aes.NewCipher(key[:aesBlock])
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(body)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, hikV3IV).CryptBlocks(out, padded)
	return out, nil
}

// aesDecrypt reverses aesEncrypt.
func aesDecrypt(body, key []byte) ([]byte, error) {
	if len(key) < aesBlock {
		return nil, fmt.Errorf("ezviz: v3 key too short: %d bytes", len(key))
	}
	if len(body) == 0 || len(body)%aesBlock != 0 {
		return nil, fmt.Errorf("ezviz: v3 ciphertext not block-aligned: %d bytes", len(body))
	}
	block, err := aes.NewCipher(key[:aesBlock])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, hikV3IV).CryptBlocks(out, body)
	return pkcs7Unpad(out)
}

func pkcs7Pad(b []byte) []byte {
	pad := aesBlock - len(b)%aesBlock
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	pad := int(b[len(b)-1])
	if pad == 0 || pad > aesBlock || pad > len(b) {
		return nil, fmt.Errorf("ezviz: invalid PKCS#7 padding: %d", pad)
	}
	for _, v := range b[len(b)-pad:] {
		if int(v) != pad {
			return nil, fmt.Errorf("ezviz: invalid PKCS#7 padding bytes")
		}
	}
	return b[:len(b)-pad], nil
}

// EncodeV3Message serializes a control message. When the mask's Encrypt flag is
// set and a non-nil key is supplied, the TLV body is AES-128-CBC encrypted.
func EncodeV3Message(msg V3Message, key []byte) ([]byte, error) {
	body := encodeAttrs(msg.Attrs, msg.Mask.Is2BLen)

	if msg.Mask.Encrypt && key != nil {
		enc, err := aesEncrypt(body, key)
		if err != nil {
			return nil, err
		}
		body = enc
	}

	full := make([]byte, V3HeaderLen+len(body))
	full[0] = V3Magic
	full[1] = msg.Mask.Encode()
	binary.BigEndian.PutUint16(full[2:], msg.MsgType)
	binary.BigEndian.PutUint32(full[4:], msg.SeqNum)
	binary.BigEndian.PutUint16(full[8:], msg.Reserved)
	full[10] = V3HeaderLen
	full[11] = 0x00 // CRC placeholder
	copy(full[V3HeaderLen:], body)

	full[11] = CRC8(full)
	return full, nil
}

// DecodeV3Message parses a control message, verifying the CRC and optionally
// decrypting the body when the Encrypt flag is set and a key is supplied.
func DecodeV3Message(buf []byte, key []byte) (V3Message, error) {
	var msg V3Message
	if len(buf) < V3HeaderLen {
		return msg, fmt.Errorf("ezviz: v3 message too short: %d bytes", len(buf))
	}
	if buf[0]>>4 != 0xe {
		return msg, fmt.Errorf("ezviz: invalid v3 magic: 0x%02x", buf[0])
	}

	mask := DecodeMask(buf[1])
	msgType := binary.BigEndian.Uint16(buf[2:])
	seqNum := binary.BigEndian.Uint32(buf[4:])
	reserved := binary.BigEndian.Uint16(buf[8:])
	headerLen := int(buf[10])

	storedCRC := buf[11]
	check := cloneBytes(buf)
	check[11] = 0x00
	if got := CRC8(check); got != storedCRC {
		return msg, fmt.Errorf("ezviz: crc8 mismatch: stored=0x%02x computed=0x%02x", storedCRC, got)
	}

	if headerLen > len(buf) {
		return msg, fmt.Errorf("ezviz: v3 headerLen %d exceeds packet %d", headerLen, len(buf))
	}
	body := buf[headerLen:]
	if mask.Encrypt && key != nil {
		dec, err := aesDecrypt(body, key)
		if err != nil {
			return msg, err
		}
		body = dec
	}

	msg = V3Message{
		MsgType:  msgType,
		SeqNum:   seqNum,
		Reserved: reserved,
		Mask:     mask,
		Attrs:    decodeAttrs(body, mask.Is2BLen),
	}
	return msg, nil
}

// GetStringAttr returns the first attribute with the given tag as a string, and
// ok=false if no such attribute exists.
func GetStringAttr(attrs []V3Attr, tag byte) (string, bool) {
	for _, a := range attrs {
		if a.Tag == tag {
			return string(a.Value), true
		}
	}
	return "", false
}

// GetIntAttr returns the first attribute with the given tag decoded as a
// big-endian unsigned integer. Only 1-, 2- and 4-byte values are supported;
// ok=false for a missing tag or any other length.
func GetIntAttr(attrs []V3Attr, tag byte) (uint32, bool) {
	for _, a := range attrs {
		if a.Tag != tag {
			continue
		}
		switch len(a.Value) {
		case 4:
			return binary.BigEndian.Uint32(a.Value), true
		case 2:
			return uint32(binary.BigEndian.Uint16(a.Value)), true
		case 1:
			return uint32(a.Value[0]), true
		default:
			return 0, false
		}
	}
	return 0, false
}
