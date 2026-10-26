package ezviz

import "encoding/binary"

// Hik-RTP frame extractor — converts the P2P/SRT data payloads emitted by a
// Hikvision device into an H.265 Annex-B stream.
//
// The framing below was derived from pcap and live-capture analysis of the
// Hik-Connect cloud transport:
//
//   - A data payload starts with a 12-byte Hik-RTP header; the first two bytes
//     are the packet type (0x8060/0x8050/0x8051 carry video).
//   - After the header an optional 13-byte sub-frame header may follow
//     (0x0d + 4 variable bytes + an 8-byte sync pattern).
//   - After the sub-header is the NAL payload:
//   - VPS/SPS/PPS (NAL types 32-34): parameter sets.
//   - Slice data (NAL types 0-21): video frames.
//   - Length-prefixed frames (00 NN 00 LL [data]): Hikvision metadata.
//
// NAL type 49 is an HEVC Fragmentation Unit (FU) per RFC 7798:
//
//   - Structure: [2B PayloadHdr (type=49)] [1B FU header] [FU payload].
//   - FU header: S(1) | E(1) | FuType(6).
//   - S=1: start of a fragmented NAL, FuType holds the original NAL type.
//   - E=1: end of the fragmented NAL.
//   - S=0,E=0: continuation fragment.
//   - The original NAL header is reconstructed from the PayloadHdr plus FuType
//     on the start fragment; each FU (S=1 … E=1) yields one reassembled NAL.

const (
	hikRTPHeaderLen = 12
	subHeaderLen    = 13 // 0x0d + 4 bytes + 8-byte sync
	fuNALType       = 49
)

// annexBStartCode prefixes every emitted NAL unit.
var annexBStartCode = []byte{0x00, 0x00, 0x00, 0x01}

// isVideoPacketType reports whether a Hik-RTP type carries video payload, as
// opposed to 0x807f control keepalives or 0x0200 IMKH metadata.
func isVideoPacketType(t uint16) bool {
	return t == 0x8060 || t == 0x8050 || t == 0x8051
}

// extractPlaybackPayload returns the MPEG-PS fragment carried by a playback
// (busType=2) data packet. Recordings stream as an MPEG Program Stream split
// across SRT packets: each packet is the 12-byte Hik-RTP header followed by a
// raw PS fragment — no 13-byte sub-header and no NAL framing (that is the live
// path, which would mangle PS bytes). Concatenating these fragments in order
// reconstructs the PS byte stream for psDemuxer. Returns nil for control and
// empty packets.
func extractPlaybackPayload(payload []byte) []byte {
	if len(payload) <= hikRTPHeaderLen {
		return nil
	}
	if !isVideoPacketType(binary.BigEndian.Uint16(payload)) {
		return nil
	}
	return payload[hikRTPHeaderLen:]
}

// audioSubType marks an audio sub-frame in the Hik-RTP sub-header (byte 2).
const audioSubType = 0x88

// extractAudioPayload returns the raw audio samples (G.711 A-law) of an audio
// Hik-RTP packet, or nil if the packet is not audio. Audio shares the video
// packet types (0x8060/0x8050/0x8051) and the 13-byte sub-header layout, and is
// distinguished only by sub-header byte 2 == 0x88. hikRTPExtractor.process
// discards these so the video NAL stream stays clean; this surfaces them for
// the audio track.
func extractAudioPayload(payload []byte) []byte {
	if len(payload) <= hikRTPHeaderLen {
		return nil
	}
	if !isVideoPacketType(binary.BigEndian.Uint16(payload)) {
		return nil
	}
	rtp := payload[hikRTPHeaderLen:]
	if len(rtp) <= subHeaderLen || rtp[0] != 0x0d {
		return nil
	}
	switch rtp[1] & 0xf0 {
	case 0x80, 0x90, 0xa0, 0xd0:
	default:
		return nil
	}
	if rtp[2] != audioSubType {
		return nil
	}
	return rtp[subHeaderLen:]
}

// hikRTPExtractor reassembles whole H.265 NAL units from a sequence of Hik-RTP
// data payloads. It is stateful across packets to carry RFC 7798 FU fragments.
type hikRTPExtractor struct {
	fuFragments [][]byte
	fuNALHeader []byte
	fuComplete  bool // true only once the End fragment has been received
	nalCount    int
}

func newHikRTPExtractor() *hikRTPExtractor {
	return &hikRTPExtractor{}
}

// flush returns a completed-but-buffered FU NAL if one is pending, else nil. An
// incomplete FU (no End received) is discarded to prevent decoder corruption.
func (e *hikRTPExtractor) flush() [][]byte {
	defer e.resetFU()

	if len(e.fuFragments) == 0 || e.fuNALHeader == nil || !e.fuComplete {
		return nil
	}

	assembled := make([]byte, 0, len(e.fuNALHeader))
	assembled = append(assembled, e.fuNALHeader...)
	for _, f := range e.fuFragments {
		assembled = append(assembled, f...)
	}

	if nal := e.buildNAL(assembled); nal != nil {
		return [][]byte{nal}
	}
	return nil
}

func (e *hikRTPExtractor) resetFU() {
	e.fuFragments = nil
	e.fuNALHeader = nil
	e.fuComplete = false
}

// process consumes one raw P2P data payload and returns any complete Annex-B
// NAL units it produced (each start-code 00 00 00 01 prefixed). May return nil.
func (e *hikRTPExtractor) process(payload []byte) [][]byte {
	if len(payload) < 2 {
		return nil
	}

	// Only process video data packets (0x8060/0x8050/0x8051).
	if !isVideoPacketType(binary.BigEndian.Uint16(payload)) {
		return nil
	}

	// Strip the 12-byte Hik-RTP header.
	if len(payload) <= hikRTPHeaderLen {
		return nil
	}
	rtpPayload := payload[hikRTPHeaderLen:]

	// Detect and strip the sub-header: 0x0d + 4 variable bytes + 8-byte sync.
	dataStart := 0
	if rtpPayload[0] == 0x0d && len(rtpPayload) > subHeaderLen {
		subHigh := rtpPayload[1] & 0xf0
		if subHigh == 0x80 || subHigh == 0x90 || subHigh == 0xa0 || subHigh == 0xd0 {
			// Sub-header byte 2 == 0x88 marks an audio packet — skip it.
			if rtpPayload[2] == 0x88 {
				return nil
			}
			dataStart = subHeaderLen
		}
	}

	nalData := rtpPayload[dataStart:]
	if len(nalData) < 2 {
		return nil
	}

	return e.processNALUnit(nalData)
}

func (e *hikRTPExtractor) processNALUnit(data []byte) [][]byte {
	if len(data) < 2 {
		return nil
	}

	firstByte := data[0]
	nalType := (firstByte >> 1) & 0x3f

	var out [][]byte

	// Flush accumulated FU fragments when any non-FU NAL arrives.
	if nalType != fuNALType && e.fuNALHeader != nil {
		out = append(out, e.flush()...)
	}

	// Length-prefixed format: 00 NN 00 LL [LL bytes of NAL data].
	if firstByte == 0x00 && len(data) > 4 {
		offset := 0
		for offset+4 <= len(data) {
			if data[offset] != 0x00 {
				break
			}
			dataLen := int(binary.BigEndian.Uint16(data[offset+2:]))
			if dataLen <= 0 || offset+4+dataLen > len(data) {
				break
			}
			if nal := e.buildNAL(data[offset+4 : offset+4+dataLen]); nal != nil {
				out = append(out, nal)
			}
			offset += 4 + dataLen
		}
		return out
	}

	// Standard HEVC NAL types: slices (0-21), VPS (32), SPS (33), PPS (34),
	// SEI (35, 39-40).
	if nalType <= 21 || (nalType >= 32 && nalType <= 35) || nalType == 39 || nalType == 40 {
		if nal := e.buildNAL(data); nal != nil {
			out = append(out, nal)
		}
		return out
	}

	// NAL type 49: HEVC Fragmentation Unit (FU) per RFC 7798.
	// Structure: [2B PayloadHdr] [1B FU header: S|E|FuType] [FU payload].
	// Each FU (S=1 start … E=1 end) reassembles into one NAL unit.
	if nalType == fuNALType && len(data) >= 3 {
		fuHeader := data[2]
		isStart := (fuHeader >> 7) & 1
		isEnd := (fuHeader >> 6) & 1
		fuType := fuHeader & 0x3f

		if isStart != 0 {
			// Start of a new FU — discard any previous incomplete one.
			out = append(out, e.flush()...)
			// Reconstruct the original NAL header: preserve forbidden_zero_bit
			// and nuh_layer_id from the PayloadHdr, substitute the NAL type
			// from the FU header.
			origFirstByte := (data[0] & 0x81) | ((fuType << 1) & 0x7e)
			e.fuNALHeader = []byte{origFirstByte, data[1]}
			e.fuFragments = [][]byte{append([]byte(nil), data[3:]...)}
		} else {
			// Continuation/end: strip 3 bytes (2B PayloadHdr + 1B FU header).
			e.fuFragments = append(e.fuFragments, append([]byte(nil), data[3:]...))
		}

		if isEnd != 0 {
			e.fuComplete = true
			out = append(out, e.flush()...)
		}
		return out
	}

	// Other NAL types in the 48-63 range: pass through.
	if nalType >= 48 {
		if nal := e.buildNAL(data); nal != nil {
			out = append(out, nal)
		}
		return out
	}

	return out
}

// buildNAL validates a NAL unit and returns it prefixed with the Annex-B start
// code, or nil if it should be skipped.
func (e *hikRTPExtractor) buildNAL(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}

	// Validate the NAL type before emitting — skip obviously invalid data.
	// Valid H.265: types 0-40 (standard) + 48-63 (Hikvision custom/UNSPEC).
	// Skip type 0 with a zero second byte (likely padding/zero data).
	nalType := (data[0] >> 1) & 0x3f
	if nalType == 0 && data[1] == 0 {
		return nil
	}

	e.nalCount++

	annexB := make([]byte, 0, len(annexBStartCode)+len(data))
	annexB = append(annexB, annexBStartCode...)
	annexB = append(annexB, data...)
	return annexB
}
