package ezviz

// Codec IDs for a demuxed access unit. The Hik-Connect P2P stream carries
// HEVC for both main and sub channels on current firmware; H264 is kept for
// older/other models. Live audio is interleaved as G.711 A-law.
const (
	CodecH265 byte = iota + 1
	CodecH264
	CodecPCMA // G.711 A-law, 8 kHz mono — interleaved live audio
)

// Frame is one demuxed access unit handed up by the P2P transport (Client).
//
// For video (H265/H264) Payload is Annex-B (start-code prefixed): Hik-RTP/sub
// headers stripped and RFC 7798 fragmentation units (type 49) reassembled into
// whole NAL units; the producer converts it to AVCC before pushing into go2rtc.
// For audio (PCMA) Payload is the raw G.711 samples and Timestamp is the 8 kHz
// audio clock; the producer forwards it verbatim.
type Frame struct {
	Codec     byte
	Payload   []byte // video: Annex-B NAL units; audio: raw G.711 samples
	Timestamp uint32 // video: 90 kHz PTS; audio: 8 kHz sample clock
	FrameNo   uint32
}
