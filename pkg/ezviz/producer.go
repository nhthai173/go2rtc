package ezviz

import (
	"fmt"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/h264"
	"github.com/AlexxIT/go2rtc/pkg/h264/annexb"
	"github.com/AlexxIT/go2rtc/pkg/h265"
	"github.com/pion/rtp"
)

// Producer streams a single channel from a Hik-Connect / EZVIZ device over the
// cloud P2P transport, emitting whole H.265/H.264 access units into go2rtc.
type Producer struct {
	core.Connection
	client   frameSource
	playback bool
}

// frameSource is a transport that yields demuxed access units: the direct P2P
// Client or the cloud relay.
type frameSource interface {
	ReadFrame() (*Frame, error)
	Close() error
	Protocol() string
	RemoteAddr() string
}

func NewProducer(rawURL string) (*Producer, error) {
	cfg, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}

	var client frameSource
	audio := &core.Codec{Name: core.CodecPCMA, ClockRate: 8000, PayloadType: 8}
	if cfg.relay {
		client, err = dialRelay(cfg)
		if !cfg.isPlayback() { // recordings carry A-law like P2P
			audio = &core.Codec{Name: core.CodecPCMU, ClockRate: 8000, PayloadType: 0}
		}
	} else {
		client, err = Dial(rawURL)
	}
	if err != nil {
		return nil, err
	}

	medias, err := probe(client, audio)
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	return &Producer{
		Connection: core.Connection{
			ID:         core.NewID(),
			FormatName: "ezviz",
			Protocol:   client.Protocol(),
			RemoteAddr: client.RemoteAddr(),
			Source:     rawURL,
			Medias:     medias,
			Transport:  client,
		},
		client:   client,
		playback: cfg.isPlayback(),
	}, nil
}

// probe reads frames until the video codec can be built from a complete set of
// in-band parameter sets (VPS+SPS+PPS for HEVC, SPS+PPS for H264). Each NAL
// arrives as its own single-NAL frame, so the sets are collected across frames;
// building the codec from a lone VPS/SPS would advertise an SDP fmtp missing
// sprop-sps/sprop-pps, which SDP-reliant RTSP/WebRTC consumers cannot decode.
func probe(client frameSource, audio *core.Codec) ([]*core.Media, error) {
	var vcodec *core.Codec

	paramSets := map[byte][]byte{}
	// joined returns the AVCC parameter sets concatenated in order once every
	// required NAL type has been seen, else nil.
	joined := func(types ...byte) []byte {
		var buf []byte
		for _, t := range types {
			ps, ok := paramSets[t]
			if !ok {
				return nil
			}
			buf = append(buf, ps...)
		}
		return buf
	}

	for vcodec == nil {
		f, err := client.ReadFrame()
		if err != nil {
			return nil, fmt.Errorf("ezviz: probe: %w", err)
		}
		if f == nil || len(f.Payload) < 5 {
			continue
		}

		buf := annexb.EncodeToAVCC(f.Payload)
		if len(buf) < 5 {
			continue
		}

		switch f.Codec {
		case CodecH265:
			switch t := h265.NALUType(buf); t {
			case h265.NALUTypeVPS, h265.NALUTypeSPS, h265.NALUTypePPS:
				paramSets[t] = buf
			}
			if ps := joined(h265.NALUTypeVPS, h265.NALUTypeSPS, h265.NALUTypePPS); ps != nil {
				vcodec = h265.AVCCToCodec(ps)
			}
		case CodecH264:
			switch t := h264.NALUType(buf); t {
			case h264.NALUTypeSPS, h264.NALUTypePPS:
				paramSets[t] = buf
			}
			if ps := joined(h264.NALUTypeSPS, h264.NALUTypePPS); ps != nil {
				vcodec = h264.AVCCToCodec(ps)
			}
		}
	}

	return []*core.Media{
		{
			Kind:      core.KindVideo,
			Direction: core.DirectionRecvonly,
			Codecs:    []*core.Codec{vcodec},
		},
		{
			// Live audio is interleaved as G.711 A-law. The codec is fixed, so
			// the media is advertised without probing; channels that send no
			// audio simply never produce packets on this track.
			Kind:      core.KindAudio,
			Direction: core.DirectionRecvonly,
			Codecs:    []*core.Codec{audio},
		},
	}, nil
}

func (p *Producer) Start() error {
	if p.playback {
		p.awaitConsumer()
	}
	keyed := false // a picture that starts mid-GOP is garbage until the next keyframe: drop slices before the first one
	for {
		f, err := p.client.ReadFrame()
		if err != nil {
			return err
		}
		if f == nil {
			continue
		}

		if !keyed && (f.Codec == CodecH265 || f.Codec == CodecH264) {
			if sc := startCodeLen(f.Payload); sc > 0 {
				b := f.Payload[sc]
				switch {
				case f.Codec == CodecH265 && (b>>1)&0x3f >= 16 && (b>>1)&0x3f <= 21, f.Codec == CodecH264 && b&0x1f == 5:
					keyed = true
				case f.Codec == CodecH265 && (b>>1)&0x3f < 32, f.Codec == CodecH264 && b&0x1f < 5:
					continue
				}
			}
		}

		var name string
		var payload []byte
		switch f.Codec {
		case CodecH265:
			name, payload = core.CodecH265, annexb.EncodeToAVCC(f.Payload)
		case CodecH264:
			name, payload = core.CodecH264, annexb.EncodeToAVCC(f.Payload)
		case CodecPCMA:
			name, payload = core.CodecPCMA, f.Payload // raw G.711, forwarded verbatim
		case CodecPCMU:
			name, payload = core.CodecPCMU, f.Payload
		default:
			continue
		}

		pkt := &core.Packet{
			Header:  rtp.Header{Timestamp: f.Timestamp, SequenceNumber: uint16(f.FrameNo)},
			Payload: payload,
		}

		for _, recv := range p.Receivers {
			if recv.Codec.Name == name {
				recv.WriteRTP(pkt)
				break
			}
		}
	}
}

// awaitConsumer holds a recording back until a consumer is attached and has had a
// moment to start playing. A recording starts streaming at its first keyframe as
// soon as it is opened, while live keeps producing keyframes; dropping that first
// keyframe would leave the picture black until the next one, seconds later.
// Frames wait in the transport's buffer meanwhile.
// ponytail: fixed grace period; a per-sender "playing" signal would be exact.
func (p *Producer) awaitConsumer() {
	for i := 0; i < 100; i++ {
		for _, r := range p.Receivers {
			if len(r.Senders()) > 0 {
				time.Sleep(time.Second)
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}
