package ezviz

import (
	"fmt"

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
	client *Client
}

func NewProducer(rawURL string) (*Producer, error) {
	client, err := Dial(rawURL)
	if err != nil {
		return nil, err
	}

	medias, err := probe(client)
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
		client: client,
	}, nil
}

// probe reads frames until the video codec can be built from a complete set of
// in-band parameter sets (VPS+SPS+PPS for HEVC, SPS+PPS for H264). Each NAL
// arrives as its own single-NAL frame, so the sets are collected across frames;
// building the codec from a lone VPS/SPS would advertise an SDP fmtp missing
// sprop-sps/sprop-pps, which SDP-reliant RTSP/WebRTC consumers cannot decode.
func probe(client *Client) ([]*core.Media, error) {
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
			Codecs:    []*core.Codec{{Name: core.CodecPCMA, ClockRate: 8000, PayloadType: 8}},
		},
	}, nil
}

func (p *Producer) Start() error {
	for {
		f, err := p.client.ReadFrame()
		if err != nil {
			return err
		}
		if f == nil {
			continue
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
