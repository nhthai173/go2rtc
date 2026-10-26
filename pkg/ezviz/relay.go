package ezviz

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"
)

// Hik-Connect / EZVIZ cloud relay (VTM -> VTDU), used when a device is not
// reachable over direct P2P (the P2P servers answer 0x101012). The relay speaks
// TCP with an 8-byte packet header and protobuf control messages, then streams
// RTP (H.265 + G.711 µ-law) on the stream channel. When "stream encryption" is
// enabled on the device, the RTP packets that carry the 0x4000 header extension
// have their payload scrambled with AES-128-ECB, keyed by the device verification
// code (zero-padded to 16 bytes): audio payloads entirely (whole blocks), video
// NAL bodies up to the first 4096 bytes, with the 2-byte NAL header left clear.
//
// Reference implementations (protocol discovered by their authors, code written
// independently here): RenierM26/pyEzvizApi (Apache-2.0) and
// guilhermekollet/cloud-cam-viewer (MIT).

const (
	vtmMagic = 0x24

	vtmChanMessage    = 0x00
	vtmChanStream     = 0x01
	vtmChanEncMessage = 0x0a
	vtmChanEncStream  = 0x0b

	vtmSpeedReq      = 0x13f // playback speed: ssn + varint multiplier
	vtmStopReq       = 0x130 // sent by the app when it closes a session
	vtmKeepaliveReq  = 0x132
	vtmKeepaliveRsp  = 0x133
	vtmStreamInfoReq = 0x13b
	vtmStreamInfoRsp = 0x13c
	vtmECDHNotify    = 0x14a

	relayClientVersion = "v3.6.3.20221124"

	rtpPayloadVideo = 96
	rtpPayloadAudio = 0 // PCMU

	rtpExtEncrypted    = 0x4000 // header-extension profile marking a scrambled payload
	nalEncryptedPrefix = 4096

	relayKeepalive   = 5 * time.Second
	relayReadTimeout = 15 * time.Second
	relayMaxHops     = 4
)

// relayBusyResult is the StreamInfoRsp result when the device has no free stream slot.
const relayBusyResult = 5416

var errRelayBusy = errors.New("ezviz: relay: device has no free stream slot (result 5416)")

// relayClient is a frameSource backed by the cloud relay.
type relayClient struct {
	cfg   cfgView
	conn  net.Conn
	br    *bufio.Reader
	wmu   sync.Mutex // serializes writes (keepalive vs. replies)
	seq   uint16
	ssn   string
	block cipher.Block // nil when no verification code was given

	frames    chan *Frame
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	err       error

	key       string     // playback: registry key, see playing
	pb        *psDemuxer // playback: the stream channel carries an MPEG-PS, not RTP
	lastMedia time.Time  // playback: last time the device sent media (it sends no end marker)

	frameNo uint32
	audioNo uint32
	fu      []byte // FU reassembly buffer (NAL header + body so far)
	fuEnc   bool
}

// cfgView is the subset of config the relay needs (kept separate so tests can
// build a client without a full URL).
type cfgView struct {
	remote string
}

func dialRelay(cfg config) (*relayClient, error) {
	c := &relayClient{
		frames: make(chan *Frame, 128),
		done:   make(chan struct{}),
	}
	if cfg.isPlayback() {
		c.pb = newPSDemuxer()
	}
	if cfg.code != "" {
		key := make([]byte, 16)
		copy(key, cfg.code)
		c.block, _ = aes.NewCipher(key)
	}

	api, err := sessionFor(cfg.baseURL, cfg.account, cfg.password)
	if err != nil {
		return nil, err
	}
	info, err := api.getRelayInfo(cfg.serial, cfg.channel)
	if err != nil {
		dropSession(cfg.baseURL, cfg.account, cfg.password) // maybe a stale session: next try logs in again
		return nil, err
	}

	stream := 1
	if cfg.subtype == "sub" {
		stream = 2
	}
	streamURL := info.streamURL(cfg.serial, cfg.channel, stream)
	if cfg.isPlayback() {
		if streamURL, err = info.playbackURL(cfg); err != nil {
			return nil, err
		}
	}
	// A slot freed by Close (or a seek) can take a moment to be released: the relay
	// answers 5416 until then.
	for try := 0; ; try++ {
		if err = c.connect(streamURL); err == nil || !errors.Is(err, errRelayBusy) || try == 5 {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return nil, err
	}

	if cfg.isPlayback() && cfg.speed > 1 {
		_ = c.SetSpeed(cfg.speed)
	}
	if cfg.isPlayback() {
		c.key = fmt.Sprintf("%s/%d", cfg.serial, cfg.channel)
		playing.Store(c.key, c) // a newer session of the same channel replaces the old one
	}

	go c.readLoop()
	go c.keepAlive()
	return c, nil
}

// connect performs the StreamInfoReq handshake, following VTM -> VTDU redirects.
func (c *relayClient) connect(streamURL string) error {
	var key string
	for hop := 0; hop < relayMaxHops; hop++ {
		u, err := url.Parse(streamURL)
		if err != nil {
			return fmt.Errorf("ezviz: relay: bad stream url: %w", err)
		}
		conn, err := dialRetry(u.Host)
		if err != nil {
			return err
		}
		br := bufio.NewReaderSize(conn, 64*1024)

		c.conn, c.br, c.seq = conn, br, 0
		req := appendStringField(nil, 1, streamURL)
		if key != "" {
			req = appendStringField(req, 2, key)
		}
		req = appendStringField(req, 3, relayClientVersion)
		req = appendVarintField(req, 4, 0)
		req = appendStringField(req, 6, relayClientVersion)
		if err = c.write(vtmChanMessage, vtmStreamInfoReq, req); err != nil {
			conn.Close()
			return err
		}

		info, err := readStreamInfo(conn, br)
		if err != nil {
			conn.Close()
			return err
		}
		if info.result != 0 && info.url != "" && info.key != "" {
			conn.Close()
			streamURL, key = info.url, info.key
			continue
		}
		if info.result == relayBusyResult {
			conn.Close()
			return errRelayBusy
		}
		if info.result != 0 {
			conn.Close()
			return fmt.Errorf("ezviz: relay refused the stream (result %d)", info.result)
		}

		c.ssn = info.ssn
		c.cfg.remote = conn.RemoteAddr().String()
		return nil
	}
	return errors.New("ezviz: relay: too many redirects")
}

// dialRetry retries the TCP connect: the VTM endpoint was seen to drop SYNs
// intermittently, and the first attempt after the token request often timed out.
func dialRetry(addr string) (net.Conn, error) {
	var err error
	for i := 0; i < 4; i++ {
		var conn net.Conn
		if conn, err = net.DialTimeout("tcp", addr, 4*time.Second); err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("ezviz: relay: connect %s: %w", addr, err)
}

type streamInfo struct {
	result uint64
	head   string
	ssn    string
	key    string
	url    string
}

func readStreamInfo(conn net.Conn, br *bufio.Reader) (*streamInfo, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < 20; i++ {
		_, code, body, err := readVTM(br)
		if err != nil {
			return nil, fmt.Errorf("ezviz: relay: stream info: %w", err)
		}
		if code != vtmStreamInfoRsp {
			continue
		}
		f, err := readFields(body)
		if err != nil {
			return nil, fmt.Errorf("ezviz: relay: stream info: %w", err)
		}
		return &streamInfo{
			result: f[1].n,
			head:   string(f[3].b),
			ssn:    string(f[4].b),
			key:    string(f[5].b),
			url:    string(f[7].b),
		}, nil
	}
	return nil, errors.New("ezviz: relay: no stream info response")
}

func (c *relayClient) write(channel byte, code uint16, body []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	h := make([]byte, 8, 8+len(body))
	h[0], h[1] = vtmMagic, channel
	binary.BigEndian.PutUint16(h[2:], uint16(len(body)))
	binary.BigEndian.PutUint16(h[4:], c.seq)
	binary.BigEndian.PutUint16(h[6:], code)
	c.seq++
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.conn.Write(append(h, body...))
	return err
}

func readVTM(r io.Reader) (channel byte, code uint16, body []byte, err error) {
	var h [8]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	if h[0] != vtmMagic {
		err = fmt.Errorf("bad VTM magic %#x", h[0])
		return
	}
	channel = h[1]
	code = binary.BigEndian.Uint16(h[6:])
	body = make([]byte, binary.BigEndian.Uint16(h[2:]))
	_, err = io.ReadFull(r, body)
	return
}

func (c *relayClient) readLoop() {
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(relayReadTimeout))
		ch, code, body, err := readVTM(c.br)
		if err != nil {
			c.fail(err)
			return
		}

		switch {
		case ch == vtmChanEncStream || ch == vtmChanEncMessage || code == vtmECDHNotify:
			c.fail(errors.New("ezviz: relay requires end-to-end (ECDH) encryption, which is not supported"))
			return
		case ch == vtmChanStream && c.pb != nil:
			if err = c.handlePS(body); err != nil {
				c.fail(err)
				return
			}
		case ch == vtmChanStream:
			if err = c.handleRTP(body); err != nil {
				c.fail(err)
				return
			}
		case code == vtmKeepaliveReq:
			_ = c.write(vtmChanMessage, vtmKeepaliveRsp, appendStringField(nil, 1, c.ssn))
		}
		// The relay keeps answering keepalives after the last recording byte, so
		// the end of a window is media silence, as on the P2P transport.
		if c.pb != nil && !c.lastMedia.IsZero() && time.Since(c.lastMedia) >= playbackIdleTimeout {
			c.fail(io.EOF)
			return
		}
	}
}

func (c *relayClient) keepAlive() {
	t := time.NewTicker(relayKeepalive)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if c.write(vtmChanMessage, vtmKeepaliveReq, appendStringField(nil, 1, c.ssn)) != nil {
				return
			}
		case <-c.done:
			return
		}
	}
}

// handleRTP depacketizes one RTP packet from the stream channel.
func (c *relayClient) handleRTP(b []byte) error {
	if len(b) < 12 || b[0]>>6 != 2 {
		return nil
	}

	off := 12 + 4*int(b[0]&0x0f)
	enc := false
	if b[0]&0x10 != 0 { // header extension
		if len(b) < off+4 {
			return nil
		}
		enc = binary.BigEndian.Uint16(b[off:]) == rtpExtEncrypted
		off += 4 + 4*int(binary.BigEndian.Uint16(b[off+2:]))
	}
	if off > len(b) {
		return nil
	}
	pl := b[off:]
	if b[0]&0x20 != 0 && len(pl) > 0 { // padding
		if n := int(pl[len(pl)-1]); n <= len(pl) {
			pl = pl[:len(pl)-n]
		}
	}

	if enc && c.block == nil {
		return errors.New("ezviz: stream is encrypted: add the device verification code as code=... to the URL")
	}

	ts := binary.BigEndian.Uint32(b[4:])
	switch b[1] & 0x7f {
	case rtpPayloadVideo:
		c.videoPacket(pl, ts, enc)
	case rtpPayloadAudio:
		if enc {
			decryptECB(c.block, pl)
		}
		c.audioNo++ // the RTSP consumers order packets by this: a constant sequence number makes ExoPlayer drop the audio
		c.push(&Frame{Codec: CodecPCMU, Payload: append([]byte(nil), pl...), Timestamp: ts, FrameNo: c.audioNo})
	}
	return nil
}

// handlePS demuxes one chunk of the recording's MPEG program stream. PES packets
// flagged as scrambled carry the same AES-ECB-scrambled NAL bodies as live RTP.
func (c *relayClient) handlePS(b []byte) error {
	c.lastMedia = time.Now()
	for _, f := range c.pb.write(b) {
		if f.Enc {
			if c.block == nil {
				return errors.New("ezviz: stream is encrypted: add the device verification code as code=... to the URL")
			}
			switch f.Codec {
			case CodecH265:
				if sc := startCodeLen(f.Payload); sc > 0 {
					decryptNAL(c.block, f.Payload[sc:])
				}
			case CodecPCMA:
				decryptECB(c.block, f.Payload)
			}
		}
		c.push(f)
	}
	return nil
}

func startCodeLen(b []byte) int {
	switch {
	case len(b) > 4 && b[0] == 0 && b[1] == 0 && b[2] == 1:
		return 3
	case len(b) > 4 && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 1:
		return 4
	}
	return 0
}

// videoPacket reassembles RFC 7798 H.265 payloads into whole NAL units.
func (c *relayClient) videoPacket(pl []byte, ts uint32, enc bool) {
	if len(pl) < 3 {
		return
	}

	switch t := (pl[0] >> 1) & 0x3f; t {
	case 48: // aggregation packet
		for p := pl[2:]; len(p) > 2; {
			n := int(binary.BigEndian.Uint16(p))
			if 2+n > len(p) {
				return
			}
			c.emitNAL(p[2:2+n], ts, enc)
			p = p[2+n:]
		}
	case 49: // fragmentation unit
		fu := pl[2]
		if fu&0x80 != 0 { // start
			c.fu = append(c.fu[:0], (pl[0]&0x81)|(fu&0x3f)<<1, pl[1])
			c.fuEnc = enc
		} else if len(c.fu) == 0 {
			return
		}
		c.fu = append(c.fu, pl[3:]...)
		if fu&0x40 != 0 { // end
			c.emitNAL(c.fu, ts, c.fuEnc)
			c.fu = c.fu[:0]
		}
	default:
		c.emitNAL(pl, ts, enc)
	}
}

func (c *relayClient) emitNAL(nal []byte, ts uint32, enc bool) {
	if len(nal) < 3 {
		return
	}
	p := make([]byte, 4+len(nal))
	copy(p, []byte{0, 0, 0, 1})
	copy(p[4:], nal)
	if enc {
		decryptNAL(c.block, p[4:])
	}
	c.frameNo++
	c.push(&Frame{Codec: CodecH265, Payload: p, Timestamp: ts, FrameNo: c.frameNo})
}

func (c *relayClient) push(f *Frame) {
	select {
	case c.frames <- f:
	case <-c.done:
	}
}

// decryptNAL decrypts the scrambled prefix of a NAL body in place, leaving the
// 2-byte NAL header clear.
func decryptNAL(block cipher.Block, nal []byte) {
	if len(nal) <= 2 {
		return
	}
	body := nal[2:]
	decryptECB(block, body[:min(len(body), nalEncryptedPrefix)])
}

// decryptECB decrypts whole 16-byte blocks in place; a trailing partial block is
// left as is.
func decryptECB(block cipher.Block, b []byte) {
	for i := 0; i+aes.BlockSize <= len(b); i += aes.BlockSize {
		block.Decrypt(b[i:i+aes.BlockSize], b[i:i+aes.BlockSize])
	}
}

func (c *relayClient) fail(err error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		close(c.done)
		_ = c.conn.Close()
	})
}

func (c *relayClient) ReadFrame() (*Frame, error) {
	select {
	case f := <-c.frames:
		return f, nil
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return nil, c.err
	}
}

func (c *relayClient) Close() error {
	if c.key != "" {
		playing.CompareAndDelete(c.key, c)
	}
	// Tell the relay the session is over: the device allows only a few streams at
	// once and a bare TCP close leaves the slot taken for a while.
	if c.ssn != "" {
		_ = c.write(vtmChanMessage, vtmStopReq, appendStringField(nil, 1, c.ssn))
	}
	c.fail(io.EOF)
	return nil
}

// playing holds the running playback session of each serial/channel, so an API
// call can change its speed without a handle on the stream.
var playing sync.Map

// SetPlaybackSpeed changes the speed of the running playback of a channel.
func SetPlaybackSpeed(serial string, channel, n int) error {
	c, ok := playing.Load(fmt.Sprintf("%s/%d", serial, channel))
	if !ok {
		return errors.New("ezviz: no playback running on this channel")
	}
	return c.(*relayClient).SetSpeed(n)
}

// SetSpeed asks the relay to deliver the recording n times faster than real time
// (the app offers 1/8x..8x; 2 and 4 are the values seen on the wire).
func (c *relayClient) SetSpeed(n int) error {
	return c.write(vtmChanMessage, vtmSpeedReq, appendVarintField(appendStringField(nil, 1, c.ssn), 2, uint64(n)))
}

func (c *relayClient) Protocol() string   { return "tcp" }
func (c *relayClient) RemoteAddr() string { return c.cfg.remote }

// --- minimal protobuf (just the fields the relay uses) ---

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendStringField(b []byte, field int, s string) []byte {
	b = appendVarint(b, uint64(field)<<3|2)
	b = appendVarint(b, uint64(len(s)))
	return append(b, s...)
}

func appendVarintField(b []byte, field int, v uint64) []byte {
	return appendVarint(appendVarint(b, uint64(field)<<3), v)
}

type pbValue struct {
	n uint64
	b []byte
}

// readFields decodes a flat protobuf message; for repeated fields the last value
// wins. Unknown wire types stop the decode with an error.
func readFields(b []byte) (map[int]pbValue, error) {
	out := map[int]pbValue{}
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return out, errors.New("bad protobuf key")
		}
		b = b[n:]
		field := int(key >> 3)

		switch key & 7 {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return out, errors.New("bad protobuf varint")
			}
			b = b[n:]
			out[field] = pbValue{n: v}
		case 1:
			if len(b) < 8 {
				return out, errors.New("short protobuf fixed64")
			}
			b = b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return out, errors.New("bad protobuf length")
			}
			out[field] = pbValue{b: b[n : n+int(l)]}
			b = b[n+int(l):]
		case 5:
			if len(b) < 4 {
				return out, errors.New("short protobuf fixed32")
			}
			b = b[4:]
		default:
			return out, fmt.Errorf("unsupported protobuf wire type %d", key&7)
		}
	}
	return out, nil
}
