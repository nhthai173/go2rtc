package ezviz

// session drives the UDP P2P + SRT exchange that streams media from a Hikvision
// device through the Hik-Connect cloud. The wire protocol — the V3 control
// opcodes, the hole-punch handshake, and the device's proprietary SRT dialect —
// was reverse-engineered from libezstreamclient.so and iVMS-4200 with Ghidra and
// validated against live packet captures. See PROTOCOL.md in this package for
// the full wire-format and transport-mix specification.
//
// Flow:
//
//  1. P2P_SETUP (0x0B02) to each P2P server registers our NAT-mapped address.
//  2. The 0x0B03 response carries the device's stream port; we pre-punch to it.
//  3. The device sends a hole-punch request (0x0C00); we reply 0x0C01 ten times.
//  4. PLAY_REQUEST (0x0C02) is sent directly to the device and relayed through
//     the P2P server inside a TRANSFOR_DATA (0x0B04) wrapper.
//  5. The device opens an SRT connection (induction -> conclusion); once up it
//     streams media data packets that we ACK and reassemble into NAL units.
//
// Concurrency: a single receive goroutine reads UDP datagrams and dispatches
// them. Completed Annex-B NAL units are pushed onto a buffered channel that
// readFrame drains. A separate ticker goroutine emits SRT ACKs and keepalives.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Non-V3 UDP packet types (big-endian at offset 0). The high bit marks an SRT
// control packet; data packets clear it.
const (
	pktSessionSetup uint16 = 0x7534
	pktConnControl  uint16 = 0x8000
	pktKeepalive    uint16 = 0x8001
	pktDataAck      uint16 = 0x8002

	// SRT control subtypes (F=1, the 0x80xx family).
	srtCtrlHandshake uint16 = 0x8000
	srtCtrlKeepalive uint16 = 0x8001
	srtCtrlAck       uint16 = 0x8002
	srtCtrlNak       uint16 = 0x8003
	srtCtrlShutdown  uint16 = 0x8005
	srtCtrlAck2      uint16 = 0x8006

	// Hik-RTP inner type carried by SRT control sub-session keepalives.
	innerControlKeepalive uint16 = 0x807f
)

const (
	srtReorderFlush    = 100 * time.Millisecond
	srtReorderMaxAhead = 64 // give up on a gap once the buffer runs this far ahead
)

// sessionConfig is everything the session needs to reach and authenticate to a
// device. It is assembled by Client.connect from the REST + secret responses.
type sessionConfig struct {
	deviceSerial     string
	devicePublicIP   string
	devicePublicPort int
	p2pServers       []apiServer
	p2pKey           []byte // 32-byte rotating P2P server key (outer encryption)
	p2pLinkKey       []byte // 32-byte link key (inner PLAY_REQUEST encryption)
	p2pKeyVersion    int
	p2pKeySaltIndex  byte
	p2pKeySaltVer    byte
	userID           string
	clientID         uint32
	channelNo        int
	streamType       int    // 1=main, 2=sub
	busType          int    // 1=live preview, 2=playback
	startTime        string // playback window start, device format YYYY-MM-DDThh:mm:ss
	stopTime         string // playback window end
	playbackIdle     time.Duration // >0 on playback: close with EOF after this much post-media silence
}

// session holds the live UDP transport state.
type session struct {
	cfg  sessionConfig
	conn *net.UDPConn

	mu sync.Mutex // guards the mutable fields below

	seqNum         uint32
	sessionCounter uint32
	sourceID       uint32
	dataSessionID  uint32

	devicePeer       *net.UDPAddr // updated when the device punches through
	deviceStreamPort int
	punchComplete    bool

	currentSessionKey string

	srtSynCookie    uint32
	srtPeerSocketID uint32
	srtAckNumber    uint32
	lastAckSeq      uint32 // video sub-session only

	// Video reorder buffer state (video sub-session sequence space).
	srtDeliverSeq int64 // next seq to deliver; -1 until first packet
	reorderBuf    map[uint32][]byte

	extractor *hikRTPExtractor
	pb        *psDemuxer // playback (busType=2) MPEG-PS demux; nil for live
	// feedMu serializes feed(): the receive loop and the reorder flush timer can
	// both deliver payloads, and the extractor (and playback demuxer) carry
	// cross-packet state that must not be mutated concurrently.
	feedMu  sync.Mutex
	frameNo uint32

	audioFrameNo uint32
	audioTS      uint32 // 8 kHz audio sample clock

	// epoch anchors both media clocks to one real-time reference. The device
	// exposes no usable per-frame PTS, so arrival time is the reference; sharing
	// one epoch keeps the audio and video tracks in sync (they ride the same SRT
	// session, so capture-to-arrival latency is shared and cancels out).
	epoch time.Time

	// lastMediaNanos is the arrival time (UnixNano) of the most recent media frame,
	// read by the playback idle watchdog. Atomic to stay off the push hot path's lock.
	lastMediaNanos atomic.Int64

	frames     chan *Frame
	punchCh    chan struct{}
	punchOnce  sync.Once
	dataCh     chan struct{}
	dataOnce   sync.Once
	closeCh    chan struct{}
	closeOnce  sync.Once
	framesOnce sync.Once
	wg         sync.WaitGroup

	flushTimer *time.Timer
}

func newSession(cfg sessionConfig) (*session, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("ezviz: udp bind: %w", err)
	}

	s := &session{
		cfg:           cfg,
		conn:          conn,
		sourceID:      randUint32(),
		srtAckNumber:  1,
		srtDeliverSeq: -1,
		reorderBuf:    make(map[uint32][]byte),
		extractor:     newHikRTPExtractor(),
		frames:        make(chan *Frame, 256),
		pb:            newPSDemuxer(),
		punchCh:       make(chan struct{}),
		dataCh:        make(chan struct{}),
		closeCh:       make(chan struct{}),
	}
	return s, nil
}

// start runs the full bring-up sequence and leaves the receive + ticker
// goroutines running. It returns once streaming has been requested; media then
// arrives asynchronously on the frames channel.
func (s *session) start() error {
	s.wg.Add(1)
	go s.receiveLoop()

	// Step 1: P2P_SETUP to every P2P server, then wait for the device punch.
	if err := s.contactP2PServers(); err != nil {
		return err
	}

	// Step 2: PLAY_REQUEST (direct + relayed).
	if err := s.sendPlayRequest(); err != nil {
		return err
	}

	// Step 3: periodic keepalives + SRT ACKs.
	s.wg.Add(1)
	go s.tickerLoop()

	// Step 4: wait for the SRT data session to come up. If it never does the
	// device is offline, UDP/NAT is blocked, or the channel is not streaming —
	// fail here rather than return nil and let probe's ReadFrame block forever.
	s.waitForDataSession(15 * time.Second)
	if s.getDataSessionID() == 0 {
		return fmt.Errorf("ezviz: SRT data session did not start within 15s (device offline, blocked UDP/NAT, or channel %d not streaming)", s.cfg.channelNo)
	}

	// Step 5: nudge the device to start streaming with a SESSION_SETUP packet.
	s.sendSessionSetup()

	// Step 6 (playback only): watch for the post-media silence that marks the end
	// of the window / the live edge and turn it into a clean EOF.
	if s.cfg.playbackIdle > 0 {
		s.wg.Add(1)
		go s.idleWatchdog()
	}
	return nil
}

// idleWatchdog closes the frames channel (→ readFrame returns io.EOF) once the
// device has gone quiet for cfg.playbackIdle after delivering at least one media
// frame. Playback has no end-of-stream marker: at a window end or the live edge
// the device simply stops sending, so without this the consumer would hang until
// its own read-timeout. It never fires before the first frame, so a slow bring-up
// is not mistaken for an empty recording.
func (s *session) idleWatchdog() {
	defer s.wg.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-tick.C:
			last := s.lastMediaNanos.Load()
			if last == 0 {
				continue // no media yet — don't time out the bring-up
			}
			if time.Since(time.Unix(0, last)) >= s.cfg.playbackIdle {
				// close() closes closeCh (stopping push) before frames and waits on
				// the wait group — which includes this goroutine — so run it
				// separately and return to let that wait complete.
				go s.close()
				return
			}
		}
	}
}

func (s *session) contactP2PServers() error {
	setup, err := s.buildP2PSetupRequest()
	if err != nil {
		return err
	}
	for _, srv := range s.cfg.p2pServers {
		s.sendTo(setup, srv.IP, srv.Port)
	}

	// Wait for the device hole-punch (0x0C00 -> 0x0C01 handled in receiveLoop).
	if s.waitFor(s.punchCh, 10*time.Second) {
		return nil
	}

	// Fallback: punch directly to the known device address.
	s.holePunch()
	s.sleep(2 * time.Second)
	return nil
}

func (s *session) sendPlayRequest() error {
	// Path A: directly to the device over the punched connection.
	s.mu.Lock()
	peer := s.devicePeer
	punched := s.punchComplete
	s.mu.Unlock()

	if punched && peer != nil {
		direct, err := s.buildInnerV3Message(s.buildPlayRequestBody(), OpPlayRequest)
		if err != nil {
			return err
		}
		for i := 0; i < 3; i++ {
			s.sendToAddr(direct, peer)
		}
	}

	// Path B: relayed through the P2P server inside a TRANSFOR_DATA wrapper.
	relay, err := s.buildP2PServerRequest()
	if err != nil {
		return err
	}
	for _, srv := range s.cfg.p2pServers {
		s.sendTo(relay, srv.IP, srv.Port)
	}

	s.sleep(3 * time.Second)
	return nil
}

// -- V3 message builders --

func (s *session) nextSeq() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seqNum++
	return s.seqNum
}

// sessionKey builds the per-session correlation key the device echoes back:
// base64(serial) + channel + YYYYMMDDhhmmss + 5 random digits.
func (s *session) sessionKey() string {
	b64 := base64.StdEncoding.EncodeToString([]byte(s.cfg.deviceSerial))
	now := time.Now()
	ts := now.Format("20060102150405")
	rand5 := strconv.Itoa(10000 + mrand.Intn(90000))
	return b64 + strconv.Itoa(s.cfg.channelNo) + ts + rand5
}

func (s *session) busType() byte {
	if s.cfg.busType == 0 {
		return 1
	}
	return byte(s.cfg.busType)
}

// buildP2PSetupRequest builds the standalone P2P_SETUP (0x0B02) message. It is
// encrypted with the P2P server key and carries no expand header. The body holds
// the session key, user id, serial and a nested TRANSFOR sub-TLV (tag 0xFF) that
// advertises our bus type, local address and client id.
func (s *session) buildP2PSetupRequest() ([]byte, error) {
	serial := s.cfg.deviceSerial
	key := s.sessionKey()

	s.mu.Lock()
	s.currentSessionKey = key
	s.mu.Unlock()

	localIP, localPort := s.localAddr()

	var body []byte
	body = appendTLV(body, AttrSessionKey, []byte(key))
	body = appendTLV(body, AttrSessionInfo, []byte(s.cfg.userID))
	body = appendTLV(body, AttrTransforData, []byte(serial))
	body = appendTLV(body, AttrBusTypeEnc, []byte{0x03}) // protocol version 3

	// Nested TRANSFOR sub-TLVs under tag 0xFF.
	var transfor []byte
	transfor = appendTLV(transfor, 0x71, []byte{s.busType()}) // busType
	transfor = appendTLV(transfor, 0x72, []byte{0x03})        // protocol flag
	transfor = appendTLV(transfor, 0x75, []byte{0x01})        // flag
	transfor = appendTLV(transfor, 0x7f, []byte{0x0a})        // NAT type/flag
	transfor = appendTLV(transfor, 0x74, []byte(fmt.Sprintf("%s:%d", localIP, localPort)))
	clientID := make([]byte, 4)
	binary.BigEndian.PutUint32(clientID, s.cfg.clientID)
	transfor = appendTLV(transfor, 0x8c, clientID)
	body = appendTLV(body, AttrEndMarker, transfor)

	enc, err := aesEncrypt(body, s.cfg.p2pKey)
	if err != nil {
		return nil, err
	}

	// P2P_SETUP uses seq=0 and no expand header.
	mask := V3Mask{
		Encrypt:     true,
		Is2BLen:     true,
		SaltVersion: s.cfg.p2pKeySaltVer,
		SaltIndex:   s.cfg.p2pKeySaltIndex,
	}
	return frameV3(OpP2PSetup, 0, mask, enc), nil
}

// buildP2PServerRequest wraps an inner PLAY_REQUEST V3 message inside an
// AES-encrypted TRANSFOR_DATA (0x0B04) message addressed to the P2P server,
// which relays it to the device.
func (s *session) buildP2PServerRequest() ([]byte, error) {
	inner, err := s.buildInnerV3Message(s.buildPlayRequestBody(), OpPlayRequest)
	if err != nil {
		return nil, err
	}
	outerBody := s.buildOuterBody(inner)

	enc, err := aesEncrypt(outerBody, s.cfg.p2pKey)
	if err != nil {
		return nil, err
	}

	mask := V3Mask{
		Encrypt:     true,
		Is2BLen:     true,
		SaltVersion: s.cfg.p2pKeySaltVer,
		SaltIndex:   s.cfg.p2pKeySaltIndex,
	}
	return frameV3(OpTransforData, s.nextSeq(), mask, enc), nil
}

// buildPlayRequestBody builds the (still plaintext) TLV body of PLAY_REQUEST.
func (s *session) buildPlayRequestBody() []byte {
	serial := s.cfg.deviceSerial

	s.mu.Lock()
	key := s.currentSessionKey
	counter := s.sessionCounter
	s.mu.Unlock()

	now := time.Now()
	today := now.Format("2006-01-02")

	// Live preview ignores the time window but the device still expects the
	// fields; default to "today so far". Playback (busType=2) overrides both with
	// the requested recording window.
	start := today + "T00:00:00"
	stop := today + "T" + now.Format("15:04:05")
	if s.cfg.startTime != "" {
		start = s.cfg.startTime
	}
	if s.cfg.stopTime != "" {
		stop = s.cfg.stopTime
	}

	var body []byte
	body = appendTLV(body, AttrBusType, []byte{s.busType()})
	body = appendTLV(body, AttrSessionKey, []byte(key))
	body = appendTLV(body, AttrStreamType, []byte{byte(s.cfg.streamType)})
	body = appendTLV(body, AttrChannelNo, u16(uint16(s.cfg.channelNo)))
	body = appendTLV(body, AttrStreamSession, u32(counter+1))
	body = appendTLV(body, AttrDeviceSessionAlt, u32(180))
	body = appendTLV(body, AttrStartTime, []byte(start))
	body = appendTLV(body, AttrStopTime, []byte(stop))
	body = appendTLV(body, AttrStreamMeta, []byte(serial))
	body = appendTLV(body, AttrOptMeta1, []byte(newUUID()))
	body = appendTLV(body, AttrOptMeta2, []byte(strconv.FormatInt(now.UnixMilli(), 10)))
	return body
}

// buildInnerV3Message encrypts a body with the link key and wraps it in a V3
// message carrying the expand header (key version, user id, client id, channel).
func (s *session) buildInnerV3Message(body []byte, opcode uint16) ([]byte, error) {
	enc, err := aesEncrypt(body, s.cfg.p2pLinkKey)
	if err != nil {
		return nil, err
	}

	var expand []byte
	expand = appendTLV(expand, AttrTransforData, u16(uint16(s.cfg.p2pKeyVersion)))
	expand = appendTLV(expand, AttrExpandKeyVersion, []byte(s.cfg.userID))
	clientID := make([]byte, 4)
	binary.BigEndian.PutUint32(clientID, s.cfg.clientID)
	expand = appendTLV(expand, AttrClientID, clientID)
	expand = appendTLV(expand, AttrDeviceChannel, u16(uint16(s.cfg.channelNo)))

	headerLen := V3HeaderLen + len(expand)

	mask := V3Mask{
		Encrypt:      true,
		Is2BLen:      true,
		ExpandHeader: true,
		SaltVersion:  s.cfg.p2pKeySaltVer,
		SaltIndex:    s.cfg.p2pKeySaltIndex,
	}

	full := make([]byte, headerLen+len(enc))
	full[0] = V3Magic
	full[1] = mask.Encode()
	binary.BigEndian.PutUint16(full[2:], opcode)
	binary.BigEndian.PutUint32(full[4:], s.nextSeq())
	binary.BigEndian.PutUint16(full[8:], 0x6234)
	full[10] = byte(headerLen)
	full[11] = 0x00
	copy(full[V3HeaderLen:], expand)
	copy(full[headerLen:], enc)
	full[11] = CRC8(full)
	return full, nil
}

// buildOuterBody is the TRANSFOR_DATA outer body: a routing serial tag plus the
// inner V3 message carried under tag 0x07 (2-byte length).
func (s *session) buildOuterBody(inner []byte) []byte {
	serial := []byte(s.cfg.deviceSerial)
	var body []byte
	body = appendTLV(body, AttrTransforData, serial)

	hdr := make([]byte, 3)
	hdr[0] = AttrLargeData
	binary.BigEndian.PutUint16(hdr[1:], uint16(len(inner)))
	body = append(body, hdr...)
	body = append(body, inner...)
	return body
}

// -- Hole punching --

func (s *session) holePunch() {
	punch := []byte{0x00}
	ports := map[int]struct{}{s.cfg.devicePublicPort: {}}
	s.mu.Lock()
	if s.deviceStreamPort != 0 {
		ports[s.deviceStreamPort] = struct{}{}
	}
	s.mu.Unlock()
	for port := range ports {
		for i := 0; i < 5; i++ {
			s.sendTo(punch, s.cfg.devicePublicIP, port)
		}
	}
}

// -- Session setup (0x7534) --

func (s *session) sendSessionSetup() {
	key := s.sessionKey()

	v3, err := EncodeV3Message(V3Message{
		MsgType:  0x0c00,
		SeqNum:   s.nextSeq(),
		Reserved: 0x6234,
		Mask: V3Mask{
			Is2BLen:     true,
			SaltVersion: s.cfg.p2pKeySaltVer,
			SaltIndex:   s.cfg.p2pKeySaltIndex,
		},
		Attrs: []V3Attr{
			{Tag: AttrSessionKey, Value: []byte(key)},
			{Tag: 0x71, Value: []byte{0x01}},
			{Tag: AttrPortCount, Value: make([]byte, 4)},
		},
	}, nil)
	if err != nil {
		return
	}

	s.mu.Lock()
	s.sessionCounter++
	sessionID := s.sessionCounter
	seq := s.seqNum
	source := s.sourceID
	s.mu.Unlock()

	pkt := make([]byte, 28+len(v3))
	binary.BigEndian.PutUint16(pkt[0:], pktSessionSetup)
	binary.BigEndian.PutUint16(pkt[2:], uint16(sessionID))
	binary.BigEndian.PutUint16(pkt[4:], 0xc000) // SYN flags
	binary.BigEndian.PutUint16(pkt[6:], uint16(seq))
	binary.BigEndian.PutUint32(pkt[8:], timestamp32())
	binary.BigEndian.PutUint32(pkt[12:], source)
	pkt[16] = 0x80
	pkt[17] = 0x7f
	copy(pkt[28:], v3)

	s.sendToDevice(pkt)
	time.AfterFunc(200*time.Millisecond, func() { s.sendToDevice(pkt) })
	time.AfterFunc(500*time.Millisecond, func() { s.sendToDevice(pkt) })
}

// -- Receive loop --

func (s *session) receiveLoop() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		select {
		case <-s.closeCh:
			return
		default:
		}

		_ = s.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			s.closeFrames()
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.handlePacket(pkt, src)
	}
}

func (s *session) handlePacket(buf []byte, src *net.UDPAddr) {
	if len(buf) < 2 {
		return
	}

	// V3 messages from P2P servers (magic high nibble 0xE).
	if buf[0]>>4 == 0xe && len(buf) >= V3HeaderLen {
		s.handleV3Response(buf, src)
		return
	}

	t := binary.BigEndian.Uint16(buf)

	switch t {
	case srtCtrlKeepalive:
		// Echo an SRT keepalive with our peer socket id.
		resp := make([]byte, 16)
		binary.BigEndian.PutUint16(resp[0:], srtCtrlKeepalive)
		binary.BigEndian.PutUint32(resp[8:], timestamp32())
		binary.BigEndian.PutUint32(resp[12:], s.getPeerSocketID())
		s.sendToDevice(resp)
		return
	case srtCtrlAck, srtCtrlShutdown, srtCtrlAck2, srtCtrlNak:
		// ACK / NAK / ACK2 / shutdown — nothing to do. (0x8002/0x8003/0x8006 also
		// cover the custom DATA_ACK / DATA_REF / SHORT_ACK aliases.) Despite its
		// name, 0x8005 is NOT an end-of-stream signal in this dialect: live and
		// playback captures both show exactly one 0x8005 arriving early (the device
		// tearing down the control sub-session once the video sub-session is up),
		// after which media streams normally for the rest of the session. Closing
		// on it truncates the stream ~5s in. Playback simply streams from the start
		// time until the consumer disconnects; the device sends neither a PS
		// program-end marker nor a distinct end-of-window shutdown.
		return
	case pktSessionSetup:
		s.handleSessionSetup(buf)
		return
	case pktConnControl:
		s.handleConnectionControl(buf)
		return
	}

	// SRT data packet: control bit clear, has a 16-byte header, session is up.
	if len(buf) >= 16 && buf[0]&0x80 == 0 && s.getDataSessionID() != 0 {
		s.handleSrtDataPacket(buf)
	}
}

func (s *session) handleV3Response(buf []byte, src *net.UDPAddr) {
	isEncrypted := buf[1]&0x80 != 0
	var (
		msg V3Message
		err error
	)
	if isEncrypted {
		msg, err = DecodeV3Message(buf, s.cfg.p2pKey)
	} else {
		msg, err = DecodeV3Message(buf, nil)
	}
	if err != nil {
		return
	}

	switch msg.MsgType {
	case OpTransforCtrl: // 0x0b03 — P2P_SETUP response
		s.handleSetupResponse(msg)
	case OpPunchRequest: // 0x0c00 — device hole-punch request
		s.handlePunchRequest(src)
	case OpPunchResponse: // 0x0c01 — device punch ack
		// nothing to do
	}
}

// handleSetupResponse extracts the device stream port from the 0x0B03 response's
// nested tag 0xFF sub-TLV (0x74 = "IP:PORT") and pre-punches to it so the
// device's 0x0C00 can traverse our NAT.
func (s *session) handleSetupResponse(msg V3Message) {
	var ff []byte
	for _, a := range msg.Attrs {
		if a.Tag == AttrEndMarker {
			ff = a.Value
			break
		}
	}
	if len(ff) == 0 {
		return
	}

	off := 0
	for off+2 <= len(ff) {
		tag := ff[off]
		l := int(ff[off+1])
		if off+2+l > len(ff) {
			break
		}
		if tag == 0x74 {
			addr := string(ff[off+2 : off+2+l])
			if idx := strings.LastIndex(addr, ":"); idx > 0 {
				if port, err := strconv.Atoi(addr[idx+1:]); err == nil && port > 0 && port < 65536 {
					s.mu.Lock()
					s.deviceStreamPort = port
					s.mu.Unlock()
					punch := []byte{0x00}
					for i := 0; i < 5; i++ {
						s.sendTo(punch, s.cfg.devicePublicIP, port)
					}
				}
			}
		}
		off += 2 + l
	}
}

func (s *session) handlePunchRequest(src *net.UDPAddr) {
	s.mu.Lock()
	s.devicePeer = src
	key := s.currentSessionKey
	already := s.punchComplete
	s.punchComplete = true
	s.mu.Unlock()

	resp, err := EncodeV3Message(V3Message{
		MsgType:  OpPunchResponse,
		SeqNum:   s.nextSeq(),
		Reserved: 0x6234,
		Mask: V3Mask{
			Is2BLen:     true,
			SaltVersion: s.cfg.p2pKeySaltVer,
			SaltIndex:   s.cfg.p2pKeySaltIndex,
		},
		Attrs: []V3Attr{
			{Tag: AttrSessionKey, Value: []byte(key)},
			{Tag: 0x71, Value: []byte{0x01}},
		},
	}, nil)
	if err == nil {
		for i := 0; i < 10; i++ {
			s.sendToAddr(resp, src)
		}
	}

	if !already {
		s.punchOnce.Do(func() { close(s.punchCh) })
	}
}

func (s *session) handleSessionSetup(buf []byte) {
	if len(buf) < 28 {
		return
	}
	// Bytes 0-1 are the packet type (0x7534); the session id is the 16-bit field
	// at bytes 2-3, mirroring the layout sendSessionSetup writes. Echo that id so
	// the device matches the ACK to its setup exchange. Embedded V3 message, if
	// any, follows and is not needed here.
	sessionID := uint32(binary.BigEndian.Uint16(buf[2:]))
	s.sendDataAck(sessionID)
}

func (s *session) sendDataAck(ackedSessionID uint32) {
	pkt := make([]byte, 44)
	binary.BigEndian.PutUint16(pkt[0:], pktDataAck)
	binary.BigEndian.PutUint32(pkt[8:], timestamp32())
	binary.BigEndian.PutUint32(pkt[12:], s.sourceID)
	binary.BigEndian.PutUint32(pkt[16:], ackedSessionID)
	binary.BigEndian.PutUint32(pkt[20:], 0x3a0c)
	binary.BigEndian.PutUint32(pkt[24:], 0)
	binary.BigEndian.PutUint32(pkt[28:], 0x1e)
	binary.BigEndian.PutUint32(pkt[32:], 1)
	binary.BigEndian.PutUint32(pkt[36:], 0x3e8)
	binary.BigEndian.PutUint32(pkt[40:], 0x38)
	s.sendToDevice(pkt)
}

// -- SRT handshake --

func (s *session) handleConnectionControl(buf []byte) {
	if len(buf) < 64 {
		return
	}
	srtVersion := binary.BigEndian.Uint32(buf[16:])
	initSeq := binary.BigEndian.Uint32(buf[24:])
	mtu := binary.BigEndian.Uint32(buf[28:])
	window := binary.BigEndian.Uint32(buf[32:])
	hsType := binary.BigEndian.Uint32(buf[36:])
	peerSocketID := binary.BigEndian.Uint32(buf[40:])

	if hsType == 1 && srtVersion == 4 {
		s.handleSrtInduction(peerSocketID, initSeq, mtu, window)
		return
	}
	if hsType == 0xFFFFFFFF {
		s.handleSrtConclusion(buf, peerSocketID)
		return
	}
	if initSeq != 0 && s.getDataSessionID() == 0 {
		s.setDataSession(initSeq)
	}
}

func (s *session) handleSrtInduction(peerSocketID, initSeq, mtu, window uint32) {
	cookie := s.sourceID ^ peerSocketID ^ timestamp32()

	pkt := make([]byte, 64)
	binary.BigEndian.PutUint16(pkt[0:], srtCtrlHandshake)
	binary.BigEndian.PutUint32(pkt[8:], timestamp32())
	binary.BigEndian.PutUint32(pkt[12:], peerSocketID)
	binary.BigEndian.PutUint32(pkt[16:], 5)      // version 5 (SRT)
	binary.BigEndian.PutUint16(pkt[20:], 0)      // encryption: none
	binary.BigEndian.PutUint16(pkt[22:], 0x4a17) // SRT magic
	binary.BigEndian.PutUint32(pkt[24:], initSeq)
	binary.BigEndian.PutUint32(pkt[28:], mtu)
	binary.BigEndian.PutUint32(pkt[32:], window)
	binary.BigEndian.PutUint32(pkt[36:], 1) // induction response
	binary.BigEndian.PutUint32(pkt[40:], s.sourceID)
	binary.BigEndian.PutUint32(pkt[44:], cookie)

	s.mu.Lock()
	s.srtSynCookie = cookie
	// The device opens two SRT sub-sessions: control then video. We deliberately
	// keep the last peer socket id so ACKs target the video sub-session.
	s.srtPeerSocketID = peerSocketID
	s.mu.Unlock()

	s.sendToDevice(pkt)
}

func (s *session) handleSrtConclusion(buf []byte, peerSocketID uint32) {
	initSeq := binary.BigEndian.Uint32(buf[24:])
	if s.getDataSessionID() == 0 {
		s.setDataSession(initSeq)
	}

	s.mu.Lock()
	cookie := s.srtSynCookie
	s.mu.Unlock()

	pkt := make([]byte, 80)
	binary.BigEndian.PutUint16(pkt[0:], srtCtrlHandshake)
	binary.BigEndian.PutUint32(pkt[8:], timestamp32())
	binary.BigEndian.PutUint32(pkt[12:], peerSocketID)
	binary.BigEndian.PutUint32(pkt[16:], 5) // version 5 (SRT)
	binary.BigEndian.PutUint16(pkt[20:], 0) // encryption: none
	binary.BigEndian.PutUint16(pkt[22:], 1) // extensions present
	binary.BigEndian.PutUint32(pkt[24:], initSeq)
	binary.BigEndian.PutUint32(pkt[28:], 1500)       // MTU
	binary.BigEndian.PutUint32(pkt[32:], 32)         // window
	binary.BigEndian.PutUint32(pkt[36:], 0xFFFFFFFF) // conclusion
	binary.BigEndian.PutUint32(pkt[40:], s.sourceID)
	binary.BigEndian.PutUint32(pkt[44:], cookie)
	// SRT_CMD_HSRSP extension.
	binary.BigEndian.PutUint16(pkt[64:], 2)          // extension type HSRSP
	binary.BigEndian.PutUint16(pkt[66:], 3)          // length in 32-bit words
	binary.BigEndian.PutUint32(pkt[68:], 0x00010401) // SRT version 1.4.1
	binary.BigEndian.PutUint32(pkt[72:], 0x000000b4) // flags

	s.sendToDevice(pkt)
}

// -- SRT data path --

func (s *session) handleSrtDataPacket(buf []byte) {
	seqNum := binary.BigEndian.Uint32(buf) & 0x7fffffff
	payload := buf[16:]

	// The device multiplexes two SRT sub-sessions onto this one socket, each
	// with its OWN sequence space: a control channel carrying 0x807f keepalives
	// and the video data channel. Our ACKs go to the video socket and must carry
	// the video channel's sequence — a control keepalive's sequence belongs to
	// the control space, so letting it advance lastAckSeq would ACK the video
	// session with an out-of-range sequence and stall the device's flow-control
	// window. Route by inner Hik-RTP type and never mix the spaces.
	var innerType uint16
	if len(payload) >= 2 {
		innerType = binary.BigEndian.Uint16(payload)
	}
	if innerType == innerControlKeepalive {
		return
	}

	s.mu.Lock()
	s.lastAckSeq = seqNum
	s.mu.Unlock()

	s.deliverInOrder(seqNum, payload)
}

// srtAhead returns the wrap-aware signed distance of seq ahead of the next seq
// expected for delivery. Caller holds s.mu.
func (s *session) srtAhead(seq uint32) int64 {
	d := (int64(seq) - s.srtDeliverSeq) & 0x7fffffff
	if d > 0x40000000 {
		d -= 0x80000000
	}
	return d
}

// deliverInOrder re-sequences video payloads before NAL reassembly. UDP delivers
// a small fraction out of order and Hik-RTP carries no per-packet sequence, so
// FU reassembly relies on in-order delivery. Out-of-order packets are buffered
// briefly; a genuinely lost packet is given up on after a flush timeout or once
// the buffer runs too far ahead, so the stream never stalls.
func (s *session) deliverInOrder(seq uint32, payload []byte) {
	s.mu.Lock()
	if s.srtDeliverSeq < 0 {
		s.srtDeliverSeq = int64(seq)
	}
	ahead := s.srtAhead(seq)

	if ahead < 0 {
		s.mu.Unlock()
		return // late duplicate of an already-delivered seq
	}

	if ahead == 0 {
		out := [][]byte{payload}
		s.srtDeliverSeq = (s.srtDeliverSeq + 1) & 0x7fffffff
		out = append(out, s.drainReorderLocked()...)
		s.mu.Unlock()
		for _, p := range out {
			s.feed(p)
		}
		return
	}

	// Ahead of expected — a packet is missing. Buffer and wait.
	s.reorderBuf[seq] = payload
	if ahead > srtReorderMaxAhead {
		out := s.advancePastGapLocked()
		s.mu.Unlock()
		for _, p := range out {
			s.feed(p)
		}
		return
	}
	s.scheduleFlushLocked()
	s.mu.Unlock()
}

// drainReorderLocked releases buffered packets now contiguous with the delivery
// cursor. Caller holds s.mu.
func (s *session) drainReorderLocked() [][]byte {
	var out [][]byte
	for {
		key := uint32(s.srtDeliverSeq)
		p, ok := s.reorderBuf[key]
		if !ok {
			break
		}
		delete(s.reorderBuf, key)
		out = append(out, p)
		s.srtDeliverSeq = (s.srtDeliverSeq + 1) & 0x7fffffff
	}
	if len(s.reorderBuf) == 0 && s.flushTimer != nil {
		s.flushTimer.Stop()
		s.flushTimer = nil
	}
	return out
}

// advancePastGapLocked gives up on the missing sequence, jumps to the lowest
// buffered sequence and drains. Caller holds s.mu.
func (s *session) advancePastGapLocked() [][]byte {
	lowest := int64(-1)
	lowestAhead := int64(1) << 62
	for k := range s.reorderBuf {
		a := s.srtAhead(k)
		if a >= 0 && a < lowestAhead {
			lowestAhead = a
			lowest = int64(k)
		}
	}
	if lowest < 0 {
		return nil
	}
	s.srtDeliverSeq = lowest
	out := s.drainReorderLocked()
	if len(s.reorderBuf) > 0 {
		s.scheduleFlushLocked()
	}
	return out
}

// scheduleFlushLocked arms the reorder flush timer. Caller holds s.mu.
func (s *session) scheduleFlushLocked() {
	if s.flushTimer != nil {
		return
	}
	s.flushTimer = time.AfterFunc(srtReorderFlush, func() {
		s.mu.Lock()
		s.flushTimer = nil
		var out [][]byte
		if len(s.reorderBuf) > 0 {
			out = s.advancePastGapLocked()
		}
		s.mu.Unlock()
		for _, p := range out {
			s.feed(p)
		}
	})
}

// feed runs a delivered video payload through the Hik-RTP extractor and pushes
// any completed NAL units onto the frames channel. The receive loop and the
// reorder flush timer can call this from different goroutines, so the stateful
// extractor work is serialized under feedMu.
func (s *session) feed(payload []byte) {
	s.feedMu.Lock()
	defer s.feedMu.Unlock()

	// Playback (busType=2) is an MPEG Program Stream, not Hik-RTP-framed NALs:
	// strip the 12-byte header and let the PS demuxer reconstruct access units.
	if s.cfg.busType == 2 {
		frag := extractPlaybackPayload(payload)
		if frag == nil {
			return
		}
		for _, f := range s.pb.write(frag) {
			s.push(f)
		}
		return
	}

	// Audio is interleaved on the same SRT data session as video, distinguished
	// by the sub-header. Surface G.711 frames on the audio track.
	if a := extractAudioPayload(payload); a != nil {
		ts, seq := s.nextAudio(len(a))
		s.push(&Frame{Codec: CodecPCMA, Payload: append([]byte(nil), a...), Timestamp: ts, FrameNo: seq})
		return
	}

	// One arrival is one access unit; all NALs it yields (e.g. VPS/SPS/PPS/IDR)
	// must share a single PTS, so stamp once per payload rather than per NAL.
	nals := s.extractor.process(payload)
	if len(nals) == 0 {
		return
	}
	ts := s.nextTimestamp()
	for _, nal := range nals {
		s.push(&Frame{Codec: CodecH265, Payload: nal, Timestamp: ts, FrameNo: s.nextFrameNo()})
	}
}

func (s *session) push(f *Frame) {
	// Never send after close: closeCh is closed before the frames channel, so a
	// late flush-timer delivery exits here instead of panicking on a closed send.
	select {
	case <-s.closeCh:
		return
	default:
	}
	s.lastMediaNanos.Store(time.Now().UnixNano())
	select {
	case s.frames <- f:
	case <-s.closeCh:
	default:
		// Drop on a full buffer rather than block the receive loop; the
		// consumer fell behind and stale media is not worth stalling for.
	}
}

func (s *session) nextFrameNo() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frameNo++
	return s.frameNo
}

// mediaTicks returns the elapsed time since the session epoch scaled to the
// given clock rate (90 kHz for video, 8 kHz for audio), setting the epoch on the
// first call. Video frames are timestamped by arrival because the device sends
// at a variable real rate (~19 fps observed, not a fixed 30) and exposes no
// per-frame PTS; a synthetic fixed-fps counter compressed the video timeline and
// drifted it out of sync with the real-time audio. Caller must hold s.mu.
func (s *session) mediaTicks(hz float64) uint32 {
	if s.epoch.IsZero() {
		s.epoch = time.Now()
	}
	return uint32(time.Since(s.epoch).Seconds() * hz)
}

// nextTimestamp returns the 90 kHz video PTS for a frame arriving now.
func (s *session) nextTimestamp() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mediaTicks(90000)
}

// nextAudio returns the RTP timestamp (8 kHz sample clock) and sequence number
// for the next audio frame, advancing the audio clock by the frame's sample
// count (1 byte = 1 sample for G.711).
func (s *session) nextAudio(samples int) (ts, seq uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Anchor the first audio frame to the shared epoch so the audio track lines
	// up with video; thereafter advance by the exact sample count for a smooth,
	// jitter-free audio clock (audio arrives gap-free at real 8 kHz).
	if s.audioFrameNo == 0 {
		s.audioTS = s.mediaTicks(8000)
	}
	ts = s.audioTS
	s.audioTS += uint32(samples)
	s.audioFrameNo++
	return ts, s.audioFrameNo
}

// -- ACK / keepalive ticker --

func (s *session) tickerLoop() {
	defer s.wg.Done()
	ack := time.NewTicker(10 * time.Millisecond)
	keepalive := time.NewTicker(15 * time.Second)
	defer ack.Stop()
	defer keepalive.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case <-ack.C:
			s.mu.Lock()
			last := s.lastAckSeq
			s.mu.Unlock()
			if last > 0 {
				s.sendSrtAck(last)
			}
		case <-keepalive.C:
			s.sendKeepalive()
		}
	}
}

func (s *session) sendKeepalive() {
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:], pktKeepalive)
	binary.BigEndian.PutUint32(pkt[8:], timestamp32())
	binary.BigEndian.PutUint32(pkt[12:], s.sourceID)
	s.sendToDevice(pkt)
}

func (s *session) sendSrtAck(lastRecvSeq uint32) {
	s.mu.Lock()
	ackNum := s.srtAckNumber
	s.srtAckNumber++
	peer := s.srtPeerSocketID
	s.mu.Unlock()

	pkt := make([]byte, 44)
	binary.BigEndian.PutUint16(pkt[0:], srtCtrlAck)
	binary.BigEndian.PutUint32(pkt[4:], ackNum)
	binary.BigEndian.PutUint32(pkt[8:], timestamp32())
	binary.BigEndian.PutUint32(pkt[12:], peer)
	binary.BigEndian.PutUint32(pkt[16:], (lastRecvSeq+1)&0x7fffffff) // last ACK'd seq + 1
	binary.BigEndian.PutUint32(pkt[20:], 8000)                       // RTT (us)
	binary.BigEndian.PutUint32(pkt[24:], 1000)                       // RTT variance (us)
	binary.BigEndian.PutUint32(pkt[28:], 8192)                       // available buffer (packets)
	binary.BigEndian.PutUint32(pkt[32:], 1000)                       // receiving rate (pkt/s)
	binary.BigEndian.PutUint32(pkt[36:], 100000)                     // estimated link capacity (pkt/s)
	binary.BigEndian.PutUint32(pkt[40:], 0)                          // receiving rate (bytes/s)
	s.sendToDevice(pkt)
}

// -- frame channel + lifecycle --

func (s *session) readFrame() (*Frame, error) {
	select {
	case f, ok := <-s.frames:
		if !ok {
			return nil, io.EOF
		}
		return f, nil
	case <-s.closeCh:
		return nil, io.EOF
	}
}

func (s *session) close() error {
	s.closeOnce.Do(func() {
		// Best-effort SRT shutdown + V3 teardown so the device releases the slot.
		s.sendTeardown()

		close(s.closeCh)
		s.mu.Lock()
		if s.flushTimer != nil {
			s.flushTimer.Stop()
			s.flushTimer = nil
		}
		s.mu.Unlock()
		_ = s.conn.Close()
		s.wg.Wait()
		s.closeFrames()
	})
	return nil
}

func (s *session) closeFrames() {
	// Close frames exactly once; readFrame also unblocks via closeCh.
	s.framesOnce.Do(func() { close(s.frames) })
}

func (s *session) sendTeardown() {
	s.mu.Lock()
	peerSocket := s.srtPeerSocketID
	s.mu.Unlock()

	if peerSocket != 0 {
		shutdown := make([]byte, 16)
		binary.BigEndian.PutUint16(shutdown[0:], srtCtrlShutdown)
		binary.BigEndian.PutUint32(shutdown[8:], timestamp32())
		binary.BigEndian.PutUint32(shutdown[12:], peerSocket)
		s.sendToDevice(shutdown)
	}
}

// -- send helpers --

func (s *session) sendToDevice(data []byte) {
	s.mu.Lock()
	peer := s.devicePeer
	s.mu.Unlock()
	if peer == nil {
		peer = &net.UDPAddr{IP: net.ParseIP(s.cfg.devicePublicIP), Port: s.cfg.devicePublicPort}
	}
	s.sendToAddr(data, peer)
}

func (s *session) sendToAddr(data []byte, addr *net.UDPAddr) {
	_, _ = s.conn.WriteToUDP(data, addr)
}

func (s *session) sendTo(data []byte, host string, port int) {
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	_, _ = s.conn.WriteToUDP(data, addr)
}

// -- accessors --

func (s *session) getDataSessionID() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dataSessionID
}

func (s *session) setDataSession(id uint32) {
	s.mu.Lock()
	s.dataSessionID = id
	s.mu.Unlock()
	s.dataOnce.Do(func() { close(s.dataCh) })
}

func (s *session) getPeerSocketID() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.srtPeerSocketID
}

func (s *session) localAddr() (string, int) {
	a, ok := s.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "0.0.0.0", 0
	}
	ip := a.IP.String()
	if a.IP == nil || a.IP.IsUnspecified() {
		ip = "0.0.0.0"
	}
	return ip, a.Port
}

// -- waiting helpers --

// waitFor blocks until ch closes or the timeout elapses, returning true if the
// channel fired.
func (s *session) waitFor(ch <-chan struct{}, timeout time.Duration) bool {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ch:
		return true
	case <-t.C:
		return false
	case <-s.closeCh:
		return false
	}
}

func (s *session) waitForDataSession(timeout time.Duration) {
	if s.getDataSessionID() != 0 {
		return
	}
	s.waitFor(s.dataCh, timeout)
}

func (s *session) sleep(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-s.closeCh:
	}
}

// -- small encoders --

func appendTLV(buf []byte, tag byte, value []byte) []byte {
	buf = append(buf, tag, byte(len(value)))
	return append(buf, value...)
}

func u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// frameV3 assembles a V3 header around an already-built body and stamps the CRC.
func frameV3(opcode uint16, seq uint32, mask V3Mask, body []byte) []byte {
	full := make([]byte, V3HeaderLen+len(body))
	full[0] = V3Magic
	full[1] = mask.Encode()
	binary.BigEndian.PutUint16(full[2:], opcode)
	binary.BigEndian.PutUint32(full[4:], seq)
	binary.BigEndian.PutUint16(full[8:], 0x6234)
	full[10] = V3HeaderLen
	full[11] = 0x00
	copy(full[V3HeaderLen:], body)
	full[11] = CRC8(full)
	return full
}

func timestamp32() uint32 {
	return uint32(time.Now().UnixMilli())
}

func randUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return mrand.Uint32()
	}
	return binary.BigEndian.Uint32(b[:])
}

// randomClientID mints a fresh non-zero client id for the PLAY_REQUEST expand
// header. The device does not validate it — it is a client-side correlation id.
func randomClientID() uint32 {
	for {
		if v := randUint32(); v != 0 {
			return v
		}
	}
}

// newUUID returns a random RFC 4122 v4 UUID string.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a math/rand fill; uniqueness suffices for a session tag.
		for i := range b {
			b[i] = byte(mrand.Intn(256))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
