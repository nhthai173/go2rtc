package ezviz

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// config is parsed from the source URL:
//
//	ezviz://ACCOUNT:PASSWORD@API_HOST/SERIAL?channel=1&subtype=main
//	hikconnect://ACCOUNT:PASSWORD@api.hik-connect.com/L38239367?channel=1&subtype=sub
type config struct {
	baseURL  string // https://API_HOST
	account  string
	password string
	serial   string // device serial
	channel  int    // 1-based channel
	subtype  string // "main" (busType main stream) | "sub"

	// Playback (busType=2): set when the URL carries a start time. Live preview
	// (busType=1) leaves these zero.
	start string // recording window start, device format YYYY-MM-DDThh:mm:ss
	stop  string // recording window end (empty => open-ended, stream to live edge)
}

// playbackMode is the three-way source selection derived from the URL window.
// Modelled as an enum (not a pair of bools) so new states stay easy to add.
type playbackMode int

const (
	modeLive       playbackMode = iota // no start: live preview (busType=1)
	modeWindow                         // start+end: a fixed [start, stop] window
	modeOpenEnded                      // start only: stream from start to the live edge
)

func (c config) mode() playbackMode {
	if c.start == "" {
		return modeLive
	}
	if c.stop == "" {
		return modeOpenEnded
	}
	return modeWindow
}

// isPlayback reports whether the URL requested a recording window rather than
// live preview. A start time is the trigger, mirroring how the Milestone source
// switches to playback when a playbackTime is present.
func (c config) isPlayback() bool { return c.start != "" }

// Client is the Hik-Connect / EZVIZ cloud P2P transport.
//
// Responsibilities, by method (≈2.5–3k LOC budget):
//
//	connect():
//	  - REST login + per-session P2P secret fetch (the P2PServerKey + salt index
//	    are returned fresh per session and must never be cached/hardcoded), then
//	    device lookup.
//	  - V3 binary control protocol: TLV bodies, custom CRC-8, AES-128-CBC.
//	  - P2P_SETUP (0x0B02) → UDP hole-punch (0x0C00/0x0C01) → PLAY_REQUEST
//	    (0x0C02), over the V3 protocol.
//	  - Crypto: AES-CBC, ChaCha20, ECDH P-256, HMAC-SHA256 (stdlib +
//	    golang.org/x/crypto/chacha20).
//
//	ReadFrame():
//	  - The device's proprietary one-way SRT dialect: data/ACK routing plus a
//	    reorder buffer. Control (0x807f) and video (0x8060/0x8050) use separate
//	    ACK sequence spaces and MUST be routed independently, or the device
//	    flow-control stalls.
//	  - Media extraction: strip Hik-RTP (12B) + sub (13B) headers and reassemble
//	    RFC 7798 fragmentation units (type 49) into Annex-B NAL units. Playback
//	    recordings arrive as MPEG-PS instead and are demuxed separately.
type Client struct {
	cfg        config
	remoteAddr string // device NAT-mapped addr, filled by connect()
	session    *session
}

// Dial parses the source URL and establishes the P2P session.
func Dial(rawURL string) (*Client, error) {
	cfg, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}

	c := &Client{cfg: cfg}
	if err := c.connect(); err != nil {
		return nil, err
	}
	return c, nil
}

func parseURL(rawURL string) (config, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return config{}, fmt.Errorf("ezviz: bad url: %w", err)
	}

	pass, _ := u.User.Password()
	cfg := config{
		baseURL:  "https://" + u.Host,
		account:  u.User.Username(),
		password: pass,
		serial:   strings.Trim(u.Path, "/"),
		channel:  1,
		subtype:  "main",
	}

	q := u.Query()
	if v := q.Get("channel"); v != "" {
		if cfg.channel, err = strconv.Atoi(v); err != nil {
			return config{}, fmt.Errorf("ezviz: bad channel %q: %w", v, err)
		}
	}
	if v := q.Get("subtype"); v != "" {
		cfg.subtype = v
	}

	// Playback window. Presence of start switches the session to recording
	// playback (busType=2). `end` is optional: with both ends it streams the fixed
	// [start, stop] window; with start only it is open-ended and streams from start
	// to the live edge (see connect — we hand the device a far-future stop, which it
	// honours until the recording catches up to "now" and then goes silent). Times
	// are camera-local wall clock and passed through verbatim.
	if v := q.Get("start"); v != "" {
		if cfg.start, err = parsePlaybackTime(v); err != nil {
			return config{}, fmt.Errorf("ezviz: bad start %q: %w", v, err)
		}
	}
	if v := q.Get("end"); v != "" {
		if cfg.stop, err = parsePlaybackTime(v); err != nil {
			return config{}, fmt.Errorf("ezviz: bad end %q: %w", v, err)
		}
	}
	if cfg.stop != "" && !cfg.isPlayback() {
		return config{}, errors.New("ezviz: end requires start")
	}

	if cfg.account == "" || cfg.password == "" || cfg.serial == "" {
		return config{}, errors.New("ezviz: url needs account:password@host/serial")
	}
	return cfg, nil
}

// deviceTimeLayout is the timestamp format the device's PLAY_REQUEST expects.
const deviceTimeLayout = "2006-01-02T15:04:05"

// openEndedSpan is the stop offset handed to the device for open-ended playback.
// The device needs a concrete [start, stop] — an empty stop streams nothing — but
// it stops sending once playback catches the live edge regardless of how far the
// stop is, so any value comfortably past "now" works. 24 h covers a full day of
// catch-up from the start time; it is camera-local arithmetic (start + span) so no
// timezone is involved.
const openEndedSpan = 24 * time.Hour

// playbackIdleTimeout closes a playback session once the device has been silent
// this long after delivering media. The device sends no end-of-stream marker at a
// window end or the live edge (it just goes quiet — confirmed against hardware and
// iVMS-4200), so this turns that silence into a clean io.EOF instead of hanging
// until the downstream read-timeout. Comfortably longer than any intra-stream gap
// observed during continuous playback (sub-second).
const playbackIdleTimeout = 10 * time.Second

// effectiveStop is the stop time sent to the device for this config: the requested
// stop for a fixed window, or start+openEndedSpan for open-ended playback.
func (c config) effectiveStop() (string, error) {
	if c.mode() != modeOpenEnded {
		return c.stop, nil
	}
	t, err := time.Parse(deviceTimeLayout, c.start)
	if err != nil {
		return "", fmt.Errorf("ezviz: bad start %q: %w", c.start, err)
	}
	return t.Add(openEndedSpan).Format(deviceTimeLayout), nil
}

// parsePlaybackTime accepts a few common timestamp spellings and normalizes them
// to the device's layout. The wall-clock value is passed through verbatim — the
// device interprets the window in its own configured timezone, so the user
// specifies camera-local time and we must not shift it.
func parsePlaybackTime(v string) (string, error) {
	for _, layout := range []string{deviceTimeLayout, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.Format(deviceTimeLayout), nil
		}
	}
	return "", fmt.Errorf("want %s", deviceTimeLayout)
}

// connect performs: login → P2P config + secret fetch → assemble the session
// config → P2P_SETUP → hole-punch → PLAY_REQUEST → SRT handshake. Media then
// flows asynchronously and is drained by ReadFrame.
func (c *Client) connect() error {
	api := newAPIClient(c.cfg.baseURL)
	if err := api.login(c.cfg.account, c.cfg.password); err != nil {
		return err
	}

	p2p, err := api.getP2PConfig(c.cfg.serial)
	if err != nil {
		return err
	}

	secret, err := api.getP2PSecret()
	if err != nil {
		return err
	}

	// The link key (inner PLAY_REQUEST encryption) is the first 32 ASCII chars
	// of the KMS secret.
	linkKey := []byte(p2p.secretKey)
	if len(linkKey) < 32 {
		return fmt.Errorf("ezviz: KMS secret too short: %d chars", len(linkKey))
	}
	linkKey = linkKey[:32]

	// P2P servers come from the per-device config; fall back to the
	// account-level list returned alongside the secret.
	servers := p2p.servers
	if len(servers) == 0 {
		servers = secret.servers
	}
	if len(servers) == 0 {
		return errors.New("ezviz: no P2P servers available")
	}

	// Device NAT-mapped stream endpoint: prefer the WAN IP, fall back to NET IP.
	deviceIP := p2p.wanIP
	if deviceIP == "" {
		deviceIP = p2p.netIP
	}

	stop, err := c.cfg.effectiveStop()
	if err != nil {
		return err
	}

	cfg := sessionConfig{
		deviceSerial:     c.cfg.serial,
		devicePublicIP:   deviceIP,
		devicePublicPort: p2p.netStreamPort,
		p2pServers:       servers,
		p2pKey:           secret.key,
		p2pLinkKey:       linkKey,
		p2pKeyVersion:    p2p.keyVersion,
		p2pKeySaltIndex:  secret.saltIndex,
		p2pKeySaltVer:    secret.saltVer,
		userID:           extractUserID(api.sessionID),
		clientID:         randomClientID(),
		channelNo:        c.cfg.channel,
		streamType:       streamTypeFor(c.cfg.subtype),
		busType:          busTypeFor(c.cfg),
		startTime:        c.cfg.start,
		stopTime:         stop,
	}
	// Playback gives no end-of-stream marker; arm the idle watchdog so the live
	// edge / window end becomes a clean EOF rather than a hang.
	if c.cfg.isPlayback() {
		cfg.playbackIdle = playbackIdleTimeout
	}

	sess, err := newSession(cfg)
	if err != nil {
		return err
	}
	if err := sess.start(); err != nil {
		_ = sess.close()
		return err
	}

	c.session = sess
	if deviceIP != "" {
		c.remoteAddr = fmt.Sprintf("%s:%d", deviceIP, p2p.netStreamPort)
	}
	return nil
}

// streamTypeFor maps a URL subtype to the device stream type: main=1, sub=2.
func streamTypeFor(subtype string) int {
	if subtype == "sub" {
		return 2
	}
	return 1
}

// busTypeFor selects live preview (1) or recording playback (2).
func busTypeFor(cfg config) int {
	if cfg.isPlayback() {
		return 2
	}
	return 1
}

// ReadFrame returns the next demuxed access unit, or io.EOF on stream end.
func (c *Client) ReadFrame() (*Frame, error) {
	if c.session == nil {
		return nil, errors.New("ezviz: session not started")
	}
	return c.session.readFrame()
}

func (c *Client) Close() error {
	if c.session == nil {
		return nil
	}
	return c.session.close()
}

func (c *Client) Protocol() string { return "udp" }

func (c *Client) RemoteAddr() string {
	if c.remoteAddr != "" {
		return c.remoteAddr
	}
	return c.cfg.baseURL
}
