package ezviz

import (
	"testing"
	"time"
)

func TestParseURL(t *testing.T) {
	cfg, err := parseURL("hikconnect://user@example.com:secret@api.hik-connect.com/L38239367?channel=2&subtype=sub")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.account != "user@example.com" {
		t.Errorf("account = %q", cfg.account)
	}
	if cfg.password != "secret" {
		t.Errorf("password = %q", cfg.password)
	}
	if cfg.baseURL != "https://api.hik-connect.com" {
		t.Errorf("baseURL = %q", cfg.baseURL)
	}
	if cfg.serial != "L38239367" {
		t.Errorf("serial = %q", cfg.serial)
	}
	if cfg.channel != 2 {
		t.Errorf("channel = %d", cfg.channel)
	}
	if cfg.subtype != "sub" {
		t.Errorf("subtype = %q", cfg.subtype)
	}
}

func TestParseURLDefaults(t *testing.T) {
	cfg, err := parseURL("ezviz://a@b.com:p@api.hik-connect.com/SERIAL")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.channel != 1 || cfg.subtype != "main" {
		t.Errorf("defaults: channel=%d subtype=%q", cfg.channel, cfg.subtype)
	}
}

func TestParseURLMissingFields(t *testing.T) {
	if _, err := parseURL("ezviz://api.hik-connect.com/SERIAL"); err == nil {
		t.Error("expected error for missing credentials")
	}
}

func TestParseURLPlayback(t *testing.T) {
	cfg, err := parseURL("ezviz://a@b.com:p@api.hik-connect.com/SERIAL?channel=4&start=2026-06-05T19:00:00&end=2026-06-05T19:01:00")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.isPlayback() {
		t.Fatal("expected playback")
	}
	if cfg.start != "2026-06-05T19:00:00" || cfg.stop != "2026-06-05T19:01:00" {
		t.Errorf("window = %q..%q", cfg.start, cfg.stop)
	}
	if busTypeFor(cfg) != 2 {
		t.Errorf("busType = %d, want 2", busTypeFor(cfg))
	}
}

func TestParseURLLiveIsNotPlayback(t *testing.T) {
	cfg, err := parseURL("ezviz://a@b.com:p@api.hik-connect.com/SERIAL?channel=1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.isPlayback() {
		t.Error("live URL must not be playback")
	}
	if busTypeFor(cfg) != 1 {
		t.Errorf("busType = %d, want 1", busTypeFor(cfg))
	}
}

func TestParseURLEndRequiresStart(t *testing.T) {
	if _, err := parseURL("ezviz://a@b.com:p@h/SERIAL?end=2026-06-05T19:01:00"); err == nil {
		t.Fatal("end without start must error")
	}
}

func TestParseURLStartOnlyIsOpenEnded(t *testing.T) {
	// start without end is valid: open-ended playback (stream from start to the
	// live edge). The device gets a synthesized far-future stop (start+24h).
	cfg, err := parseURL("ezviz://a@b.com:p@h/SERIAL?start=2026-06-05T19:00:00")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.mode() != modeOpenEnded {
		t.Fatalf("mode = %d, want modeOpenEnded", cfg.mode())
	}
	if !cfg.isPlayback() {
		t.Error("open-ended URL must be playback")
	}
	stop, err := cfg.effectiveStop()
	if err != nil {
		t.Fatal(err)
	}
	if stop != "2026-06-06T19:00:00" {
		t.Errorf("effectiveStop = %q, want start+24h 2026-06-06T19:00:00", stop)
	}
}

func TestConfigMode(t *testing.T) {
	cases := []struct {
		url  string
		want playbackMode
	}{
		{"ezviz://a@b.com:p@h/SERIAL", modeLive},
		{"ezviz://a@b.com:p@h/SERIAL?start=2026-06-05T19:00:00", modeOpenEnded},
		{"ezviz://a@b.com:p@h/SERIAL?start=2026-06-05T19:00:00&end=2026-06-05T19:01:00", modeWindow},
	}
	for _, c := range cases {
		cfg, err := parseURL(c.url)
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		if cfg.mode() != c.want {
			t.Errorf("%s: mode = %d, want %d", c.url, cfg.mode(), c.want)
		}
	}
}

func TestEffectiveStopWindowUnchanged(t *testing.T) {
	// A fixed window passes its stop through verbatim.
	cfg, err := parseURL("ezviz://a@b.com:p@h/SERIAL?start=2026-06-05T19:00:00&end=2026-06-05T19:05:00")
	if err != nil {
		t.Fatal(err)
	}
	stop, err := cfg.effectiveStop()
	if err != nil {
		t.Fatal(err)
	}
	if stop != "2026-06-05T19:05:00" {
		t.Errorf("effectiveStop = %q, want the requested 2026-06-05T19:05:00", stop)
	}
}

func TestParsePlaybackTime(t *testing.T) {
	// Wall-clock is preserved verbatim — no timezone shift (the device interprets
	// the window in its own local time).
	cases := map[string]string{
		"2026-06-05T19:00:00":  "2026-06-05T19:00:00",
		"2026-06-05 19:00:00":  "2026-06-05T19:00:00",
		"2026-06-05T19:00:00Z": "2026-06-05T19:00:00",
	}
	for in, want := range cases {
		got, err := parsePlaybackTime(in)
		if err != nil || got != want {
			t.Errorf("parsePlaybackTime(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := parsePlaybackTime("not-a-time"); err == nil {
		t.Error("bad time must error")
	}
}

// TestBuildPlayRequestBodyPlayback asserts a playback session emits busType=2
// and the requested recording window in the PLAY_REQUEST body.
func TestBuildPlayRequestBodyPlayback(t *testing.T) {
	sess, err := newSession(sessionConfig{
		deviceSerial: "SERIAL", channelNo: 4, streamType: 1,
		busType: 2, startTime: "2026-06-05T19:00:00", stopTime: "2026-06-05T19:01:00",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.close()

	attrs := decodeAttrs(sess.buildPlayRequestBody(), false)
	if v, _ := GetIntAttr(attrs, AttrBusType); v != 2 {
		t.Errorf("busType = %d, want 2", v)
	}
	if s, _ := GetStringAttr(attrs, AttrStartTime); s != "2026-06-05T19:00:00" {
		t.Errorf("start = %q", s)
	}
	if s, _ := GetStringAttr(attrs, AttrStopTime); s != "2026-06-05T19:01:00" {
		t.Errorf("stop = %q", s)
	}
}

// TestBuildPlayRequestBodyLive asserts a live session emits busType=1.
func TestBuildPlayRequestBodyLive(t *testing.T) {
	sess, err := newSession(sessionConfig{deviceSerial: "SERIAL", channelNo: 1, streamType: 1, busType: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.close()

	attrs := decodeAttrs(sess.buildPlayRequestBody(), false)
	if v, _ := GetIntAttr(attrs, AttrBusType); v != 1 {
		t.Errorf("busType = %d, want 1", v)
	}
}

// TestDialReachesTransport proves the data-plane wiring is reachable: NewProducer
// → Dial → connect() runs login and fails on the network for an unreachable
// host. It stays hermetic (no live cloud) by pointing at an invalid TLD that
// fails DNS resolution quickly, and asserts an error is returned promptly.
func TestDialReachesTransport(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		_, err := NewProducer("ezviz://a@b.com:p@host.invalid/SERIAL")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error dialing an unreachable host")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Dial did not return within timeout")
	}
}
