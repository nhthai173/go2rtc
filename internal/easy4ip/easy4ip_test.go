package easy4ip

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/easy4ip"
	"github.com/stretchr/testify/require"
)

// Nothing answers here: sessions started by these tests never come up, and never reach the internet.
func init() { easy4ip.MainServer = "127.0.0.1:1" }

func TestParseURL(t *testing.T) {
	tg, err := parseURL("easy4ip://admin:p%40ss@9A0123456789/cam/realmonitor?channel=2&subtype=1&rtsp_port=8554&http_port=8080&relay=1&client_id=abc:37777#backchannel=0")
	require.NoError(t, err)
	require.Equal(t, "9A0123456789", tg.serial)
	require.Equal(t, "admin", tg.user)
	require.Equal(t, "p@ss", tg.pass)
	require.Equal(t, 8554, tg.rtspPort)
	require.Equal(t, 8080, tg.httpPort)
	require.True(t, tg.relay)
	require.Equal(t, "abc:37777", tg.clientID)

	// our options never reach the NVR, everything else does
	require.Equal(t, "rtsp://admin:p%40ss@127.0.0.1:41000/cam/realmonitor?channel=2&subtype=1#backchannel=0", tg.location(41000))
}

func TestParseURLDefaults(t *testing.T) {
	tg, err := parseURL("easy4ip://admin:pw@SN1/cam/realmonitor?channel=1")
	require.NoError(t, err)
	require.Equal(t, 554, tg.rtspPort)
	require.Zero(t, tg.httpPort)
	require.False(t, tg.relay)
	require.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:37777$`, tg.clientID)

	again, _ := parseURL("easy4ip://other:pw@SN1/x")
	require.Equal(t, tg.clientID, again.clientID, "stable per host and serial")
	other, _ := parseURL("easy4ip://admin:pw@SN2/x")
	require.NotEqual(t, tg.clientID, other.clientID)
}

func TestParseURLErrors(t *testing.T) {
	for _, bad := range []string{"easy4ip://SN1/path", "easy4ip://:pw@/path", "easy4ip://%zz"} {
		_, err := parseURL(bad)
		require.Error(t, err, bad)
	}
}

func TestAPIRegistersAndRemovesDevice(t *testing.T) {
	call := func(method, query string) (int, []byte) {
		w := httptest.NewRecorder()
		apiDahua(w, httptest.NewRequest(method, "/api/easy4ip?"+query, nil))
		return w.Code, w.Body.Bytes()
	}

	code, _ := call("PUT", "user=admin")
	require.Equal(t, 400, code, "serial is required")
	code, _ = call("PUT", "serial=SNAPI&user=admin&tunnel=nonsense")
	require.Equal(t, 400, code)

	code, body := call("PUT", "serial=SNAPI&user=admin&password=pw&tunnel=554:127.0.0.1:0&tunnel=80:127.0.0.1:0")
	require.Equal(t, 200, code, string(body))
	var info deviceInfo
	require.NoError(t, json.Unmarshal(body, &info))
	require.False(t, info.Up)
	require.Len(t, info.Ports, 2)

	// the tunnel port is open even before the session is up: players connect and wait
	addr := "127.0.0.1:" + strconv.Itoa(info.Ports["554"])
	c, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	_ = c.Close()

	// registering again changes nothing
	_, body = call("PUT", "serial=SNAPI&user=admin&password=pw&tunnel=554:127.0.0.1:0")
	var again deviceInfo
	require.NoError(t, json.Unmarshal(body, &again))
	require.Equal(t, info.Ports["554"], again.Ports["554"])

	_, body = call("GET", "")
	require.Contains(t, string(body), "SNAPI")

	code, _ = call("DELETE", "serial=SNAPI")
	require.Equal(t, 200, code)
	_, err = net.DialTimeout("tcp", addr, time.Second)
	require.Error(t, err, "the tunnel is closed with the device")
	code, _ = call("DELETE", "serial=SNAPI")
	require.Equal(t, 404, code)
}
