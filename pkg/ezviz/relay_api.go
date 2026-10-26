package ezviz

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// relayInfo is everything the VTM cloud relay needs to start a live stream:
// the VTM TCP endpoint, the resource's business parameters and a VTDU token.
type relayInfo struct {
	host  string
	port  int
	biz   url.Values // streamBizUrl query of the resource (e.g. biz=2)
	token string     // VTDU token (ssn parameter of the ysproto URL)
}

type vtmServer struct {
	Domain     string `json:"domain"`
	ExternalIP string `json:"externalIp"`
	InternalIP string `json:"internalIp"`
	Port       int    `json:"port"`
}

func (v vtmServer) endpoint() (string, int, error) {
	host := v.ExternalIP
	if host == "" {
		host = v.Domain
	}
	if host == "" {
		host = v.InternalIP
	}
	if host == "" || v.Port < 1 || v.Port > 65535 {
		return "", 0, errors.New("ezviz: relay: VTM server has no usable endpoint")
	}
	return host, v.Port, nil
}

// getJSON GETs base+path with the session headers and decodes the JSON body.
func (a *apiClient) getJSONFrom(base, path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	a.headers(req)

	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return json.Unmarshal(b, out)
}

// getRelayInfo resolves the VTM relay endpoint and a VTDU token for one channel.
// It must be called after login.
func (a *apiClient) getRelayInfo(serial string, channel int) (*relayInfo, error) {
	const limit = 50

	var (
		biz    url.Values
		server vtmServer
		found  bool
	)

	for offset := 0; !found; offset += limit {
		path := fmt.Sprintf("/v3/userdevices/v1/resources/pagelist?groupId=-1&limit=%d&offset=%d&filter=VTM", limit, offset)

		var out struct {
			ResourceInfos []struct {
				DeviceSerial string `json:"deviceSerial"`
				LocalIndex   string `json:"localIndex"`
				ResourceID   string `json:"resourceId"`
				StreamBizURL string `json:"streamBizUrl"`
			} `json:"resourceInfos"`
			VTM map[string]vtmServer `json:"VTM"`
		}
		if err := a.getJSONFrom(a.host(), path, &out); err != nil {
			return nil, fmt.Errorf("ezviz: relay: pagelist: %w", err)
		}

		for _, r := range out.ResourceInfos {
			if r.DeviceSerial == serial && r.LocalIndex == strconv.Itoa(channel) {
				biz, _ = url.ParseQuery(strings.TrimPrefix(r.StreamBizURL, "?"))
				server = out.VTM[r.ResourceID]
				found = true
				break
			}
		}
		if !found && len(out.ResourceInfos) < limit {
			return nil, fmt.Errorf("ezviz: relay: no stream resource for %s channel %d", serial, channel)
		}
	}

	// The app refreshes the VTM server per channel before playing; the response
	// overrides the pagelist entry when it carries an endpoint.
	var vi struct {
		StreamServerConfig vtmServer `json:"streamServerConfig"`
	}
	if err := a.getJSONFrom(a.host(), fmt.Sprintf("/v3/streaming/vtm/%s/%d", serial, channel), &vi); err == nil {
		if h, _, err := vi.StreamServerConfig.endpoint(); err == nil && h != "" {
			server = vi.StreamServerConfig
		}
	}

	host, port, err := server.endpoint()
	if err != nil {
		return nil, err
	}

	token, err := a.getVTDUToken()
	if err != nil {
		return nil, err
	}

	return &relayInfo{host: host, port: port, biz: biz, token: token}, nil
}

// authBase returns the auth service base URL. The system info normally carries
// it; when it is null (seen on regional Hik-Connect accounts) it is derived from
// the API host: apii<region>.<domain> -> https://<region>auth.<domain>.
func (a *apiClient) authBase() (string, error) {
	var si struct {
		SystemConfigInfo struct {
			AuthAddr string `json:"authAddr"`
		} `json:"systemConfigInfo"`
	}
	if err := a.getJSONFrom(a.host(), "/v3/configurations/system/info", &si); err == nil {
		if v := strings.TrimSpace(si.SystemConfigInfo.AuthAddr); v != "" && !strings.Contains(strings.ToLower(v), "null") {
			if !strings.HasPrefix(v, "http") {
				v = "https://" + v
			}
			return strings.TrimRight(v, "/"), nil
		}
	}
	return deriveAuthBase(a.host())
}

func deriveAuthBase(apiBase string) (string, error) {
	u, err := url.Parse(apiBase)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if !strings.HasPrefix(host, "apii") {
		return "", fmt.Errorf("ezviz: relay: cannot derive auth host from %q", host)
	}
	region, domain, ok := strings.Cut(strings.TrimPrefix(host, "apii"), ".")
	if !ok || region == "" || domain == "" {
		return "", fmt.Errorf("ezviz: relay: cannot derive auth host from %q", host)
	}
	return "https://" + region + "auth." + domain, nil
}

// sessionSign extracts the "s" claim of the session JWT, which signs the VTDU
// token request.
func sessionSign(sessionID string) (string, error) {
	parts := strings.Split(sessionID, ".")
	if len(parts) < 2 {
		return "", errors.New("ezviz: relay: session is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", err
	}
	var claims struct {
		S string `json:"s"`
	}
	if err = json.Unmarshal(raw, &claims); err != nil || claims.S == "" {
		return "", errors.New("ezviz: relay: session has no sign claim")
	}
	return claims.S, nil
}

func (a *apiClient) getVTDUToken() (string, error) {
	base, err := a.authBase()
	if err != nil {
		return "", err
	}
	sign, err := sessionSign(a.sessionID)
	if err != nil {
		return "", err
	}

	var out struct {
		RetCode int      `json:"retcode"`
		Tokens  []string `json:"tokens"`
	}
	q := url.Values{"ssid": {a.sessionID}, "sign": {sign}}
	if err = a.getJSONFrom(base, "/vtdutoken2?"+q.Encode(), &out); err != nil {
		return "", fmt.Errorf("ezviz: relay: vtdu token: %w", err)
	}
	if out.RetCode != 0 || len(out.Tokens) == 0 {
		return "", fmt.Errorf("ezviz: relay: vtdu token refused (retcode %d)", out.RetCode)
	}
	return out.Tokens[0], nil
}

// streamURL builds the ysproto URL carried in the StreamInfoReq. stream is the
// relay stream index (1 = main, 2 = sub).
func (r *relayInfo) streamURL(serial string, channel, stream int) string {
	q := url.Values{}
	for k, v := range r.biz {
		q[k] = v
	}
	q.Set("dev", serial)
	q.Set("chn", strconv.Itoa(channel))
	q.Set("stream", strconv.Itoa(stream))
	q.Set("cln", "9")
	q.Set("isp", "0")
	q.Set("auth", "1")
	q.Set("ssn", r.token)
	q.Set("vip", "0")
	q.Set("timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	return fmt.Sprintf("ysproto://%s:%d/live?%s", r.host, r.port, q.Encode())
}

// playbackURL builds the ysproto URL of a recording window. The relay takes the
// window as compact UTC-looking stamps (really camera-local, like the device
// search) and wants the client identity params the app sends with it.
func (r *relayInfo) playbackURL(cfg config) (string, error) {
	begin, err := time.Parse(deviceTimeLayout, cfg.start)
	if err != nil {
		return "", fmt.Errorf("ezviz: relay: bad start %q: %w", cfg.start, err)
	}
	// Open-ended: to the end of that day, as the app asks for (a longer window is refused).
	end := time.Date(begin.Year(), begin.Month(), begin.Day(), 23, 59, 59, 0, time.UTC)
	if cfg.stop != "" {
		if end, err = time.Parse(deviceTimeLayout, cfg.stop); err != nil {
			return "", fmt.Errorf("ezviz: relay: bad end %q: %w", cfg.stop, err)
		}
	}
	const stamp = "20060102T150405Z"
	u := r.streamURL(cfg.serial, cfg.channel, 1)
	u = strings.Replace(u, "/live?", "/playback?", 1)
	q := url.Values{
		"begin": {begin.Format(stamp)}, "end": {end.Format(stamp)},
		"serial": {cfg.serial}, "lid": {fmt.Sprintf("%016x%016x", rand.Uint64(), rand.Uint64())},
		"tls": {"0"}, "rnd": {strconv.FormatUint(uint64(rand.Uint32()), 10)},
		"udpecdh": {"0"}, "devecdh": {"0"},
	}
	return u + "&" + q.Encode(), nil
}

// Record is one recording span reported by the device search. Type is "ALARM"
// for motion/event clips and the plain schedule type otherwise.
type Record struct {
	Begin string `json:"begin"` // camera-local, 2006-01-02T15:04:05
	End   string `json:"end"`
	Type  string `json:"type"`
}

// Records lists the recordings of one channel on one day (camera-local).
// ponytail: single page of up to 500 spans; follow isFinished if a day ever has more.
func Records(baseURL, account, password, serial string, channel int, day string) ([]Record, error) {
	return RecordsRange(baseURL, account, password, serial, channel, day, day)
}

// RecordsRange lists the recordings between two camera-local days, inclusive.
// The search returns about 50 spans per call, so it pages on the last start time.
func RecordsRange(baseURL, account, password, serial string, channel int, from, to string) ([]Record, error) {
	a, err := sessionFor(baseURL, account, password)
	if err != nil {
		return nil, err
	}
	const layout = "2006-01-02T15:04:05"
	var all []Record
	start := from + " 00:00:00"
	for page := 0; page < 100; page++ {
		q := url.Values{
			"deviceSerial": {serial}, "channelNo": {strconv.Itoa(channel)},
			"startTime": {start}, "stopTime": {to + " 23:59:59"}, "size": {"500"},
		}
		var out struct {
			Records    []Record `json:"records"`
			IsFinished any      `json:"isFinished"`
		}
		if err := a.getJSONFrom(a.host(), "/v3/streaming/records?"+q.Encode(), &out); err != nil {
			dropSession(baseURL, account, password)
			return nil, fmt.Errorf("ezviz: records: %w", err)
		}
		n := len(out.Records)
		for _, r := range out.Records {
			if len(all) == 0 || r.Begin > all[len(all)-1].Begin {
				all = append(all, r)
			}
		}
		if n == 0 || strings.EqualFold(fmt.Sprint(out.IsFinished), "true") {
			break
		}
		last, err := time.Parse(layout, out.Records[n-1].Begin)
		if err != nil {
			break
		}
		start = last.Add(time.Second).Format("2006-01-02 15:04:05")
	}
	return all, nil
}

// RecordedDays lists the days (2006-01-02) of a month that have any recording.
func RecordedDays(baseURL, account, password, serial string, channel int, month string) ([]string, error) {
	first, err := time.Parse("2006-01", month)
	if err != nil {
		return nil, fmt.Errorf("ezviz: bad month %q: %w", month, err)
	}
	recs, err := RecordsRange(baseURL, account, password, serial, channel, first.Format("2006-01-02"), first.AddDate(0, 1, -1).Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	var days []string
	for _, r := range recs {
		if d := r.Begin[:10]; len(days) == 0 || days[len(days)-1] != d {
			days = append(days, d)
		}
	}
	return days, nil
}

// sessions caches one logged-in client per account: a login takes a second or two,
// and seeks, speed changes and PTZ presses each need the API.
var (
	sessionsMu sync.Mutex
	sessions   = map[string]*cachedSession{}
)

type cachedSession struct {
	api *apiClient
	at  time.Time
}

const sessionTTL = 30 * time.Minute

func sessionFor(baseURL, account, password string) (*apiClient, error) {
	key := baseURL + "|" + account + "|" + password
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if c, ok := sessions[key]; ok && time.Since(c.at) < sessionTTL {
		return c.api, nil
	}
	a := newAPIClient(baseURL)
	if err := a.login(account, password); err != nil {
		return nil, err
	}
	sessions[key] = &cachedSession{a, time.Now()}
	return a, nil
}

// dropSession forgets a cached login (the server rejected it); the next call logs in again.
func dropSession(baseURL, account, password string) {
	sessionsMu.Lock()
	delete(sessions, baseURL+"|"+account+"|"+password)
	sessionsMu.Unlock()
}

// PTZ moves a PTZ channel: command is LEFT, RIGHT, UP, DOWN, ZOOMIN or ZOOMOUT, action START or STOP.
// ponytail: only LEFT/RIGHT were tried (the camera pans only); the other commands follow the EZVIZ API names.
func PTZ(baseURL, account, password, serial string, channel int, command, action string, speed int) error {
	for try := 0; try < 2; try++ {
		a, err := sessionFor(baseURL, account, password)
		if err != nil {
			return err
		}
		f := url.Values{
			"command": {command}, "action": {action}, "channelNo": {strconv.Itoa(channel)},
			"speed": {strconv.Itoa(speed)}, "uuid": {strconv.FormatInt(time.Now().UnixNano(), 36)}, "serial": {serial},
		}
		req, err := http.NewRequest(http.MethodPut, a.host()+"/v3/devices/"+serial+"/ptzControl", strings.NewReader(f.Encode()))
		if err != nil {
			return err
		}
		a.headers(req)
		resp, err := a.http.Do(req)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var m struct {
			Meta apiMeta `json:"meta"`
		}
		_ = json.Unmarshal(b, &m)
		if resp.StatusCode == http.StatusOK && m.Meta.Code == 200 {
			return nil
		}
		if try == 0 && (resp.StatusCode == http.StatusUnauthorized || m.Meta.Code == 401 || m.Meta.Code == 403) {
			dropSession(baseURL, account, password)
			continue
		}
		return fmt.Errorf("ezviz: ptz: http %d code %d %s", resp.StatusCode, m.Meta.Code, m.Meta.Message)
	}
	return errors.New("ezviz: ptz: session rejected")
}

// Device is one device of the account with its cameras.
type Device struct {
	Serial   string    `json:"serial"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Online   bool      `json:"online"`
	Channels []Channel `json:"channels"`
}

// Channel is one camera of a [Device].
type Channel struct {
	No   int    `json:"channel"`
	Name string `json:"name"`
}

// Devices lists the devices of the account and their cameras (the names the account app shows).
func Devices(baseURL, account, password string) ([]Device, error) {
	a, err := sessionFor(baseURL, account, password)
	if err != nil {
		return nil, err
	}
	devs, err := a.getDevices()
	if err != nil {
		dropSession(baseURL, account, password)
		return nil, err
	}
	var out []Device
	for _, d := range devs {
		item := Device{Serial: d.Serial, Name: d.Name, Type: d.DeviceType, Online: d.Status == 1}
		cams, err := a.getCameras(d.Serial)
		if err != nil {
			continue // one unreadable device must not hide the others
		}
		for _, c := range cams {
			name := c.CameraName
			if name == "" {
				name = d.Name
			}
			item.Channels = append(item.Channels, Channel{c.ChannelNo, name})
		}
		sort.Slice(item.Channels, func(i, j int) bool { return item.Channels[i].No < item.Channels[j].No })
		out = append(out, item)
	}
	return out, nil
}
