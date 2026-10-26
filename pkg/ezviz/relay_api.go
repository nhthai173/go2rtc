package ezviz

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
