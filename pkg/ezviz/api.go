package ezviz

// REST client for the Hik-Connect cloud account API. It performs the steps
// needed to bootstrap a P2P streaming session:
//
//   - login: exchange account credentials for a session id (a JWT) and the
//     region-specific API domain.
//   - getP2PConfig: per-device P2P server list, the device's NAT-mapped stream
//     endpoint (CONNECTION), and the KMS secret used to derive the inner link
//     key for PLAY_REQUEST encryption.
//   - getP2PSecret: the account-level P2P server key + salt index. The server
//     keeps eight salt-indexed keys and returns a fresh one per call, so this is
//     fetched per session and never cached or hardcoded.
//
// The endpoint shapes were established from observed cloud traffic.

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// channelType identifies the client to the cloud account API.
	channelType = "55"
	// featureCode is a per-install fingerprint; a fixed value is accepted.
	featureCode = "deadbeef"
)

// apiServer is one P2P/STUN server endpoint returned by the cloud.
type apiServer struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// p2pConfig is the per-device P2P configuration resolved from the cloud.
type p2pConfig struct {
	servers    []apiServer
	secretKey  string // KMS secret; first 32 ASCII chars seed the inner link key
	keyVersion int
	// Device NAT-mapped stream endpoint.
	wanIP         string
	netIP         string
	netStreamPort int
}

// p2pSecret is the account-level rotating P2P server key plus its salt.
type p2pSecret struct {
	key       []byte // 32 bytes
	saltIndex byte
	saltVer   byte
	servers   []apiServer
}

// apiClient talks to the Hik-Connect REST API.
type apiClient struct {
	baseURL   string
	http      *http.Client
	sessionID string
	apiDomain string
}

func newAPIClient(baseURL string) *apiClient {
	return &apiClient{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// host returns the base for the next request: the region API domain once login
// has resolved it, otherwise the bootstrap host.
func (a *apiClient) host() string {
	base := a.baseURL
	if a.apiDomain != "" {
		base = a.apiDomain
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + base
	}
	return base
}

func (a *apiClient) headers(req *http.Request) {
	req.Header.Set("clientType", channelType)
	req.Header.Set("featureCode", featureCode)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if a.sessionID != "" {
		req.Header.Set("sessionId", a.sessionID)
	}
}

// apiMeta is the envelope status present on most account API responses.
type apiMeta struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// login exchanges credentials for a session id and resolves the region API
// domain. The password is sent as a lowercase hex MD5 digest.
func (a *apiClient) login(account, password string) error {
	digest := md5.Sum([]byte(password))
	form := url.Values{
		"account":     {account},
		"password":    {hex.EncodeToString(digest[:])},
		"featureCode": {featureCode},
	}

	req, err := http.NewRequest(http.MethodPost, a.host()+"/v3/users/login/v2", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	a.headers(req)

	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("ezviz: login: %w", err)
	}
	defer resp.Body.Close()

	var out struct {
		Meta         apiMeta `json:"meta"`
		LoginSession struct {
			SessionID   string `json:"sessionId"`
			RfSessionID string `json:"rfSessionId"`
		} `json:"loginSession"`
		LoginArea struct {
			APIDomain string `json:"apiDomain"`
		} `json:"loginArea"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("ezviz: login decode: %w", err)
	}
	if out.Meta.Code != 200 {
		return fmt.Errorf("ezviz: login failed: %d %s", out.Meta.Code, out.Meta.Message)
	}
	if out.LoginSession.SessionID == "" {
		return fmt.Errorf("ezviz: login returned no session id")
	}

	a.sessionID = out.LoginSession.SessionID
	if out.LoginArea.APIDomain != "" {
		a.apiDomain = out.LoginArea.APIDomain
	}
	return nil
}

// getP2PConfig resolves the per-device P2P servers, NAT-mapped stream endpoint
// and KMS secret from the device pagelist. The endpoint is paginated, so it
// pages until the serial is found or the device list is exhausted — accounts
// with more than one page of devices would otherwise fail to find a camera that
// falls beyond the first page.
func (a *apiClient) getP2PConfig(serial string) (*p2pConfig, error) {
	const limit = 50

	for offset := 0; ; offset += limit {
		path := fmt.Sprintf("/v3/userdevices/v1/resources/pagelist"+
			"?groupId=-1&limit=%d&offset=%d&filter=P2P,KMS,CONNECTION", limit, offset)

		req, err := http.NewRequest(http.MethodGet, a.host()+path, nil)
		if err != nil {
			return nil, err
		}
		a.headers(req)

		resp, err := a.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("ezviz: p2p config: %w", err)
		}

		var out struct {
			Meta        apiMeta                `json:"meta"`
			DeviceInfos []json.RawMessage      `json:"deviceInfos"`
			P2P         map[string][]apiServer `json:"P2P"`
			KMS         map[string]struct {
				SecretKey string `json:"secretKey"`
				Version   string `json:"version"`
			} `json:"KMS"`
			CONNECTION map[string]struct {
				NetIP         string `json:"netIp"`
				WanIP         string `json:"wanIp"`
				NetStreamPort int    `json:"netStreamPort"`
			} `json:"CONNECTION"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("ezviz: p2p config decode: %w", err)
		}
		if out.Meta.Code != 200 {
			return nil, fmt.Errorf("ezviz: p2p config failed: %d %s", out.Meta.Code, out.Meta.Message)
		}

		if servers, ok := out.P2P[serial]; ok {
			kms, ok := out.KMS[serial]
			if !ok {
				return nil, fmt.Errorf("ezviz: no KMS entry for device %s", serial)
			}
			conn, ok := out.CONNECTION[serial]
			if !ok {
				return nil, fmt.Errorf("ezviz: no CONNECTION entry for device %s", serial)
			}

			keyVersion, err := strconv.Atoi(kms.Version)
			if err != nil {
				return nil, fmt.Errorf("ezviz: invalid KMS version %q: %w", kms.Version, err)
			}

			return &p2pConfig{
				servers:       servers,
				secretKey:     kms.SecretKey,
				keyVersion:    keyVersion,
				wanIP:         conn.WanIP,
				netIP:         conn.NetIP,
				netStreamPort: conn.NetStreamPort,
			}, nil
		}

		// Last page reached without finding the serial.
		if len(out.DeviceInfos) < limit {
			return nil, fmt.Errorf("ezviz: no P2P servers for device %s", serial)
		}
	}
}

// getP2PSecret fetches the rotating account-level P2P server key and salt. The
// key arrives as a decimal byte-array string ("[12,34,...]") of 32 signed
// bytes.
func (a *apiClient) getP2PSecret() (*p2pSecret, error) {
	req, err := http.NewRequest(http.MethodPost, a.host()+"/api/p2p/configurations", nil)
	if err != nil {
		return nil, err
	}
	a.headers(req)

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ezviz: p2p secret: %w", err)
	}
	defer resp.Body.Close()

	var out struct {
		ServerInfos []apiServer `json:"serverInfos"`
		ResultCode  string      `json:"resultCode"`
		ResultDes   string      `json:"resultDes"`
		Secret      struct {
			Version   int    `json:"version"`
			SaltIndex int    `json:"saltIndex"`
			Data      string `json:"data"`
		} `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("ezviz: p2p secret decode: %w", err)
	}
	if out.ResultCode != "0" || out.Secret.Data == "" {
		return nil, fmt.Errorf("ezviz: p2p secret failed: resultCode=%s %s", out.ResultCode, out.ResultDes)
	}

	key, err := parseByteArray(out.Secret.Data)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("ezviz: expected 32-byte P2P key, got %d", len(key))
	}

	return &p2pSecret{
		key:       key,
		saltIndex: byte(out.Secret.SaltIndex),
		saltVer:   byte(out.Secret.Version),
		servers:   out.ServerInfos,
	}, nil
}

// parseByteArray turns a "[b0, b1, ..., bN]" decimal byte-array string (signed
// values are masked to a byte) into a byte slice.
func parseByteArray(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]byte, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("ezviz: bad byte %q: %w", p, err)
		}
		out[i] = byte(v & 0xff)
	}
	return out, nil
}

// extractUserID returns the `aud` claim from a Hik-Connect session JWT. The
// claim is the account user id used in PLAY_REQUEST expand headers.
func extractUserID(sessionID string) string {
	parts := strings.Split(sessionID, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Aud string `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Aud
}
