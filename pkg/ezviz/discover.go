package ezviz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
)

// DiscoveredStream is one selectable stream on an account: a specific channel of
// a device at a specific quality (main or sub).
type DiscoveredStream struct {
	Serial     string
	DeviceName string
	DeviceType string
	Channel    int
	Subtype    string // "main" | "sub"
	Online     bool
}

type discDevice struct {
	Serial     string `json:"deviceSerial"`
	Name       string `json:"name"`
	DeviceType string `json:"deviceType"`
	Status     int    `json:"status"` // 1 = online
}

type discCamera struct {
	CameraName string `json:"cameraName"`
	ChannelNo  int    `json:"channelNo"`
	Serial     string `json:"deviceSerial"`
	Quality    []struct {
		StreamType int `json:"streamType"` // 1 = main, 2 = sub
	} `json:"videoQualityInfos"`
}

// Discover logs in to a Hik-Connect account and enumerates every channel of
// every device along with the stream qualities (main/sub) each channel actually
// advertises. It is read-only: nothing about the account or devices is changed.
func Discover(baseURL, account, password string) ([]DiscoveredStream, error) {
	api := newAPIClient(baseURL)
	if err := api.login(account, password); err != nil {
		return nil, err
	}

	devices, err := api.getDevices()
	if err != nil {
		return nil, err
	}

	var out []DiscoveredStream
	for _, d := range devices {
		cams, err := api.getCameras(d.Serial)
		if err != nil {
			// One unreadable device shouldn't abort the whole listing.
			continue
		}
		for _, c := range cams {
			name := c.CameraName
			if name == "" {
				name = d.Name
			}
			for _, st := range streamTypes(c) {
				out = append(out, DiscoveredStream{
					Serial:     d.Serial,
					DeviceName: name,
					DeviceType: d.DeviceType,
					Channel:    c.ChannelNo,
					Subtype:    subtypeForStreamType(st),
					Online:     d.Status == 1,
				})
			}
		}
	}
	return out, nil
}

// streamTypes returns the distinct stream types a camera advertises (sorted, so
// main precedes sub). When the camera advertises none, both main and sub are
// assumed.
func streamTypes(c discCamera) []int {
	seen := map[int]bool{}
	var types []int
	for _, q := range c.Quality {
		if q.StreamType != 0 && !seen[q.StreamType] {
			seen[q.StreamType] = true
			types = append(types, q.StreamType)
		}
	}
	if len(types) == 0 {
		return []int{1, 2}
	}
	sort.Ints(types)
	return types
}

func subtypeForStreamType(t int) string {
	if t == 2 {
		return "sub"
	}
	return "main"
}

func (a *apiClient) getDevices() ([]discDevice, error) {
	const limit = 50

	var all []discDevice
	for offset := 0; ; offset += limit {
		path := fmt.Sprintf("/v3/userdevices/v1/resources/pagelist"+
			"?groupId=-1&limit=%d&offset=%d&filter=CONNECTION,STATUS", limit, offset)

		var out struct {
			Meta        apiMeta      `json:"meta"`
			DeviceInfos []discDevice `json:"deviceInfos"`
		}
		if err := a.getJSON(path, &out); err != nil {
			return nil, fmt.Errorf("ezviz: device list: %w", err)
		}
		if out.Meta.Code != 200 {
			return nil, fmt.Errorf("ezviz: device list failed: %d %s", out.Meta.Code, out.Meta.Message)
		}

		all = append(all, out.DeviceInfos...)
		if len(out.DeviceInfos) < limit {
			return all, nil
		}
	}
}

func (a *apiClient) getCameras(serial string) ([]discCamera, error) {
	var out struct {
		Meta        apiMeta      `json:"meta"`
		CameraInfos []discCamera `json:"cameraInfos"`
	}
	if err := a.getJSON("/v3/userdevices/v1/cameras/info?deviceSerial="+serial, &out); err != nil {
		return nil, fmt.Errorf("ezviz: camera list: %w", err)
	}
	if out.Meta.Code != 200 {
		return nil, fmt.Errorf("ezviz: camera list failed: %d %s", out.Meta.Code, out.Meta.Message)
	}
	return out.CameraInfos, nil
}

// getJSON performs an authenticated GET and decodes the JSON body into v.
func (a *apiClient) getJSON(path string, v any) error {
	req, err := http.NewRequest(http.MethodGet, a.host()+path, nil)
	if err != nil {
		return err
	}
	a.headers(req)

	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(v)
}
