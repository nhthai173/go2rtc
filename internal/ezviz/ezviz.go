package ezviz

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/AlexxIT/go2rtc/internal/api"
	"github.com/AlexxIT/go2rtc/internal/streams"
	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/ezviz"
)

const defaultHost = "api.hik-connect.com"

func Init() {
	handler := func(source string) (core.Producer, error) {
		return ezviz.NewProducer(source)
	}

	streams.HandleFunc("ezviz", handler)
	streams.HandleFunc("hikconnect", handler)

	// Account device/stream discovery for the "Add" page wizard.
	api.HandleFunc("api/ezviz", apiDiscover)
	api.HandleFunc("api/ezviz/records", apiRecords)
	api.HandleFunc("api/ezviz/days", apiDays)
	api.HandleFunc("api/ezviz/speed", apiSpeed)
	api.HandleFunc("api/ezviz/ptz", apiPTZ)
	api.HandleFunc("api/ezviz/devices", apiDevices)
}

// apiDiscover logs in to a Hik-Connect account and returns every channel/stream
// as a ready-to-add source. Read-only — it never changes config or the account.
func apiDiscover(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	account := q.Get("account")
	password := q.Get("password")
	host := q.Get("host")
	if host == "" {
		host = defaultHost
	}

	if account == "" || password == "" {
		http.Error(w, "account and password required", http.StatusBadRequest)
		return
	}

	// Discovery accepts the host with or without a scheme; the REST client wants a
	// full base URL while the per-stream source URL wants a bare host[:port].
	scheme := "https"
	if strings.HasPrefix(host, "http://") {
		scheme = "http"
	}
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://"), "/")

	found, err := ezviz.Discover(scheme+"://"+host, account, password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	items := make([]*api.Source, 0, len(found))
	for _, s := range found {
		status := "online"
		if !s.Online {
			status = "offline"
		}
		items = append(items, &api.Source{
			Name: fmt.Sprintf("%s ch%d %s", s.DeviceName, s.Channel, s.Subtype),
			Info: fmt.Sprintf("%s | %s | %s", s.Serial, s.DeviceType, status),
			URL:  streamURL(host, account, password, s),
		})
	}

	api.ResponseSources(w, items)
}

// streamURL builds a self-contained source URL for a discovered stream. The
// account credentials are embedded so the stream works without any further
// config, matching how a hand-written ezviz: URL carries them.
func streamURL(host, account, password string, s ezviz.DiscoveredStream) string {
	u := url.URL{
		Scheme: "ezviz",
		User:   url.UserPassword(account, password),
		Host:   host,
		Path:   "/" + s.Serial,
	}
	query := url.Values{}
	query.Set("channel", strconv.Itoa(s.Channel))
	query.Set("subtype", s.Subtype)
	u.RawQuery = query.Encode()
	return u.String()
}

// apiRecords lists one day of recordings of a channel (motion clips have type
// ALARM): ?account=&password=&serial=&channel=&day=2006-01-02[&host=].
func apiRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := q.Get("host")
	if host == "" {
		host = defaultHost
	}
	ch, _ := strconv.Atoi(q.Get("channel"))
	recs, err := ezviz.Records("https://"+host, q.Get("account"), q.Get("password"), q.Get("serial"), max(ch, 1), q.Get("day"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	api.ResponseJSON(w, recs)
}

// apiDays lists the days of a month that have recordings: same query as records,
// with month=2006-01 instead of day.
func apiDays(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := q.Get("host")
	if host == "" {
		host = defaultHost
	}
	ch, _ := strconv.Atoi(q.Get("channel"))
	days, err := ezviz.RecordedDays("https://"+host, q.Get("account"), q.Get("password"), q.Get("serial"), max(ch, 1), q.Get("month"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	api.ResponseJSON(w, days)
}

// apiSpeed changes the speed of the playback running on a channel:
// ?serial=&channel=&speed=2. The relay keeps up with 2x; 4x and 8x are best effort.
func apiSpeed(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ch, _ := strconv.Atoi(q.Get("channel"))
	n, _ := strconv.Atoi(q.Get("speed"))
	if n < 1 {
		http.Error(w, "speed must be a whole number of at least 1", http.StatusBadRequest)
		return
	}
	if err := ezviz.SetPlaybackSpeed(q.Get("serial"), max(ch, 1), n); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
}

// apiPTZ presses or releases a PTZ control:
// ?account=&password=&serial=&channel=&command=LEFT&action=START|STOP[&speed=5][&host=].
func apiPTZ(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := q.Get("host")
	if host == "" {
		host = defaultHost
	}
	ch, _ := strconv.Atoi(q.Get("channel"))
	speed, _ := strconv.Atoi(q.Get("speed"))
	if speed < 1 {
		speed = 5
	}
	action := strings.ToUpper(q.Get("action"))
	if action != "START" && action != "STOP" {
		http.Error(w, "action must be START or STOP", http.StatusBadRequest)
		return
	}
	err := ezviz.PTZ("https://"+host, q.Get("account"), q.Get("password"), q.Get("serial"), max(ch, 1), strings.ToUpper(q.Get("command")), action, speed)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

// apiDevices lists the devices of an account with their cameras: ?account=&password=[&host=].
func apiDevices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := q.Get("host")
	if host == "" {
		host = defaultHost
	}
	devs, err := ezviz.Devices("https://"+host, q.Get("account"), q.Get("password"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	api.ResponseJSON(w, devs)
}
