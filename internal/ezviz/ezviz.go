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
