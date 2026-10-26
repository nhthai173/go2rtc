package ezviz

import (
	"testing"

	"github.com/AlexxIT/go2rtc/internal/streams"
)

// TestSchemeRegistration proves Init() registers both URL schemes with the
// go2rtc stream registry.
func TestSchemeRegistration(t *testing.T) {
	Init()

	for _, src := range []string{
		"ezviz://a@b.com:p@api.hik-connect.com/SERIAL",
		"hikconnect://a@b.com:p@api.hik-connect.com/SERIAL",
	} {
		if !streams.HasProducer(src) {
			t.Errorf("scheme not registered for %q", src)
		}
	}
}
