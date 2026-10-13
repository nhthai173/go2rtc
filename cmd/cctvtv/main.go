// go2rtc trimmed for the TV app: Xiaomi and Dahua P2P sources in, RTSP out, API for login and streams.
// Leaving out the other modules shrinks the binary and keeps exec/ffmpeg off the local API.
package main

import (
	"github.com/AlexxIT/go2rtc/internal/api"
	"github.com/AlexxIT/go2rtc/internal/app"
	"github.com/AlexxIT/go2rtc/internal/easy4ip"
	"github.com/AlexxIT/go2rtc/internal/rtsp"
	"github.com/AlexxIT/go2rtc/internal/streams"
	"github.com/AlexxIT/go2rtc/internal/xiaomi"
	"github.com/AlexxIT/go2rtc/pkg/shell"
)

func main() {
	app.Version = "1.9.14-cctvtv"
	app.Init()
	api.Init()
	streams.Init()
	rtsp.Init()
	xiaomi.Init()
	easy4ip.Init()
	shell.RunUntilSignal()
	easy4ip.Shutdown() // end the devices' P2P sessions properly, or they hold them for ~30 s
}
