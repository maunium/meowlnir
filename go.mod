module go.mau.fi/meowlnir

go 1.23

require (
	github.com/lib/pq v1.10.9
	github.com/rs/zerolog v1.33.0
	go.mau.fi/util v0.7.1-0.20240901193650-bf007b10eaf6
	go.mau.fi/zeroconfig v0.1.3
	golang.org/x/exp v0.0.0-20240823005443-9b4947da3948
	gopkg.in/yaml.v3 v3.0.1
	maunium.net/go/mauflag v1.0.0
	maunium.net/go/mautrix v0.20.1-0.20240902204906-db8f2433a1db
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/petermattis/goid v0.0.0-20240813172612-4fcff4a6cae7 // indirect
	github.com/tidwall/gjson v1.17.3 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/yuin/goldmark v1.7.4 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

//replace maunium.net/go/mautrix => ../mautrix-go
//replace go.mau.fi/util => ../../Go/go-util
