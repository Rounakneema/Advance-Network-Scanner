// go.mod
module revealr

go 1.22

require (
	github.com/glebarez/go-sqlite v1.21.2
	github.com/google/gopacket v1.1.19 // Make sure this line is here
	github.com/spf13/cobra v1.8.0
	golang.org/x/net v0.26.0
	gopkg.in/yaml.v3 v3.0.1
)

// After any changes, run `go mod tidy`

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/sys v0.21.0 // indirect
	modernc.org/libc v1.22.5 // indirect
	modernc.org/mathutil v1.5.0 // indirect
	modernc.org/memory v1.5.0 // indirect
	modernc.org/sqlite v1.23.1 // indirect
)

// Run `go mod tidy` in your terminal after creating this file to fetch dependencies.
