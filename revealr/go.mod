module revealr

go 1.24.5

require (
	github.com/mattn/go-sqlite3 v1.14.22 // For future session management (lightweight DB)
	github.com/spf13/cobra v1.8.0 // For robust CLI parsing
	golang.org/x/net v0.26.0 // For advanced networking, including ICMP
	gopkg.in/yaml.v3 v3.0.1 // For configuration parsing
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/sys v0.21.0 // indirect
)

// Run `go mod tidy` in your terminal after creating this file to fetch dependencies.
