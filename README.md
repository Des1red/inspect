# inspect

A simple command-line IP scanner written in Go. Checks if a host is alive via ICMP echo, then performs a full TCP connect port scan and enriches open ports with service name, banner, and latency.

## Requirements

- Go
- Root privileges (raw ICMP sockets require it)

## Installation 

```
sudo go run main.go --install
```

## Usage

```
sudo inspect
```

You'll be prompted for a target IP:

```
IP >> 192.168.1.140
```

The tool will:

1. Send an ICMP echo request to check if the host is alive (exits if dead or the IP is invalid).
2. Scan all 65535 TCP ports via connect scan.
3. Enrich each open port with service name (from a built-in common-ports table), a banner grab (with an HTTP/HTTPS-aware GET probe for web ports), and connection latency.
4. Print a results table.

Example output:

```
IP >> 192.168.1.140
192.168.1.140 is alive
open ports found : 5355, 27500
PORT   STATE  SERVICE      BANNER  LATENCY
5355   open   llmnr                117.914µs
27500  open   tw-auth-key          184.75µs
```

## Commands

| Command     | Description                                  |
|-------------|-----------------------------------------------|
| `install`   | Build the binary and install it to `/usr/local/bin/inspect` |
| `uninstall` | Remove the installed binary                   |
| `help`      | Show usage information                        |
| `version`   | Show the current version                      |

```
sudo go run main.go install
sudo inspect
```

## Project structure

```
main.go
cmd/
  run.go        — entry point (Run), orchestrates the scan flow
  flags.go       — flag handling (install/uninstall/help/version)
internal/
  ping.go        — ICMP echo alive check (IPv4 + IPv6)
  port_scan.go    — TCP connect port scan (1-65535)
  port_enrich.go      — service/banner/latency enrichment, HTTP(S)-aware probing
  bootstrap/
    install.go   — build + install logic
    uninstall.go — uninstall logic
  models/
    models.go    — shared state: INFO (target), LOOT (scan results), Version
```

## How it works

- **Ping**: raw ICMP socket (`golang.org/x/net/icmp`), branches on IPv4/IPv6, matches echo ID/sequence to avoid false positives from unrelated ICMP traffic.
- **Port scan**: sequential TCP connect attempts across all 65535 ports with a 500ms timeout each.
- **Enrichment**: re-dials each open port; HTTP/HTTPS ports get an active `GET / HTTP/1.0` probe (HTTPS over TLS with certificate verification skipped, since the goal is banner retrieval, not trust validation), other services are passively read for a self-announced banner (e.g. SSH).

## Notes

- Raw ICMP sockets require root — hence `sudo` in all examples above.
- The full 65535-port scan is sequential and can take a while depending on target responsiveness and timeout settings.
- The common-ports table is best-effort; unmapped ports show as `unknown`.