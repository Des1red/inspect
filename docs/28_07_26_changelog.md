# ipspect — Technical Documentation

A Go command-line tool that checks whether a target host is alive via ICMP, then runs a concurrent TCP connect port scan across all 65535 ports and enriches each open port with service name, banner, and latency.

## Architecture

```
main.go
cmd/
  run.go          — Run(): entry point, orchestrates the full flow
  flags.go        — flagcheck(), install/uninstall/help/version wiring
internal/
  ping.go         — Ping(): ICMP alive check
  convert.go      — convert(): string -> net.IP, validates and stores target
  check.go        — check(): raw ICMP echo (IPv4 + IPv6)
  portscan.go      — PortScan(), port_search(), sortPorts()
  enrich.go        — enrich(), probeHTTP(), lookupService(), commonPorts table
  bootstrap/
    install.go     — Install(), Uninstall(): build + copy binary to /usr/local/bin
  models/
    models.go      — INFO (target state), LOOT (scan results), Version
```

## Data model (`models` package)

```go
var INFO struct {
    TargetName string   // raw user input
    Target     net.IP   // parsed/validated IP
}

type PortDetail struct {
    Port    int
    State   string
    Service string
    Banner  string
    Latency time.Duration
}

var LOOT struct {
    Ports   []int
    Details []PortDetail
}

const Version = "0.1.0"
```

`INFO` and `LOOT` are package-level singletons — every part of the program reads and writes through them rather than passing values around explicitly. This was a deliberate early design choice ("everything is gonna read from that").

## Flow (`cmd.Run()`)

1. **`flagcheck()`** — ipspects `os.Args[1]`. If it matches `install`, `uninstall`, `help`, or `version`, handles it and exits immediately, skipping the scan flow entirely. Anything unrecognized prints an error plus help text and exits. No flag at all falls through to the scan flow below.
2. **`target()`** — prompts for an IP string on stdin, loops until non-empty input is given, trims whitespace, stores it in `models.INFO.TargetName`.
3. **`ping()`** — calls `internal.Ping()`, prints the alive/dead message, exits if the host is unreachable or the IP was invalid.
4. **`ports()`** — calls `internal.PortScan()`, exits if no open ports were found.
5. **`result()`** — prints a formatted table of `models.LOOT.Details` using `text/tabwriter`.

## Ping (`internal.Ping`, `convert`, `check`)

- `convert(t string) bool` — uses `net.ParseIP` to validate and parse the input, storing the result in `models.INFO.Target`. Returns `false` on invalid input (`ParseIP` returns `nil`).
- `check() bool` — sends a real ICMP echo request using a raw socket (`golang.org/x/net/icmp`). Branches on IPv4 vs IPv6 (`ip.To4() != nil`), since the two use different network strings, message types, and protocol numbers:
  - IPv4: `"ip4:icmp"`, `ipv4.ICMPTypeEcho` / `ipv4.ICMPTypeEchoReply`, protocol number `1`
  - IPv6: `"ip6:ipv6-icmp"`, `ipv6.ICMPTypeEchoRequest` / `ipv6.ICMPTypeEchoReply`, protocol number `58`
  - Reads incoming packets in a loop, skipping the program's own outbound echo request (which the raw socket can otherwise read back), and validates the reply's ID and sequence number match what was sent — guards against accepting an unrelated ICMP packet as the reply.
  - 3-second read deadline; times out to `false` if nothing valid arrives.

**Requires root** — raw ICMP sockets need elevated privileges (or `CAP_NET_RAW` via `setcap` on Linux).

## Port scan (`internal.PortScan`, `port_search`, `sortPorts`)

- `port_search()` — concurrent TCP connect scan across ports 1–65535. Uses a **fixed worker pool of 500 goroutines** pulling from a buffered channel, rather than spawning 65535 goroutines at once (which would risk exhausting file descriptors). A mutex guards writes to `models.LOOT.Ports`/`Details` since multiple goroutines append concurrently. Each dial uses a 500ms timeout.
- `sortPorts()` — sorts both `models.LOOT.Ports` and `models.LOOT.Details` by port number ascending. Needed because concurrent scanning means ports are no longer discovered in numeric order (unlike the original sequential version) — sorting restores a predictable, readable order for output. Mutates the package-level slices in place, so the result stays sorted for any later reader (e.g. `result()`).
- `PortScan()` — orchestrates: runs `port_search()`, prints "no open ports found" and returns `false` if nothing was found, otherwise sorts, prints a comma-separated summary line of open ports, runs `enrich()`, and returns `true`.

## Enrichment (`internal.enrich`, `probeHTTP`, `lookupService`)

For each open port, re-dials it and attempts to extract a service name, banner, and latency:

- `lookupService(port)` — looks up the port in a large hardcoded `commonPorts` map (well-known/IANA-registered ports plus common dev/database/infra defaults). Falls back to `"unknown"` if unmapped.
- **HTTP-family ports** (`http`, `http-proxy`, `https`) — handled by `probeHTTP()`, which actively sends `GET / HTTP/1.0\r\n\r\n` and reads the response's first line as the banner. HTTPS uses `tls.DialWithDialer` with `InsecureSkipVerify: true` (certificate trust isn't the goal here — banner retrieval is), everything else in this group uses a plain TCP dial.
- **All other ports** — handled inline in `enrich()`: dials, then passively reads whatever the service sends first (many services, like SSH, announce a version banner unprompted). No probe is sent.
- Each result is written back into the matching `models.LOOT.Details` entry by port number.

## Output (`cmd.result`)

Uses `text/tabwriter` to print an aligned table:

```
PORT   STATE  SERVICE      BANNER  LATENCY
5355   open   llmnr                117.914µs
27500  open   tw-auth-key          184.75µs
```

## Install / uninstall (`bootstrap` package)

- `Install()` — shells out to `go build -o ipspect .`, then copies the resulting binary to `/usr/local/bin/ipspect` (mode `0755`), then removes the local build artifact. Must be run from the project source directory. Requires root to write into `/usr/local/bin`.
- `Uninstall()` — removes `/usr/local/bin/ipspect`.
- `InstallPath` is exported for `cmd.help()` to reference in its usage text.

## Known constraints / open items

- **Root required at runtime**, not just for install — raw ICMP sockets need it every time the scanner runs, regardless of install location.
- **`install` assumes `go` is on `$PATH`** and is run from the source directory — it won't work from an already-installed binary trying to reinstall itself.
- **`commonPorts` is best-effort**, not exhaustive — unmapped ports report as `"unknown"`.
- **Full 65535-port scan is bounded by the 500-worker pool and 500ms per-port timeout** — still takes meaningful time depending on target responsiveness, though far faster than the original sequential version.
- **`os.Exit(0)` is used for both success and error exits** in several places (e.g. failed `icmp.ListenPacket`, invalid IP) — worth revisiting if distinct exit codes for success vs. failure become important later.