# ipspect

`ipspect` is a command-line IP and TCP scanner written in Go.

It performs concurrent ICMP discovery, followed by a half-open TCP SYN scan. Open ports are then enriched using full TCP connections to retrieve service information, banners, HTTP response headers, and connection latency.

ICMP is used as an additional reachability signal only. A target that does not respond to ICMP is still scanned for open TCP ports.

## Features

* IPv4 target scanning
* IPv4 CIDR scanning
* Concurrent ICMP discovery
* 3 ICMP retries after the initial request
* ICMP reachability tracking
* Half-open TCP SYN scanning
* Concurrent SYN probe window
* Open, closed, and filtered port classification
* Single ports, ranges, lists, and mixed port specifications
* Concurrent TCP enrichment of open ports
* Built-in common-port service mapping
* TCP banner grabbing
* HTTP and HTTPS probing
* HTTP response header collection
* Connection latency measurement
* Markdown result export

## Requirements

* Go
* Linux
* Raw socket privileges

`ipspect` uses raw sockets for ICMP and TCP SYN scanning, so it normally needs to run as root:

```bash
sudo ipspect
```

Alternatively, the installed binary can be granted the appropriate raw-socket capability.

## Installation

From the project directory:

```bash
sudo go run main.go install
```

This builds and installs `ipspect`.

You can then run it with:

```bash
sudo ipspect
```

To uninstall:

```bash
sudo ipspect uninstall
```

## Usage

Run:

```bash
sudo ipspect
```

You will be prompted for a target:

```text
IP >> 192.168.1.105
```

A CIDR range can also be supplied:

```text
IP >> 192.168.1.0/24
```

By default, `ipspect` scans all TCP ports:

```text
1-65535
```

## Port Selection

Use `-p` to restrict the TCP scan.

### Single port

```bash
sudo ipspect -p 22
```

### Port range

```bash
sudo ipspect -p 1-1024
```

### Port list

```bash
sudo ipspect -p 21,22,80,443
```

### Mixed ports and ranges

```bash
sudo ipspect -p 21,22,80,443,8000-8100
```

Duplicate ports are removed and the selected ports are normalized internally before scanning.

When ports are explicitly selected with `-p`, closed ports are also retained and displayed.

For example:

```text
192.168.1.105
open     [80, 443]
closed   [21, 22]
filtered 0
```

During the default `1-65535` scan, closed ports are not individually displayed to avoid producing tens of thousands of unnecessary result entries.

## Saving Results

Use `-s` to save the scan as Markdown:

```bash
sudo ipspect -s
```

It can also be combined with port selection:

```bash
sudo ipspect -s -p 22,80,443
```

The saved report includes:

* target
* selected port specification
* ICMP-reachable hosts
* open ports
* explicitly selected closed ports
* service names
* banners
* latency
* HTTP response headers

The output filename is generated from the target.

## Commands

| Command     | Description                 |
| ----------- | --------------------------- |
| `install`   | Build and install `ipspect` |
| `uninstall` | Remove the installed binary |
| `help`      | Show usage information      |
| `version`   | Show the current version    |

Examples:

```bash
sudo go run main.go install

sudo ipspect help

sudo ipspect version

sudo ipspect uninstall
```

## Flags

| Flag | Value             | Description                        |
| ---- | ----------------- | ---------------------------------- |
| `-s` |                   | Save scan results as Markdown      |
| `-p` | `22`              | Scan a single TCP port             |
| `-p` | `1-1024`          | Scan a TCP port range              |
| `-p` | `21,22,80,443`    | Scan selected TCP ports            |
| `-p` | `22,80,8000-8100` | Scan a mixture of ports and ranges |

If `-p` is omitted, ports `1-65535` are scanned.

## Scan Flow

The scanner runs in three main stages:

```text
targets
   |
   v
ICMP discovery
   |
   |-- responders recorded
   |
   v
all original targets
   |
   v
TCP SYN scan
   |
   |-- SYN/ACK -> open -> RST
   |-- RST     -> closed
   |-- timeout -> filtered
   |
   v
open ports
   |
   v
TCP enrichment
   |
   |-- service lookup
   |-- banner
   |-- HTTP/HTTPS probe
   |-- HTTP headers
   |-- latency
   |
   v
results
```

## ICMP Discovery

ICMP discovery uses `golang.org/x/net/icmp`.

The scanner uses shared ICMP sockets and keeps multiple probes outstanding concurrently rather than opening a separate raw socket for every target.

Each outstanding target receives a unique ICMP sequence number.

A target gets:

```text
initial request
retry 1
retry 2
retry 3
```

for a maximum of four Echo Requests.

A valid response is matched using the ICMP identifier, sequence number, and source IP.

### ICMP Does Not Gate TCP Scanning

Failure to answer ICMP does **not** mean that a target is removed from the scan.

For example:

```text
192.168.1.20
ICMP: no response
TCP 443: SYN/ACK
```

The target can still be discovered through its open TCP ports.

ICMP-responsive targets are stored separately and included in saved scan results.

## TCP SYN Scan

Port discovery uses a half-open TCP SYN scan rather than establishing a full TCP connection for every port.

The basic exchange for an open port is:

```text
ipspect -> SYN
target  -> SYN/ACK
ipspect -> RST
```

The three primary states are:

```text
SYN/ACK      open
RST          closed
no response  filtered
```

`ipspect` keeps up to 500 SYN probes outstanding concurrently.

A shared raw TCP receiver processes replies and matches them to pending probes using information such as the source/destination ports, target address, and TCP sequence/acknowledgement numbers.

This avoids creating a full TCP connection merely to determine whether every port is open.

## Enrichment

After SYN discovery completes, only open ports move to the enrichment stage.

Enrichment uses a separate worker pool so multiple open ports can be processed concurrently.

The current enrichment pool uses:

```text
128 workers
```

Each open port is assigned a service name using the built-in common-port table.

If a port is not present in the table:

```text
unknown
```

is used.

## TCP Banner Grabbing

For non-HTTP services, `ipspect` establishes one full TCP connection to the open port.

It then waits briefly for a service-provided banner.

For example, SSH may return:

```text
SSH-2.0-OpenSSH_9.x
```

The same connection is used to record connection latency.

## HTTP and HTTPS

Ports identified as HTTP or HTTPS receive an HTTP-aware probe.

For HTTP:

```text
TCP connect
GET /
read response
close
```

For HTTPS:

```text
TCP connect
TLS handshake
GET /
read response
close
```

TLS certificate verification is skipped because this stage is being used for service inspection rather than certificate trust validation.

The request includes:

```http
GET / HTTP/1.0
Host: <target>
User-Agent: ipspect
Connection: close
```

The HTTP status line becomes the port banner, for example:

```text
HTTP/1.1 200 OK
```

The remaining response headers are also collected.

Examples include:

```text
Server
Content-Type
Content-Length
Location
Content-Security-Policy
Strict-Transport-Security
X-Frame-Options
X-Content-Type-Options
```

The exact headers depend on the target server.

## Example

```bash
sudo ipspect -p 21,22,80,443
```

```text
IP >> 192.168.1.105

accept icmp [192.168.1.105]

192.168.1.105
open     [80, 443]
closed   [21, 22]
filtered 0


HOST           192.168.1.105
PORT  STATE    SERVICE  BANNER               LATENCY
21    closed
22    closed
80    open     http     HTTP/1.1 200 OK      1.2ms
                         Content-Type:        text/html
                         Server:              nginx
443   open     https    HTTP/1.1 200 OK      4.1ms
                         Content-Type:        text/html
                         Server:              nginx
```

The exact output depends on the target and network conditions.

## Project Structure

```text
.
├── main.go
├── cmd/
│   ├── flags.go
│   ├── lifecycle.go
│   └── root.go
│
└── internal/
    ├── input.go
    │
    ├── bootstrap/
    │   ├── install.go
    │   └── uninstall.go
    │
    ├── models/
    │   ├── scope.go
    │   └── version.go
    │
    ├── output/
    │   └── save.go
    │
    └── portscan/
        ├── ping.go
        ├── syn_probe.go
        ├── port_search.go
        ├── port_scan.go
        ├── port_enrich.go
        ├── header_grab.go
        ├── port_list.go
        └── portscan.go
```

### Main Components

`ping.go`

Handles concurrent ICMP discovery and retries.

`syn_probe.go`

Handles raw TCP packet creation, checksums, SYN transmission, reply reception, and RST transmission.

`port_search.go`

Controls the concurrent SYN scan, pending probes, timeouts, and port-state classification.

`port_scan.go`

Sorts and summarizes scan results before enrichment.

`port_enrich.go`

Runs concurrent full-TCP enrichment against discovered open ports.

`header_grab.go`

Parses HTTP response headers.

`port_list.go`

Contains the built-in TCP port/service mapping.

`models/scope.go`

Contains shared scan configuration and result structures.

`output/save.go`

Generates Markdown scan reports.

## Design

The main distinction in `ipspect` is between **discovery** and **enrichment**.

Discovery is lightweight:

```text
SYN -> response -> RST
```

Enrichment is more expensive:

```text
full TCP connection -> inspect service -> close
```

A full TCP connection is therefore only made for ports already identified as open.

For HTTP/HTTPS ports, the same enrichment connection is used to retrieve both the HTTP status and response headers.

## Notes

* Raw ICMP and TCP sockets require elevated privileges.
* SYN scanning currently targets IPv4.
* CIDR scanning currently supports IPv4.
* CIDR ranges larger than `/16` are rejected.
* ICMP response does not determine whether TCP scanning occurs.
* A silent TCP port is classified as filtered after the SYN timeout.
* Closed ports are shown individually when `-p` explicitly selects ports.
* Closed ports are not retained individually during the default full-port scan.
* Service names come from a built-in common-port mapping and are best-effort.
* An open service may provide no banner.
* HTTP headers are collected only for services treated as HTTP/HTTPS.
* Network latency, packet loss, filtering, and rate limiting can affect scan results.

## Legal Notice

Only scan systems and networks that you own or have explicit authorization to test.
