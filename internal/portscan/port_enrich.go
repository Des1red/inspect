package portscan

import (
	"bufio"
	"crypto/tls"
	"ipspect/internal/models"
	"net"
	"strconv"
	"strings"
	"time"
)

func lookupService(port int) string {
	if name, ok := commonPorts[port]; ok {
		return name
	}

	return "unknown"
}

func enrich() {
	for h := range models.LOOT.Hosts {
		host := &models.LOOT.Hosts[h]

		for i := range host.Details {
			detail := &host.Details[i]

			if detail.State != "open" {
				continue
			}

			service := lookupService(detail.Port)

			var banner string
			var latency time.Duration

			switch service {
			case "http", "http-proxy", "https":
				b, l, ok := probeHTTP(
					host.Target,
					detail.Port,
					service,
				)

				if !ok {
					continue
				}

				banner = b
				latency = l

			default:
				address := net.JoinHostPort(
					host.Target,
					strconv.Itoa(detail.Port),
				)

				start := time.Now()

				conn, err := net.DialTimeout(
					"tcp",
					address,
					500*time.Millisecond,
				)

				latency = time.Since(start)

				if err != nil {
					continue
				}

				conn.SetReadDeadline(
					time.Now().Add(500 * time.Millisecond),
				)

				reader := bufio.NewReader(conn)

				line, _ := reader.ReadString('\n')

				banner = strings.TrimSpace(line)

				conn.Close()
			}

			detail.Service = service
			detail.Banner = banner
			detail.Latency = latency
		}
	}
}

func probeHTTP(
	ip string,
	port int,
	service string,
) (string, time.Duration, bool) {

	address := net.JoinHostPort(
		ip,
		strconv.Itoa(port),
	)

	start := time.Now()

	var conn net.Conn
	var err error

	if service == "https" {
		conn, err = tls.DialWithDialer(
			&net.Dialer{
				Timeout: 500 * time.Millisecond,
			},
			"tcp",
			address,
			&tls.Config{
				InsecureSkipVerify: true,
			},
		)
	} else {
		conn, err = net.DialTimeout(
			"tcp",
			address,
			500*time.Millisecond,
		)
	}

	latency := time.Since(start)

	if err != nil {
		return "", latency, false
	}

	defer conn.Close()

	conn.SetWriteDeadline(
		time.Now().Add(500 * time.Millisecond),
	)

	conn.Write(
		[]byte("GET / HTTP/1.0\r\n\r\n"),
	)

	conn.SetReadDeadline(
		time.Now().Add(500 * time.Millisecond),
	)

	reader := bufio.NewReader(conn)

	line, _ := reader.ReadString('\n')

	banner := strings.TrimSpace(line)

	return banner, latency, true
}
