package internal

import (
	"bufio"
	"crypto/tls"
	"inspect/internal/models"
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
	ip := models.INFO.Target.String()

	for _, port := range models.LOOT.Ports {
		service := lookupService(port)

		var banner string
		var latency time.Duration

		switch service {
		case "http", "http-proxy", "https":
			b, l, ok := probeHTTP(ip, port, service)
			if !ok {
				continue
			}
			banner = b
			latency = l
		default:
			address := net.JoinHostPort(ip, strconv.Itoa(port))
			start := time.Now()
			conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
			latency = time.Since(start)
			if err != nil {
				continue
			}

			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			reader := bufio.NewReader(conn)
			line, _ := reader.ReadString('\n')
			banner = strings.TrimSpace(line)
			conn.Close()
		}

		for i, d := range models.LOOT.Details {
			if d.Port == port {
				models.LOOT.Details[i].Service = service
				models.LOOT.Details[i].Banner = banner
				models.LOOT.Details[i].Latency = latency
				break
			}
		}
	}
}

func probeHTTP(ip string, port int, service string) (string, time.Duration, bool) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	start := time.Now()

	var conn net.Conn
	var err error

	if service == "https" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 500 * time.Millisecond}, "tcp", address, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.DialTimeout("tcp", address, 500*time.Millisecond)
	}
	latency := time.Since(start)
	if err != nil {
		return "", latency, false
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')
	banner := strings.TrimSpace(line)

	return banner, latency, true
}
