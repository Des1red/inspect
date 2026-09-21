package portscan

import (
	"bufio"
	"crypto/tls"
	"ipspect/internal/models"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const enrichWorkers = 128

type enrichJob struct {
	hostIndex   int
	detailIndex int
}

func lookupService(port int) string {
	if name, ok := commonPorts[port]; ok {
		return name
	}

	return "unknown"
}

func enrich() {
	jobs := make(
		chan enrichJob,
		enrichWorkers,
	)

	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()

		for job := range jobs {
			enrichPort(
				job.hostIndex,
				job.detailIndex,
			)
		}
	}

	for i := 0; i < enrichWorkers; i++ {
		wg.Add(1)
		go worker()
	}

	for h := range models.LOOT.Hosts {
		host := &models.LOOT.Hosts[h]

		for i := range host.Details {
			if host.Details[i].State != "open" {
				continue
			}

			jobs <- enrichJob{
				hostIndex:   h,
				detailIndex: i,
			}
		}
	}

	close(jobs)

	wg.Wait()
}

func enrichPort(
	hostIndex int,
	detailIndex int,
) {
	host := &models.LOOT.Hosts[hostIndex]
	detail := &host.Details[detailIndex]

	service := lookupService(
		detail.Port,
	)

	detail.Service = service

	switch service {
	case "http",
		"http-proxy",
		"https":

		enrichHTTP(
			host.Target,
			detail,
			service,
		)

	default:
		enrichTCP(
			host.Target,
			detail,
		)
	}
}

func enrichTCP(
	ip string,
	detail *models.PortDetail,
) {
	address := net.JoinHostPort(
		ip,
		strconv.Itoa(detail.Port),
	)

	start := time.Now()

	conn, err := net.DialTimeout(
		"tcp",
		address,
		500*time.Millisecond,
	)

	detail.Latency =
		time.Since(start)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.SetReadDeadline(
		time.Now().Add(
			500 * time.Millisecond,
		),
	)

	reader := bufio.NewReader(
		conn,
	)

	line, _ := reader.ReadString(
		'\n',
	)

	detail.Banner =
		strings.TrimSpace(line)
}

func enrichHTTP(
	ip string,
	detail *models.PortDetail,
	service string,
) {
	address := net.JoinHostPort(
		ip,
		strconv.Itoa(detail.Port),
	)

	start := time.Now()

	conn, err := openHTTPConnection(
		address,
		service,
	)

	detail.Latency =
		time.Since(start)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.SetWriteDeadline(
		time.Now().Add(
			500 * time.Millisecond,
		),
	)

	_, err = conn.Write(
		[]byte(
			"GET / HTTP/1.0\r\n" +
				"Host: " + ip + "\r\n" +
				"User-Agent: ipspect\r\n" +
				"Connection: close\r\n" +
				"\r\n",
		),
	)

	if err != nil {
		return
	}

	conn.SetReadDeadline(
		time.Now().Add(
			500 * time.Millisecond,
		),
	)

	reader := bufio.NewReader(
		conn,
	)

	line, err := reader.ReadString(
		'\n',
	)

	if err != nil {
		return
	}

	detail.Banner =
		strings.TrimSpace(line)

	detail.Headers =
		grabHeaders(reader)
}

func openHTTPConnection(
	address string,
	service string,
) (net.Conn, error) {
	if service == "https" {
		return tls.DialWithDialer(
			&net.Dialer{
				Timeout: 500 * time.Millisecond,
			},
			"tcp",
			address,
			&tls.Config{
				InsecureSkipVerify: true,
			},
		)
	}

	return net.DialTimeout(
		"tcp",
		address,
		500*time.Millisecond,
	)
}
