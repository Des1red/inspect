package internal

import (
	"errors"
	"inspect/internal/models"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type scanJob struct {
	hostIndex int
	ip        string
	port      int
}

func classifyError(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "filtered"
	}

	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "filtered"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return "closed"
		}
	}

	return "filtered"
}

func port_search() {
	jobs := make(chan scanJob, 500)

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Build one result container per target.
	models.LOOT.Hosts = make(
		[]models.HostResult,
		len(models.INFO.Targets),
	)

	for i, ip := range models.INFO.Targets {
		models.LOOT.Hosts[i].Target = ip.String()
	}

	worker := func() {
		defer wg.Done()

		for job := range jobs {
			address := net.JoinHostPort(
				job.ip,
				strconv.Itoa(job.port),
			)

			conn, err := net.DialTimeout(
				"tcp",
				address,
				500*time.Millisecond,
			)

			state := "open"

			if err != nil {
				state = classifyError(err)
			} else {
				conn.Close()
			}

			// Ignore closed ports completely.
			if state == "closed" {
				continue
			}

			mu.Lock()

			host := &models.LOOT.Hosts[job.hostIndex]

			switch state {
			case "open":
				host.Ports = append(
					host.Ports,
					job.port,
				)

				host.Details = append(
					host.Details,
					models.PortDetail{
						Port:  job.port,
						State: state,
					},
				)

			case "filtered":
				host.Filtered = append(
					host.Filtered,
					job.port,
				)
			}

			mu.Unlock()
		}
	}

	for i := 0; i < 500; i++ {
		wg.Add(1)
		go worker()
	}

	for hostIndex, ip := range models.INFO.Targets {
		for port := models.INFO.PortStart; port <= models.INFO.PortEnd; port++ {
			jobs <- scanJob{
				hostIndex: hostIndex,
				ip:        ip.String(),
				port:      port,
			}
		}
	}

	close(jobs)

	wg.Wait()
}
