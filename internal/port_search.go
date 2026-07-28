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

func classifyError(err error) string {
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
	ip := models.INFO.Target.String()

	ports := make(chan int, 500)
	var wg sync.WaitGroup
	var mu sync.Mutex

	worker := func() {
		defer wg.Done()
		for port := range ports {
			address := net.JoinHostPort(ip, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)

			state := "open"
			if err != nil {
				state = classifyError(err)
			} else {
				conn.Close()
			}

			mu.Lock()
			if state != "closed" {
				if state == "open" {
					models.LOOT.Ports = append(models.LOOT.Ports, port)
				}
				models.LOOT.Details = append(models.LOOT.Details, models.PortDetail{
					Port:  port,
					State: state,
				})
			}
			mu.Unlock()
		}
	}

	for i := 0; i < 500; i++ {
		wg.Add(1)
		go worker()
	}

	for port := 1; port <= 65535; port++ {
		ports <- port
	}
	close(ports)

	wg.Wait()
}
