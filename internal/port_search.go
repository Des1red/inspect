package internal

import (
	"inspect/internal/models"
	"net"
	"strconv"
	"sync"
	"time"
)

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
			if err != nil {
				continue
			}
			conn.Close()

			mu.Lock()
			models.LOOT.Ports = append(models.LOOT.Ports, port)
			models.LOOT.Details = append(models.LOOT.Details, models.PortDetail{
				Port:  port,
				State: "open",
			})
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
