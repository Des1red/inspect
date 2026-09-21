package portscan

import (
	"ipspect/internal/models"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type pingResult struct {
	ip    net.IP
	alive bool
}

func ping() ([]net.IP, int) {
	total := len(models.INFO.Targets)

	if total == 0 {
		return nil, 0
	}

	jobs := make(chan net.IP, total)
	results := make(chan pingResult, total)

	var wg sync.WaitGroup

	workerCount := 64

	if total < workerCount {
		workerCount = total
	}

	worker := func() {
		defer wg.Done()

		for ip := range jobs {
			alive, _ := check(ip)

			results <- pingResult{
				ip:    ip,
				alive: alive,
			}
		}
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker()
	}

	for _, ip := range models.INFO.Targets {
		jobs <- ip
	}

	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	live := make([]net.IP, 0, total)

	for result := range results {
		if result.alive {
			live = append(live, result.ip)
		}
	}

	sort.Slice(live, func(i, j int) bool {
		return lessIP(live[i], live[j])
	})

	models.INFO.Targets = live

	return live, total
}

func check(ip net.IP) (bool, error) {
	isV4 := ip.To4() != nil

	var network string
	var laddr string
	var typ icmp.Type
	var replyType icmp.Type
	var protoNum int

	if isV4 {
		network = "ip4:icmp"
		laddr = "0.0.0.0"
		typ = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply
		protoNum = 1
	} else {
		network = "ip6:ipv6-icmp"
		laddr = "::"
		typ = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
		protoNum = 58
	}

	conn, err := icmp.ListenPacket(network, laddr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	seq := 1

	msg := icmp.Message{
		Type: typ,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("ping"),
		},
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		return false, err
	}

	dst := &net.IPAddr{
		IP: ip,
	}

	if _, err := conn.WriteTo(b, dst); err != nil {
		return false, err
	}

	if err := conn.SetReadDeadline(
		time.Now().Add(3 * time.Second),
	); err != nil {
		return false, err
	}

	reply := make([]byte, 1500)

	for {
		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return false, nil
			}

			return false, err
		}

		peerIP, ok := peer.(*net.IPAddr)
		if !ok {
			continue
		}

		if !peerIP.IP.Equal(ip) {
			continue
		}

		rm, err := icmp.ParseMessage(
			protoNum,
			reply[:n],
		)
		if err != nil {
			continue
		}

		if rm.Type != replyType {
			continue
		}

		echo, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		if echo.ID != id || echo.Seq != seq {
			continue
		}

		return true, nil
	}
}

func lessIP(a, b net.IP) bool {
	a4 := a.To4()
	b4 := b.To4()

	if a4 == nil || b4 == nil {
		return a.String() < b.String()
	}

	for i := 0; i < 4; i++ {
		if a4[i] != b4[i] {
			return a4[i] < b4[i]
		}
	}

	return false
}
