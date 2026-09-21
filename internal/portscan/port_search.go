package portscan

import (
	"fmt"
	"ipspect/internal/models"
	"net"
	"os"
	"time"
)

const (
	synWindow  = 500
	synTimeout = 500 * time.Millisecond
)

type scanJob struct {
	hostIndex int
	ip        net.IP
	port      int
}

type pendingProbe struct {
	job      scanJob
	srcIP    net.IP
	srcPort  uint16
	seq      uint32
	deadline time.Time
}

func port_search() {
	scanner, err := newSYNScanner()

	if err != nil {
		fmt.Println(
			"failed to initialize SYN scanner:",
			err,
		)

		fmt.Println(
			"ipspect SYN scanning requires raw-socket privileges",
		)

		os.Exit(1)
	}

	defer scanner.Close()

	models.LOOT.Hosts = make(
		[]models.HostResult,
		len(models.INFO.Targets),
	)

	for i, ip := range models.INFO.Targets {
		models.LOOT.Hosts[i].Target =
			ip.String()
	}

	pending := make(
		map[uint16]*pendingProbe,
	)

	usedPorts := make(
		map[uint16]struct{},
	)

	hostIndex := 0
	port := models.INFO.PortStart

	moreJobs :=
		len(models.INFO.Targets) > 0

	ticker := time.NewTicker(
		10 * time.Millisecond,
	)

	defer ticker.Stop()

	for moreJobs || len(pending) > 0 {
		// Fill the SYN window.
		for moreJobs &&
			len(pending) < synWindow {

			job := scanJob{
				hostIndex: hostIndex,

				ip: models.INFO.
					Targets[hostIndex].
					To4(),

				port: port,
			}

			advanceScanCursor(
				&hostIndex,
				&port,
				&moreJobs,
			)

			if job.ip == nil {
				continue
			}

			srcIP, err :=
				scanner.sourceIPv4(
					job.ip,
				)

			if err != nil {
				recordPortState(
					job.hostIndex,
					job.port,
					"filtered",
				)

				continue
			}

			srcPort, err :=
				scanner.reserveSourcePort(
					usedPorts,
				)

			if err != nil {
				fmt.Println(
					"failed to reserve SYN source port:",
					err,
				)

				os.Exit(1)
			}

			seq := scanner.sequence()

			now := time.Now()

			probe := &pendingProbe{
				job:     job,
				srcIP:   srcIP,
				srcPort: srcPort,
				seq:     seq,

				deadline: now.Add(
					synTimeout,
				),
			}

			err = scanner.sendSYN(
				srcIP,
				job.ip,
				srcPort,
				uint16(job.port),
				seq,
			)

			if err != nil {
				recordPortState(
					job.hostIndex,
					job.port,
					"filtered",
				)

				continue
			}

			pending[srcPort] =
				probe

			usedPorts[srcPort] =
				struct{}{}
		}

		if len(pending) == 0 {
			continue
		}

		select {
		case reply := <-scanner.replies:
			probe, ok :=
				pending[reply.dstPort]

			if !ok {
				continue
			}

			if !reply.srcIP.Equal(
				probe.job.ip,
			) {
				continue
			}

			if reply.srcPort !=
				uint16(probe.job.port) {

				continue
			}

			// SYN/ACK = OPEN.
			if reply.flags&tcpFlagSYN != 0 &&
				reply.flags&tcpFlagACK != 0 {

				if reply.ack !=
					probe.seq+1 {

					continue
				}

				recordPortState(
					probe.job.hostIndex,
					probe.job.port,
					"open",
				)

				// Half-open scan:
				// terminate before completing
				// the TCP handshake.
				_ = scanner.sendRST(
					probe.srcIP,
					probe.job.ip,
					probe.srcPort,
					uint16(
						probe.job.port,
					),
					reply.ack,
				)

				releaseProbe(
					pending,
					usedPorts,
					probe.srcPort,
				)

				continue
			}

			// RST = CLOSED.
			if reply.flags&tcpFlagRST != 0 {
				if reply.flags&tcpFlagACK != 0 &&
					reply.ack != probe.seq+1 {

					continue
				}

				releaseProbe(
					pending,
					usedPorts,
					probe.srcPort,
				)
			}

		case <-ticker.C:
			now := time.Now()

			for srcPort, probe := range pending {

				if now.Before(
					probe.deadline,
				) {
					continue
				}

				// No TCP reply in time.
				recordPortState(
					probe.job.hostIndex,
					probe.job.port,
					"filtered",
				)

				releaseProbe(
					pending,
					usedPorts,
					srcPort,
				)
			}

		case err := <-scanner.errors:
			if err != nil {
				fmt.Println(
					"SYN receive error:",
					err,
				)

				os.Exit(1)
			}
		}
	}
}

func advanceScanCursor(
	hostIndex *int,
	port *int,
	moreJobs *bool,
) {
	if *port < models.INFO.PortEnd {
		*port++
		return
	}

	*port = models.INFO.PortStart

	*hostIndex++

	if *hostIndex >=
		len(models.INFO.Targets) {

		*moreJobs = false
	}
}

func recordPortState(
	hostIndex int,
	port int,
	state string,
) {
	host :=
		&models.LOOT.Hosts[hostIndex]

	switch state {
	case "open":
		host.Ports = append(
			host.Ports,
			port,
		)

		host.Details = append(
			host.Details,
			models.PortDetail{
				Port:  port,
				State: state,
			},
		)

	case "filtered":
		host.Filtered = append(
			host.Filtered,
			port,
		)
	}
}

func releaseProbe(
	pending map[uint16]*pendingProbe,
	usedPorts map[uint16]struct{},
	srcPort uint16,
) {
	delete(
		pending,
		srcPort,
	)

	delete(
		usedPorts,
		srcPort,
	)
}
