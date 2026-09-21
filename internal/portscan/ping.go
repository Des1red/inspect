package portscan

import (
	"errors"
	"fmt"
	"ipspect/internal/models"
	"net"
	"os"
	"sort"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	icmpWindow  = 500
	icmpTimeout = 750 * time.Millisecond
	icmpRetries = 3
)

type icmpReply struct {
	ip  net.IP
	seq int
}

type icmpProbe struct {
	ip net.IP

	seq int

	attempts int

	deadline time.Time
}

type icmpScanner struct {
	id int

	v4 *icmp.PacketConn
	v6 *icmp.PacketConn

	replies chan icmpReply
}

func ping() ([]net.IP, int) {
	total := len(models.INFO.Targets)

	if total == 0 {
		return nil, 0
	}

	scanner, err := newICMPScanner(
		models.INFO.Targets,
	)

	if err != nil {
		fmt.Println(
			"failed to initialize ICMP scanner:",
			err,
		)

		return nil, total
	}

	defer scanner.close()

	pending := make(
		map[int]*icmpProbe,
	)

	usedSequences := make(
		map[int]struct{},
	)

	live := make(
		map[string]net.IP,
	)

	nextTarget := 0
	nextSequence := 1

	ticker := time.NewTicker(
		25 * time.Millisecond,
	)

	defer ticker.Stop()

	for nextTarget < total ||
		len(pending) > 0 {

		/*
			Fill the active ICMP window.

			There can be up to 500 hosts
			waiting for replies at once.
		*/
		for nextTarget < total &&
			len(pending) < icmpWindow {

			ip := append(
				net.IP(nil),
				models.INFO.
					Targets[nextTarget]...,
			)

			nextTarget++

			seq, ok :=
				reserveICMPSequence(
					&nextSequence,
					usedSequences,
				)

			if !ok {
				break
			}

			probe := &icmpProbe{
				ip: ip,

				seq: seq,

				attempts: 1,

				deadline: time.Now().Add(
					icmpTimeout,
				),
			}

			err := scanner.send(
				probe.ip,
				probe.seq,
			)

			if err != nil {
				delete(
					usedSequences,
					seq,
				)

				continue
			}

			pending[seq] =
				probe
		}

		if len(pending) == 0 {
			continue
		}

		select {
		case reply := <-scanner.replies:
			probe, ok :=
				pending[reply.seq]

			if !ok {
				continue
			}

			/*
				Sequence alone is not enough.

				Also verify that the response
				came from the target associated
				with that sequence.
			*/
			if !probe.ip.Equal(
				reply.ip,
			) {
				continue
			}

			key := probe.ip.String()

			if _, exists := live[key]; !exists {

				live[key] = append(
					net.IP(nil),
					probe.ip...,
				)
			}

			delete(
				pending,
				probe.seq,
			)

			delete(
				usedSequences,
				probe.seq,
			)

		case <-ticker.C:
			now := time.Now()

			for seq, probe := range pending {

				if now.Before(
					probe.deadline,
				) {
					continue
				}

				/*
					Initial request already happened.

					icmpRetries = 3 means:

					attempt 1
					retry 1
					retry 2
					retry 3

					4 packets maximum.
				*/
				if probe.attempts <=
					icmpRetries {

					probe.attempts++

					err := scanner.send(
						probe.ip,
						probe.seq,
					)

					probe.deadline =
						now.Add(
							icmpTimeout,
						)

					if err != nil {
						continue
					}

					continue
				}

				/*
					Initial request + all
					3 retries timed out.
				*/
				delete(
					pending,
					seq,
				)

				delete(
					usedSequences,
					seq,
				)
			}
		}
	}

	result := make(
		[]net.IP,
		0,
		len(live),
	)

	for _, ip := range live {
		result = append(
			result,
			ip,
		)
	}

	sort.Slice(
		result,
		func(i, j int) bool {
			return lessIP(
				result[i],
				result[j],
			)
		},
	)

	models.LOOT.ICMPReachable = make(
		[]string,
		len(result),
	)

	for i, ip := range result {
		models.LOOT.ICMPReachable[i] =
			ip.String()
	}

	return result, total
}

func newICMPScanner(
	targets []net.IP,
) (*icmpScanner, error) {
	scanner := &icmpScanner{
		id: os.Getpid() & 0xffff,

		replies: make(
			chan icmpReply,
			2048,
		),
	}

	var needV4 bool
	var needV6 bool

	for _, ip := range targets {
		if ip.To4() != nil {
			needV4 = true
		} else {
			needV6 = true
		}
	}

	if needV4 {
		conn, err := icmp.ListenPacket(
			"ip4:icmp",
			"0.0.0.0",
		)

		if err != nil {
			return nil, fmt.Errorf(
				"open IPv4 ICMP socket: %w",
				err,
			)
		}

		scanner.v4 = conn

		go scanner.readLoop(
			conn,
			1,
			ipv4.ICMPTypeEchoReply,
		)
	}

	if needV6 {
		conn, err := icmp.ListenPacket(
			"ip6:ipv6-icmp",
			"::",
		)

		if err != nil {
			if scanner.v4 != nil {
				scanner.v4.Close()
			}

			return nil, fmt.Errorf(
				"open IPv6 ICMP socket: %w",
				err,
			)
		}

		scanner.v6 = conn

		go scanner.readLoop(
			conn,
			58,
			ipv6.ICMPTypeEchoReply,
		)
	}

	return scanner, nil
}

func (s *icmpScanner) send(
	ip net.IP,
	seq int,
) error {
	var conn *icmp.PacketConn
	var typ icmp.Type

	if ip.To4() != nil {
		conn = s.v4
		typ = ipv4.ICMPTypeEcho
	} else {
		conn = s.v6
		typ = ipv6.ICMPTypeEchoRequest
	}

	if conn == nil {
		return fmt.Errorf(
			"no ICMP socket available for %s",
			ip,
		)
	}

	msg := icmp.Message{
		Type: typ,
		Code: 0,

		Body: &icmp.Echo{
			ID:  s.id,
			Seq: seq,

			Data: []byte(
				"ipspect",
			),
		},
	}

	packet, err := msg.Marshal(nil)

	if err != nil {
		return err
	}

	_, err = conn.WriteTo(
		packet,
		&net.IPAddr{
			IP: ip,
		},
	)

	return err
}

func (s *icmpScanner) readLoop(
	conn *icmp.PacketConn,
	protocol int,
	replyType icmp.Type,
) {
	buffer := make(
		[]byte,
		1500,
	)

	for {
		n, peer, err :=
			conn.ReadFrom(buffer)

		if err != nil {
			if errors.Is(
				err,
				net.ErrClosed,
			) {
				return
			}

			return
		}

		peerIP, ok :=
			peer.(*net.IPAddr)

		if !ok {
			continue
		}

		message, err :=
			icmp.ParseMessage(
				protocol,
				buffer[:n],
			)

		if err != nil {
			continue
		}

		if message.Type != replyType {
			continue
		}

		echo, ok :=
			message.Body.(*icmp.Echo)

		if !ok {
			continue
		}

		if echo.ID != s.id {
			continue
		}

		s.replies <- icmpReply{
			ip: append(
				net.IP(nil),
				peerIP.IP...,
			),

			seq: echo.Seq,
		}
	}
}

func (s *icmpScanner) close() {
	if s.v4 != nil {
		s.v4.Close()
	}

	if s.v6 != nil {
		s.v6.Close()
	}
}

func reserveICMPSequence(
	next *int,
	used map[int]struct{},
) (int, bool) {
	for attempts := 0; attempts < 65535; attempts++ {

		if *next < 1 ||
			*next > 65535 {

			*next = 1
		}

		seq := *next

		*next = *next + 1

		if _, exists :=
			used[seq]; exists {

			continue
		}

		used[seq] =
			struct{}{}

		return seq, true
	}

	return 0, false
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
