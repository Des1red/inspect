package portscan

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

const (
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10
)

type tcpReply struct {
	srcIP   net.IP
	srcPort uint16
	dstPort uint16
	seq     uint32
	ack     uint32
	flags   byte
}

type synScanner struct {
	conn net.PacketConn
	raw  *ipv4.RawConn

	replies chan tcpReply
	errors  chan error

	closeOnce sync.Once

	sourceMu    sync.Mutex
	sourceCache map[string]net.IP

	nextPort uint16
	nextSeq  uint32
}

func newSYNScanner() (*synScanner, error) {
	conn, err := net.ListenPacket(
		"ip4:tcp",
		"0.0.0.0",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"open raw TCP socket: %w",
			err,
		)
	}

	raw, err := ipv4.NewRawConn(conn)
	if err != nil {
		conn.Close()

		return nil, fmt.Errorf(
			"prepare raw IPv4 socket: %w",
			err,
		)
	}

	s := &synScanner{
		conn: conn,
		raw:  raw,

		replies: make(
			chan tcpReply,
			2048,
		),

		errors: make(
			chan error,
			1,
		),

		sourceCache: make(
			map[string]net.IP,
		),

		nextPort: 49152,
		nextSeq:  0x6a09e667,
	}

	go s.readLoop()

	return s, nil
}

func (s *synScanner) Close() error {
	var err error

	s.closeOnce.Do(func() {
		err = s.conn.Close()
	})

	return err
}

func (s *synScanner) readLoop() {
	buf := make(
		[]byte,
		65535,
	)

	for {
		header, payload, _, err :=
			s.raw.ReadFrom(buf)

		if err != nil {
			select {
			case s.errors <- err:
			default:
			}

			return
		}

		if header == nil ||
			header.Protocol != 6 ||
			len(payload) < 20 {

			continue
		}

		reply := tcpReply{
			srcIP: append(
				net.IP(nil),
				header.Src...,
			),

			srcPort: binary.BigEndian.Uint16(
				payload[0:2],
			),

			dstPort: binary.BigEndian.Uint16(
				payload[2:4],
			),

			seq: binary.BigEndian.Uint32(
				payload[4:8],
			),

			ack: binary.BigEndian.Uint32(
				payload[8:12],
			),

			flags: payload[13],
		}

		select {
		case s.replies <- reply:
		default:
		}
	}
}

func (s *synScanner) sourceIPv4(
	dst net.IP,
) (net.IP, error) {
	key := dst.String()

	s.sourceMu.Lock()

	if cached, ok :=
		s.sourceCache[key]; ok {

		ip := append(
			net.IP(nil),
			cached...,
		)

		s.sourceMu.Unlock()

		return ip, nil
	}

	s.sourceMu.Unlock()

	conn, err := net.DialUDP(
		"udp4",
		nil,
		&net.UDPAddr{
			IP:   dst,
			Port: 53,
		},
	)

	if err != nil {
		return nil, fmt.Errorf(
			"determine source IPv4 for %s: %w",
			dst,
			err,
		)
	}

	defer conn.Close()

	local, ok :=
		conn.LocalAddr().(*net.UDPAddr)

	if !ok {
		return nil, fmt.Errorf(
			"determine source IPv4 for %s",
			dst,
		)
	}

	src := local.IP.To4()

	if src == nil {
		return nil, fmt.Errorf(
			"no IPv4 source address for %s",
			dst,
		)
	}

	src = append(
		net.IP(nil),
		src...,
	)

	s.sourceMu.Lock()

	s.sourceCache[key] = src

	s.sourceMu.Unlock()

	return append(
		net.IP(nil),
		src...,
	), nil
}

func (s *synScanner) reserveSourcePort(
	used map[uint16]struct{},
) (uint16, error) {
	const (
		first = uint16(49152)
		last  = uint16(65535)
	)

	for attempts := 0; attempts <= int(last-first); attempts++ {

		port := s.nextPort

		if s.nextPort == last {
			s.nextPort = first
		} else {
			s.nextPort++
		}

		if _, exists := used[port]; exists {
			continue
		}

		return port, nil
	}

	return 0, fmt.Errorf(
		"no source TCP port available",
	)
}

func (s *synScanner) sequence() uint32 {
	s.nextSeq += 0x9e3779b9

	return s.nextSeq
}

func (s *synScanner) sendSYN(
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	seq uint32,
) error {
	segment := buildTCPSegment(
		srcIP,
		dstIP,
		srcPort,
		dstPort,
		seq,
		0,
		tcpFlagSYN,
	)

	return s.sendSegment(
		srcIP,
		dstIP,
		segment,
	)
}

func (s *synScanner) sendRST(
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	seq uint32,
) error {
	segment := buildTCPSegment(
		srcIP,
		dstIP,
		srcPort,
		dstPort,
		seq,
		0,
		tcpFlagRST,
	)

	return s.sendSegment(
		srcIP,
		dstIP,
		segment,
	)
}

func (s *synScanner) sendSegment(
	srcIP net.IP,
	dstIP net.IP,
	segment []byte,
) error {
	header := &ipv4.Header{
		Version:  4,
		Len:      20,
		TOS:      0,
		TotalLen: 20 + len(segment),
		ID:       0,
		FragOff:  0,
		TTL:      64,
		Protocol: 6,
		Checksum: 0,
		Src:      srcIP,
		Dst:      dstIP,
	}

	if err := s.raw.WriteTo(
		header,
		segment,
		nil,
	); err != nil {

		return fmt.Errorf(
			"send raw TCP segment to %s: %w",
			dstIP,
			err,
		)
	}

	return nil
}

func buildTCPSegment(
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	seq uint32,
	ack uint32,
	flags byte,
) []byte {
	segment := make(
		[]byte,
		20,
	)

	binary.BigEndian.PutUint16(
		segment[0:2],
		srcPort,
	)

	binary.BigEndian.PutUint16(
		segment[2:4],
		dstPort,
	)

	binary.BigEndian.PutUint32(
		segment[4:8],
		seq,
	)

	binary.BigEndian.PutUint32(
		segment[8:12],
		ack,
	)

	// TCP header length = 20 bytes.
	segment[12] = 5 << 4

	segment[13] = flags

	binary.BigEndian.PutUint16(
		segment[14:16],
		64240,
	)

	binary.BigEndian.PutUint16(
		segment[16:18],
		0,
	)

	binary.BigEndian.PutUint16(
		segment[18:20],
		0,
	)

	binary.BigEndian.PutUint16(
		segment[16:18],
		tcpChecksum(
			srcIP,
			dstIP,
			segment,
		),
	)

	return segment
}

func tcpChecksum(
	srcIP net.IP,
	dstIP net.IP,
	segment []byte,
) uint16 {
	src := srcIP.To4()
	dst := dstIP.To4()

	pseudo := make(
		[]byte,
		12+len(segment),
	)

	copy(
		pseudo[0:4],
		src,
	)

	copy(
		pseudo[4:8],
		dst,
	)

	pseudo[8] = 0
	pseudo[9] = 6

	binary.BigEndian.PutUint16(
		pseudo[10:12],
		uint16(len(segment)),
	)

	copy(
		pseudo[12:],
		segment,
	)

	return internetChecksum(
		pseudo,
	)
}

func internetChecksum(
	data []byte,
) uint16 {
	var sum uint32

	for len(data) >= 2 {
		sum += uint32(
			binary.BigEndian.Uint16(
				data[:2],
			),
		)

		data = data[2:]
	}

	if len(data) == 1 {
		sum += uint32(
			data[0],
		) << 8
	}

	for sum>>16 != 0 {
		sum =
			(sum & 0xffff) +
				(sum >> 16)
	}

	return ^uint16(sum)
}
