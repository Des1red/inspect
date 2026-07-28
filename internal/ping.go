package internal

import (
	"fmt"
	"inspect/internal/models"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func Ping() (bool, string) {
	if ok := convert(models.INFO.TargetName); !ok {
		fmt.Println("Invalid IP")
		os.Exit(0)
	}
	status := check()
	var msg string
	if status {
		msg = " is alive"
	} else {
		msg = " is dead"
	}
	return status, models.INFO.TargetName + msg
}

func convert(t string) bool {
	ip := net.ParseIP(t)
	if ip == nil {
		return false
	}
	models.INFO.Target = ip
	return true
}

func check() bool {
	ip := models.INFO.Target
	isV4 := ip.To4() != nil

	var network, laddr string
	var typ icmp.Type
	var replyType icmp.Type

	if isV4 {
		network = "ip4:icmp"
		laddr = "0.0.0.0"
		typ = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply
	} else {
		network = "ip6:ipv6-icmp"
		laddr = "::"
		typ = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
	}

	conn, err := icmp.ListenPacket(network, laddr)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(0)
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
		fmt.Println("error:", err)
		os.Exit(0)
	}

	dst := &net.IPAddr{IP: ip}
	if _, err := conn.WriteTo(b, dst); err != nil {
		fmt.Println("error:", err)
		os.Exit(0)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, 1500)

	var protoNum int
	if isV4 {
		protoNum = 1
	} else {
		protoNum = 58
	}

	for {
		n, _, err := conn.ReadFrom(reply)
		if err != nil {
			return false
		}

		rm, err := icmp.ParseMessage(protoNum, reply[:n])
		if err != nil {
			return false
		}

		if rm.Type == typ {
			continue
		}

		if rm.Type != replyType {
			continue
		}

		echo, ok := rm.Body.(*icmp.Echo)
		if !ok || echo.ID != id || echo.Seq != seq {
			continue
		}

		return true
	}
}
