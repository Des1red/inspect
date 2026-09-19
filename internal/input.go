package internal

import (
	"encoding/binary"
	"fmt"
	"inspect/internal/models"
	"net"
	"strconv"
	"strings"
)

func SetDefaultPorts() {
	models.INFO.PortStart = 1
	models.INFO.PortEnd = 65535
}

func SetPorts(value string) error {
	value = strings.TrimSpace(value)

	if value == "" {
		return fmt.Errorf("empty port")
	}

	// Single port:
	// 22
	if !strings.Contains(value, "-") {
		port, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%q is not a valid port", value)
		}

		if port < 1 || port > 65535 {
			return fmt.Errorf("port must be between 1 and 65535")
		}

		models.INFO.PortStart = port
		models.INFO.PortEnd = port

		return nil
	}

	// Port range:
	// 1-22
	parts := strings.SplitN(value, "-", 2)

	start, err := strconv.Atoi(
		strings.TrimSpace(parts[0]),
	)
	if err != nil {
		return fmt.Errorf("invalid starting port")
	}

	end, err := strconv.Atoi(
		strings.TrimSpace(parts[1]),
	)
	if err != nil {
		return fmt.Errorf("invalid ending port")
	}

	if start < 1 || start > 65535 {
		return fmt.Errorf(
			"starting port must be between 1 and 65535",
		)
	}

	if end < 1 || end > 65535 {
		return fmt.Errorf(
			"ending port must be between 1 and 65535",
		)
	}

	if start > end {
		return fmt.Errorf(
			"starting port cannot be greater than ending port",
		)
	}

	models.INFO.PortStart = start
	models.INFO.PortEnd = end

	return nil
}

func SetTarget(value string) error {
	value = strings.TrimSpace(value)

	if value == "" {
		return fmt.Errorf("target cannot be empty")
	}

	var targets []net.IP
	var err error

	if strings.Contains(value, "/") {
		targets, err = parseCIDR(value)
	} else {
		targets, err = parseIP(value)
	}

	if err != nil {
		return err
	}

	models.INFO.TargetName = value
	models.INFO.Targets = targets

	return nil
}

func parseIP(value string) ([]net.IP, error) {
	ip := net.ParseIP(value)

	if ip == nil {
		return nil, fmt.Errorf(
			"%q is not a valid IP address",
			value,
		)
	}

	return []net.IP{ip}, nil
}

func parseCIDR(value string) ([]net.IP, error) {
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil, err
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf(
			"CIDR scanning currently supports IPv4 only",
		)
	}

	ones, bits := network.Mask.Size()

	if bits != 32 {
		return nil, fmt.Errorf(
			"CIDR scanning currently supports IPv4 only",
		)
	}

	hostBits := 32 - ones

	// Prevent huge ranges such as /0.
	if hostBits > 16 {
		return nil, fmt.Errorf(
			"CIDR range is too large; minimum supported prefix is /16",
		)
	}

	networkIP := ipv4.Mask(network.Mask)

	start := binary.BigEndian.Uint32(networkIP)

	count := uint32(1) << uint32(hostBits)

	end := start + count - 1

	// Skip network and broadcast for normal IPv4 subnets.
	if count > 2 {
		start++
		end--
	}

	targets := make(
		[]net.IP,
		0,
		int(end-start+1),
	)

	for current := start; current <= end; current++ {
		buf := make([]byte, 4)

		binary.BigEndian.PutUint32(
			buf,
			current,
		)

		targets = append(
			targets,
			net.IP(buf),
		)
	}

	return targets, nil
}
