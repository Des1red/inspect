package internal

import (
	"encoding/binary"
	"fmt"
	"ipspect/internal/models"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

func SetDefaultPorts() {
	models.INFO.PortStart = 1
	models.INFO.PortEnd = 65535
	models.INFO.Ports = nil
	models.INFO.PortSpec = "1-65535"
}

func SetPorts(value string) error {
	value = strings.TrimSpace(value)

	if value == "" {
		return fmt.Errorf("empty port")
	}

	parts := strings.Split(
		value,
		",",
	)

	seen := make(
		map[int]struct{},
	)

	var ports []int

	for _, part := range parts {
		part = strings.TrimSpace(
			part,
		)

		if part == "" {
			return fmt.Errorf(
				"empty port in list",
			)
		}

		if strings.Contains(
			part,
			"-",
		) {
			start, end, err :=
				parsePortRange(part)

			if err != nil {
				return err
			}

			for port := start; port <= end; port++ {

				if _, exists :=
					seen[port]; exists {

					continue
				}

				seen[port] =
					struct{}{}

				ports = append(
					ports,
					port,
				)
			}

			continue
		}

		port, err :=
			parseSinglePort(part)

		if err != nil {
			return err
		}

		if _, exists :=
			seen[port]; exists {

			continue
		}

		seen[port] =
			struct{}{}

		ports = append(
			ports,
			port,
		)
	}

	if len(ports) == 0 {
		return fmt.Errorf(
			"no ports specified",
		)
	}

	sort.Ints(ports)

	models.INFO.Ports = ports
	models.INFO.PortSpec = value

	models.INFO.PortStart =
		ports[0]

	models.INFO.PortEnd =
		ports[len(ports)-1]

	return nil
}

func parseSinglePort(
	value string,
) (int, error) {
	port, err := strconv.Atoi(
		value,
	)

	if err != nil {
		return 0, fmt.Errorf(
			"%q is not a valid port",
			value,
		)
	}

	if port < 1 || port > 65535 {
		return 0, fmt.Errorf(
			"port must be between 1 and 65535",
		)
	}

	return port, nil
}

func parsePortRange(
	value string,
) (int, int, error) {
	parts := strings.SplitN(
		value,
		"-",
		2,
	)

	if len(parts) != 2 {
		return 0, 0, fmt.Errorf(
			"invalid port range %q",
			value,
		)
	}

	start, err :=
		parseSinglePort(
			strings.TrimSpace(
				parts[0],
			),
		)

	if err != nil {
		return 0, 0, err
	}

	end, err :=
		parseSinglePort(
			strings.TrimSpace(
				parts[1],
			),
		)

	if err != nil {
		return 0, 0, err
	}

	if start > end {
		return 0, 0, fmt.Errorf(
			"starting port cannot be greater than ending port",
		)
	}

	return start, end, nil
}

func Target() {
	fmt.Print("IP >> ")

	var x string
	fmt.Scanln(&x)

	x = strings.TrimSpace(x)

	for x == "" {
		fmt.Print("IP >> ")
		fmt.Scanln(&x)

		x = strings.TrimSpace(x)
	}

	if err := setTarget(x); err != nil {
		fmt.Println("invalid target:", err)
		os.Exit(1)
	}
}

func setTarget(value string) error {
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
