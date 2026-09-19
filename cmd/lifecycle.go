package cmd

import (
	"encoding/binary"
	"fmt"
	"inspect/internal"
	"inspect/internal/bootstrap"
	"inspect/internal/models"
	"inspect/internal/output"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
)

var saveResults bool

func flagcheck() {
	// Defaults.
	models.INFO.PortStart = 1
	models.INFO.PortEnd = 65535

	if len(os.Args) < 2 {
		return
	}

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]

		switch arg {
		case "-s":
			saveResults = true

		case "-p":
			if i+1 >= len(os.Args) {
				fmt.Println("-p requires a port or port range")
				fmt.Println("examples:")
				fmt.Println("  -p 22")
				fmt.Println("  -p 1-22")
				os.Exit(1)
			}

			i++

			start, end, err := parsePorts(os.Args[i])
			if err != nil {
				fmt.Println("invalid port range:", err)
				os.Exit(1)
			}

			models.INFO.PortStart = start
			models.INFO.PortEnd = end

		case "install":
			bootstrap.Install()
			os.Exit(0)

		case "uninstall":
			bootstrap.Uninstall()
			os.Exit(0)

		case "help":
			help()
			os.Exit(0)

		case "version":
			version()
			os.Exit(0)

		default:
			fmt.Println("unknown argument:", arg)
			help()
			os.Exit(1)
		}
	}
}

func parsePorts(value string) (int, int, error) {
	value = strings.TrimSpace(value)

	if value == "" {
		return 0, 0, fmt.Errorf("empty port")
	}

	// Single port:
	// -p 22
	if !strings.Contains(value, "-") {
		port, err := strconv.Atoi(value)
		if err != nil {
			return 0, 0, fmt.Errorf("%q is not a valid port", value)
		}

		if port < 1 || port > 65535 {
			return 0, 0, fmt.Errorf("port must be between 1 and 65535")
		}

		return port, port, nil
	}

	// Port range:
	// -p 1-22
	parts := strings.SplitN(value, "-", 2)

	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range %q", value)
	}

	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid starting port")
	}

	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid ending port")
	}

	if start < 1 || start > 65535 {
		return 0, 0, fmt.Errorf("starting port must be between 1 and 65535")
	}

	if end < 1 || end > 65535 {
		return 0, 0, fmt.Errorf("ending port must be between 1 and 65535")
	}

	if start > end {
		return 0, 0, fmt.Errorf("starting port cannot be greater than ending port")
	}

	return start, end, nil
}

func target() {
	fmt.Print("IP >> ")

	var x string
	fmt.Scanln(&x)

	x = strings.TrimSpace(x)

	for x == "" {
		fmt.Print("IP >> ")
		fmt.Scanln(&x)
		x = strings.TrimSpace(x)
	}

	targets, err := parseTargets(x)
	if err != nil {
		fmt.Println("invalid target:", err)
		os.Exit(1)
	}

	models.INFO.TargetName = x
	models.INFO.Targets = targets

	if len(targets) == 1 {
		models.INFO.Target = targets[0]
	}
}

func parseTargets(value string) ([]net.IP, error) {
	// CIDR target:
	// 192.168.1.0/24
	if strings.Contains(value, "/") {
		return parseCIDR(value)
	}

	// Single IP.
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("%q is not a valid IP address", value)
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
		return nil, fmt.Errorf("CIDR scanning currently supports IPv4 only")
	}

	ones, bits := network.Mask.Size()

	if bits != 32 {
		return nil, fmt.Errorf("CIDR scanning currently supports IPv4 only")
	}

	hostBits := 32 - ones

	// Prevent accidentally expanding something enormous like /0.
	if hostBits > 16 {
		return nil, fmt.Errorf(
			"CIDR range is too large; minimum supported prefix is /16",
		)
	}

	networkIP := ipv4.Mask(network.Mask)

	start := binary.BigEndian.Uint32(networkIP)
	count := uint32(1) << uint32(hostBits)

	end := start + count - 1

	/*
		For normal IPv4 subnets, skip the network and broadcast
		addresses.

	*/
	if count > 2 {
		start++
		end--
	}

	targets := make([]net.IP, 0, int(end-start+1))

	for current := start; current <= end; current++ {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, current)

		targets = append(targets, net.IP(buf))
	}

	return targets, nil
}

func ping() {
	/*
		Ping() is designed around one Target.

	*/
	if len(models.INFO.Targets) > 1 {
		fmt.Printf(
			"target range contains %d hosts\n",
			len(models.INFO.Targets),
		)
		return
	}

	ok, msg := internal.Ping()
	fmt.Println(msg)

	if !ok {
		fmt.Println("inspecting anyways.")
	}
}

func ports() {
	if ok := internal.PortScan(); !ok {
		os.Exit(0)
	}
}

func result() {
	w := tabwriter.NewWriter(
		os.Stdout,
		0,
		4,
		2,
		' ',
		0,
	)

	for _, host := range models.LOOT.Hosts {
		if len(host.Details) == 0 {
			continue
		}

		fmt.Fprintf(
			w,
			"\nHOST\t%s\n",
			host.Target,
		)

		fmt.Fprintln(
			w,
			"PORT\tSTATE\tSERVICE\tBANNER\tLATENCY",
		)

		for _, d := range host.Details {
			fmt.Fprintf(
				w,
				"%d\t%s\t%s\t%s\t%s\n",
				d.Port,
				d.State,
				d.Service,
				d.Banner,
				d.Latency,
			)
		}
	}

	w.Flush()
}

func save() {
	filename, err := output.Save()
	if err != nil {
		fmt.Println("failed to save results:", err)
		return
	}

	fmt.Println("results saved to", filename)
}
