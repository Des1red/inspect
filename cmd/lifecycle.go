package cmd

import (
	"fmt"
	"inspect/internal"
	"inspect/internal/bootstrap"
	"inspect/internal/models"
	"inspect/internal/output"
	"os"
	"strings"
	"text/tabwriter"
)

var saveResults bool

func flagcheck() {
	internal.SetDefaultPorts()

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

			if err := internal.SetPorts(os.Args[i]); err != nil {
				fmt.Println("invalid port range:", err)
				os.Exit(1)
			}

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

	if err := internal.SetTarget(x); err != nil {
		fmt.Println("invalid target:", err)
		os.Exit(1)
	}
}

func ping() {
	live, _ := internal.Ping()

	hosts := make([]string, len(live))

	for i, ip := range live {
		hosts[i] = ip.String()
	}

	fmt.Printf(
		"accept icmp [%s]\n",
		strings.Join(hosts, ", "),
	)

	if len(live) == 0 {
		os.Exit(0)
	}
}

func ports() {
	foundOpen, foundFiltered := internal.PortScan()

	if !foundOpen && !foundFiltered {
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
		fmt.Println(
			"failed to save results:",
			err,
		)
		return
	}

	fmt.Println(
		"results saved to",
		filename,
	)
}
