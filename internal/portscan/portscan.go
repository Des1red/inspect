package portscan

import (
	"fmt"
	"ipspect/internal/models"
	"os"
	"strings"
	"text/tabwriter"
)

func Ping() {
	live, _ := ping()

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

func Ports() {
	foundOpen, foundFiltered := portScan()

	if !foundOpen && !foundFiltered {
		os.Exit(0)
	}
}

func Result() {
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
