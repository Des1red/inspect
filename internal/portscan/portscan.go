package portscan

import (
	"fmt"
	"ipspect/internal/models"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

func Ping() {
	live, _ := ping()

	hosts := make(
		[]string,
		len(live),
	)

	for i, ip := range live {
		hosts[i] = ip.String()
	}

	fmt.Printf(
		"accept icmp [%s]\n",
		strings.Join(hosts, ", "),
	)
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

		for _, detail := range host.Details {
			fmt.Fprintf(
				w,
				"%d\t%s\t%s\t%s\t%s\n",
				detail.Port,
				detail.State,
				detail.Service,
				detail.Banner,
				detail.Latency,
			)

			printHeaders(
				w,
				detail.Headers,
			)
		}
	}

	w.Flush()
}

func printHeaders(
	w *tabwriter.Writer,
	headers map[string][]string,
) {
	if len(headers) == 0 {
		return
	}

	keys := make(
		[]string,
		0,
		len(headers),
	)

	for key := range headers {
		keys = append(
			keys,
			key,
		)
	}

	sort.Strings(keys)

	for _, key := range keys {
		fmt.Fprintf(
			w,
			"\t\t%s\t%s\n",
			key+":",
			strings.Join(
				headers[key],
				", ",
			),
		)
	}
}
