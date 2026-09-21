package portscan

import (
	"fmt"
	"ipspect/internal/models"
	"sort"
	"strconv"
	"strings"
)

func sortPorts() {
	for i := range models.LOOT.Hosts {
		host := &models.LOOT.Hosts[i]

		sort.Ints(host.Ports)
		sort.Ints(host.Closed)
		sort.Ints(host.Filtered)

		sort.Slice(host.Details, func(i, j int) bool {
			return host.Details[i].Port < host.Details[j].Port
		})
	}
}

func portScan() (bool, bool) {
	port_search()

	sortPorts()

	foundOpen := false
	foundFiltered := false

	for _, host := range models.LOOT.Hosts {
		fmt.Println(host.Target)

		if len(host.Ports) > 0 {
			foundOpen = true

			fmt.Printf(
				"open     [%s]\n",
				formatPorts(host.Ports),
			)
		} else {
			fmt.Println("open     []")
		}

		/*
			Only display closed ports when
			the user explicitly selected
			ports with -p.

			Default 1-65535 scans do not
			print thousands of closed ports.
		*/
		if len(models.INFO.Ports) > 0 {
			fmt.Printf(
				"closed   [%s]\n",
				formatPorts(host.Closed),
			)
		}

		if len(host.Filtered) > 0 {
			foundFiltered = true
		}

		fmt.Printf(
			"filtered %d\n",
			len(host.Filtered),
		)

		fmt.Println()
	}

	if foundOpen {
		enrich()
	}

	return foundOpen, foundFiltered
}

func formatPorts(
	ports []int,
) string {
	values := make(
		[]string,
		len(ports),
	)

	for i, port := range ports {
		values[i] = strconv.Itoa(
			port,
		)
	}

	return strings.Join(
		values,
		", ",
	)
}
