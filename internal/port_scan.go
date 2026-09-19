package internal

import (
	"fmt"
	"inspect/internal/models"
	"sort"
	"strconv"
	"strings"
)

func sortPorts() {
	for i := range models.LOOT.Hosts {
		host := &models.LOOT.Hosts[i]

		sort.Ints(host.Ports)
		sort.Ints(host.Filtered)

		sort.Slice(host.Details, func(i, j int) bool {
			return host.Details[i].Port < host.Details[j].Port
		})
	}
}

func PortScan() (bool, bool) {
	port_search()

	sortPorts()

	foundOpen := false
	foundFiltered := false

	for _, host := range models.LOOT.Hosts {
		fmt.Println(host.Target)

		if len(host.Ports) > 0 {
			foundOpen = true

			open := make([]string, len(host.Ports))

			for i, port := range host.Ports {
				open[i] = strconv.Itoa(port)
			}

			fmt.Printf(
				"open     [%s]\n",
				strings.Join(open, ", "),
			)
		} else {
			fmt.Println("open     []")
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
