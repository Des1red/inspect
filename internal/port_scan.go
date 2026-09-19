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

		sort.Slice(host.Details, func(i, j int) bool {
			return host.Details[i].Port < host.Details[j].Port
		})
	}
}

func PortScan() bool {
	port_search()

	sortPorts()

	found := false

	for _, host := range models.LOOT.Hosts {
		if len(host.Ports) == 0 {
			continue
		}

		found = true

		strs := make([]string, len(host.Ports))

		for i, port := range host.Ports {
			strs[i] = strconv.Itoa(port)
		}

		fmt.Printf(
			"%s open ports : %s\n",
			host.Target,
			strings.Join(strs, ", "),
		)
	}

	if !found {
		fmt.Println("no open ports found")
		return false
	}

	enrich()

	return true
}
