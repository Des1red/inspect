package internal

import (
	"fmt"
	"inspect/internal/models"
	"sort"
	"strconv"
	"strings"
)

func sortPorts() {
	sort.Slice(models.LOOT.Ports, func(i, j int) bool {
		return models.LOOT.Ports[i] < models.LOOT.Ports[j]
	})
	sort.Slice(models.LOOT.Details, func(i, j int) bool {
		return models.LOOT.Details[i].Port < models.LOOT.Details[j].Port
	})
}

func PortScan() bool {
	port_search()
	if len(models.LOOT.Ports) < 1 {
		fmt.Println("no open ports found")
		return false
	} else {
		sortPorts()
		fmt.Print("open ports found : ")
		strs := make([]string, len(models.LOOT.Ports))
		for i, port := range models.LOOT.Ports {
			strs[i] = strconv.Itoa(port)
		}
		fmt.Println(strings.Join(strs, ", "))
	}
	enrich()
	return true
}
