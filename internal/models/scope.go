package models

import (
	"net"
	"time"
)

var INFO struct {
	TargetName string
	Targets    []net.IP

	PortStart int
	PortEnd   int
}

type PortDetail struct {
	Port    int
	State   string
	Service string
	Banner  string
	Latency time.Duration
}

type HostResult struct {
	Target   string
	Ports    []int
	Filtered []int
	Details  []PortDetail
}

var LOOT struct {
	Hosts []HostResult
}
