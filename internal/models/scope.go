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

	Ports    []int
	PortSpec string
}

type PortDetail struct {
	Port    int
	State   string
	Service string
	Banner  string
	Headers map[string][]string
	Latency time.Duration
}

type HostResult struct {
	Target   string
	Ports    []int
	Filtered []int
	Details  []PortDetail
}

var LOOT struct {
	ICMPReachable []string
	Hosts         []HostResult
}
