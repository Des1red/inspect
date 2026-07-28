package models

import (
	"net"
	"time"
)

var INFO struct {
	TargetName string
	Target     net.IP
}

type PortDetail struct {
	Port    int
	State   string
	Service string
	Banner  string
	Latency time.Duration
}

var LOOT struct {
	Ports   []int
	Details []PortDetail
}
