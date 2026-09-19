package cmd

import (
	"fmt"
	"inspect/internal/bootstrap"
	"inspect/internal/models"
)

func help() {
	description := `A simple command-line IP scanner. Checks if a host is alive via ICMP echo, then performs a full TCP connect port scan and enriches open ports with service name, banner, and latency.`
	fmt.Println(description)
	fmt.Println("usage: inspect [command]")
	fmt.Println()
	fmt.Println("commands:")
	fmt.Println("  install    build and install the binary to", bootstrap.InstallPath)
	fmt.Println("  uninstall  remove the installed binary")
	fmt.Println("  help       show this help message")
	fmt.Println("  version    show version")

	fmt.Println("flags:")
	fmt.Println("  -s         save scan results as Markdown")
}

func version() {
	fmt.Println(models.Version)
}
