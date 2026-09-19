package cmd

import (
	"fmt"

	"inspect/internal/bootstrap"
	"inspect/internal/models"

	"github.com/Des1red/clihelp"
)

func help() {
	description := `A simple command-line IP scanner. Checks if a host is alive via ICMP echo, then performs a full TCP connect port scan and enriches open ports with service name, banner, and latency.`

	fmt.Println(description)
	fmt.Println()

	fmt.Println("Usage:")
	fmt.Println("  inspect [command]")
	fmt.Println("  inspect [flags]")
	fmt.Println()

	fmt.Println("Commands:")
	clihelp.Print(
		clihelp.F(
			"install",
			"",
			"build and install the binary to "+bootstrap.InstallPath,
		),
		clihelp.F(
			"uninstall",
			"",
			"remove the installed binary",
		),
		clihelp.F(
			"help",
			"",
			"show this help message",
		),
		clihelp.F(
			"version",
			"",
			"show version",
		),
	)

	fmt.Println()

	fmt.Println("Flags:")
	clihelp.Print(
		clihelp.F(
			"-s",
			"",
			"save scan results as Markdown",
		),
		clihelp.F(
			"-p",
			"<port>",
			"scan a single TCP port",
		),
		clihelp.F(
			"-p",
			"<start-end>",
			"scan a TCP port range",
		),
	)

	fmt.Println()
	fmt.Println("Defaults:")
	clihelp.Print(
		clihelp.F(
			"ports",
			"1-65535",
			"used when -p is not specified",
		),
	)
}

func version() {
	fmt.Println(models.Version)
}
