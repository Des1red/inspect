package cmd

import (
	"fmt"
	"inspect/internal/bootstrap"
	"inspect/internal/models"
)

func help() {
	fmt.Println("usage: inspect [command]")
	fmt.Println()
	fmt.Println("commands:")
	fmt.Println("  install    build and install the binary to", bootstrap.InstallPath)
	fmt.Println("  uninstall  remove the installed binary")
	fmt.Println("  help       show this help message")
	fmt.Println("  version    show version")
}

func version() {
	fmt.Println(models.Version)
}
