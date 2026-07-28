package cmd

import (
	"fmt"
	"inspect/internal"
	"inspect/internal/bootstrap"
	"inspect/internal/models"
	"os"
	"strings"
	"text/tabwriter"
)

func flagcheck() {
	if len(os.Args) < 2 {
		return
	}

	switch os.Args[1] {
	case "install":
		bootstrap.Install()
		os.Exit(0)
	case "uninstall":
		bootstrap.Uninstall()
		os.Exit(0)
	case "help":
		help()
		os.Exit(0)
	case "version":
		version()
		os.Exit(0)
	default:
		fmt.Println("unknown flag:", os.Args[1])
		help()
		os.Exit(0)
	}
}

func target() {
	fmt.Print("IP >> ")
	var x string
	fmt.Scanln(&x)
	for strings.Trim(x, " ") == "" {
		fmt.Print("IP >> ")
		fmt.Scanln(&x)
	}
	models.INFO.TargetName = strings.Trim(x, " ")
}

func ping() {
	ok, msg := internal.Ping()
	fmt.Println(msg)
	if !ok {
		os.Exit(0)
	}
}

func ports() {
	if ok := internal.PortScan(); !ok {
		os.Exit(0)
	}
}

func result() {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PORT\tSTATE\tSERVICE\tBANNER\tLATENCY")
	for _, d := range models.LOOT.Details {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", d.Port, d.State, d.Service, d.Banner, d.Latency)
	}
	w.Flush()
}
