package cmd

import (
	"fmt"
	"inspect/internal"
	"inspect/internal/bootstrap"
	"inspect/internal/models"
	"inspect/internal/output"
	"os"
	"strings"
	"text/tabwriter"
)

var saveResults bool

func flagcheck() {
	if len(os.Args) < 2 {
		return
	}

	for _, arg := range os.Args[1:] {
		switch arg {
		case "-s":
			saveResults = true

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
			fmt.Println("unknown argument:", arg)
			help()
			os.Exit(0)
		}
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
		fmt.Println("inspecting anyways.")
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
		fmt.Fprintf(
			w,
			"%d\t%s\t%s\t%s\t%s\n",
			d.Port,
			d.State,
			d.Service,
			d.Banner,
			d.Latency,
		)
	}

	w.Flush()
}

func save() {
	filename, err := output.Save()
	if err != nil {
		fmt.Println("failed to save results:", err)
		return
	}

	fmt.Println("results saved to", filename)
}
