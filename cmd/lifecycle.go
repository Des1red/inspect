package cmd

import (
	"fmt"
	"ipspect/internal"
	"ipspect/internal/bootstrap"
	"ipspect/internal/output"
	"ipspect/internal/portscan"
	"os"
)

var saveResults bool

func flagcheck() {
	internal.SetDefaultPorts()

	if len(os.Args) < 2 {
		return
	}

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]

		switch arg {
		case "-s":
			saveResults = true

		case "-p":
			if i+1 >= len(os.Args) {
				fmt.Println("-p requires a port or port range")
				fmt.Println("examples:")
				fmt.Println("  -p 22")
				fmt.Println("  -p 1-22")
				os.Exit(1)
			}

			i++

			if err := internal.SetPorts(os.Args[i]); err != nil {
				fmt.Println("invalid port range:", err)
				os.Exit(1)
			}

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
			os.Exit(1)
		}
	}
}

func scan() {
	internal.Target()

	portscan.Ping()
	portscan.Ports()
	portscan.Result()

}
func save() {
	filename, err := output.Save()
	if err != nil {
		fmt.Println(
			"failed to save results:",
			err,
		)
		return
	}

	fmt.Println(
		"results saved to",
		filename,
	)
}
