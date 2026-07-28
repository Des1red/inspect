package bootstrap

import (
	"fmt"
	"os"
	"os/exec"
)

const binName = "inspect"
const installPath = "/usr/local/bin/" + binName
const InstallPath = installPath

func Install() {
	cmd := exec.Command("go", "build", "-o", binName, ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("build failed:", err)
		return
	}

	src, err := os.Open(binName)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer src.Close()

	dst, err := os.OpenFile(installPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Println("error (are you root?):", err)
		return
	}
	defer dst.Close()

	if _, err := dst.ReadFrom(src); err != nil {
		fmt.Println("error copying binary:", err)
		return
	}

	os.Remove(binName)
	fmt.Println("installed to", installPath)
}
