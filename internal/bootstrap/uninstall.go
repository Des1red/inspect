package bootstrap

import (
	"fmt"
	"os"
)

func Uninstall() {
	if err := os.Remove(installPath); err != nil {
		fmt.Println("error (are you root?):", err)
		return
	}
	fmt.Println("removed", installPath)
}
