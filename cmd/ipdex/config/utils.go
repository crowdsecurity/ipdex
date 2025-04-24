package config

import (
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/pterm/pterm"
)

func MaxIPsCheck(nbIPs int, maxIPs int) (bool, error) {
	if nbIPs > maxIPs {
		pterm.Warning.Printf("You are about to scan %d IPs with CrowdSec API.\n", nbIPs)
		pterm.Info.Println("Make sure you have enough quota before continuing.")

		confirm, err := pterm.DefaultInteractiveConfirm.
			WithDefaultText("Do you want to continue?").
			Show()
		if err != nil {
			return false, err
		}
		return confirm, nil
	}
	return true, nil
}

func IsValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}

func IsValidFilePath(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return false
	}

	if fileInfo.IsDir() {
		return false
	}

	return true
}

func IsValidInt(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}
