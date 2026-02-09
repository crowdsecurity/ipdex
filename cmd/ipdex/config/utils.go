package config

import (
	"fmt"
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

// EnsureOutputPath checks if the output directory exists and offers to create it if not.
// Returns true if the path exists or was created, false if the user declined.
func EnsureOutputPath(outputPath string) (bool, error) {
	if outputPath == "" {
		return true, nil
	}

	absPath, err := filepath.Abs(outputPath)
	if err != nil {
		return false, err
	}

	// Check if path exists
	info, err := os.Stat(absPath)
	if err == nil {
		// Path exists, check if it's a directory
		if !info.IsDir() {
			return false, fmt.Errorf("output path '%s' exists but is not a directory", absPath)
		}
		return true, nil
	}

	if !os.IsNotExist(err) {
		return false, err
	}

	// Path doesn't exist, prompt to create
	pterm.Warning.Printf("Output directory '%s' does not exist.\n", absPath)

	confirm, err := pterm.DefaultInteractiveConfirm.
		WithDefaultText("Do you want to create it?").
		WithDefaultValue(true).
		Show()
	if err != nil {
		return false, err
	}

	if !confirm {
		return false, nil
	}

	// Create the directory
	if err := os.MkdirAll(absPath, 0755); err != nil {
		return false, fmt.Errorf("failed to create directory: %w", err)
	}

	pterm.Success.Printf("Created directory '%s'\n", absPath)
	return true, nil
}
