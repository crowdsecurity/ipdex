package config

import (
	"crowdsecurity/ipdex/pkg/display"
	"os"
	"path/filepath"
)

const (
	APIKeyOption           = "api_key"
	SQLiteDBpathOption     = "sqlite_path"
	OutputFormatOption     = "output_format"
	MinIPsWarningOption    = "min_ips_warning"
	ReportExpirationOption = "report_expiration_days"
)

var Parameters = []string{APIKeyOption, SQLiteDBpathOption, OutputFormatOption, MinIPsWarningOption, ReportExpirationOption}
var CacheFolder string
var ConfigFolder string

func GetCacheFolder() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "ipdex"), nil
}

func GetConfigFolder() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "ipdex"), nil
}

func IsSupportedOutputFormat(outputFormat string) bool {
	switch outputFormat {
	case display.JSONFormat, display.HumanFormat:
		return true
	default:
		return false
	}
}
