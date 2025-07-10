package config

import (
	"github.com/kirsle/configdir"

	"github.com/crowdsecurity/ipdex/pkg/display"
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
	cachePath := configdir.LocalCache("ipdex")
	err := configdir.MakePath(cachePath)
	if err != nil {
		return "", err
	}
	return cachePath, nil
}

func GetConfigFolder() (string, error) {
	configPath := configdir.LocalConfig("ipdex")
	err := configdir.MakePath(configPath)
	if err != nil {
		return "", err
	}
	return configPath, nil
}

func IsSupportedOutputFormat(outputFormat string) bool {
	switch outputFormat {
	case display.JSONFormat, display.HumanFormat, display.CSVFormat:
		return true
	default:
		return false
	}
}
