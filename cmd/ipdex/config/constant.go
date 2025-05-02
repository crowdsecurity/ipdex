package config

import "github.com/crowdsecurity/ipdex/pkg/display"

const (
	MinIPsWarningOptionDefaultValue = 30
	ReportExpirationDefaultValue    = "90d"
	DefaultSQLiteDBFile             = "ipdex.sqlite"
	DefaultFormat                   = display.HumanFormat
)
