package report

import (
	"github.com/crowdsecurity/ipdex/cmd/ipdex/config"
	"github.com/crowdsecurity/ipdex/pkg/database"
	"github.com/crowdsecurity/ipdex/pkg/report"

	"github.com/spf13/viper"
)

func GetReportClient() (*report.ReportClient, error) {
	dbClient, err := database.NewClient(viper.GetString(config.SQLiteDBpathOption))
	if err != nil {
		return nil, err
	}
	reportClient := report.NewClient(dbClient)

	return reportClient, nil
}
