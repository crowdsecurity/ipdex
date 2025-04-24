package report

import (
	"crowdsecurity/ipdex/cmd/ipdex/config"
	"crowdsecurity/ipdex/pkg/database"
	"crowdsecurity/ipdex/pkg/report"

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
