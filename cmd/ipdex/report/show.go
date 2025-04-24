package report

import (
	"crowdsecurity/ipdex/cmd/ipdex/config"
	"crowdsecurity/ipdex/cmd/ipdex/style"
	"crowdsecurity/ipdex/pkg/database"
	"crowdsecurity/ipdex/pkg/models"
	"crowdsecurity/ipdex/pkg/report"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewShowCommand() *cobra.Command {
	var reportID uint
	var filepath string
	var listCmd = &cobra.Command{
		Use:   "show",
		Short: "Show a report",
		Run: func(cmd *cobra.Command, args []string) {
			dbClient, err := database.NewClient(viper.GetString(config.SQLiteDBpathOption))
			if err != nil {
				style.Fatalf("unable to init database client: %s", err.Error())
			}
			if len(args) > 0 && reportID == 0 && filepath == "" {
				if config.IsValidInt(args[0]) {
					id, _ := strconv.Atoi(args[0])
					reportID = uint(id)
				} else if config.IsValidFilePath(args[0]) {
					filepath = args[0]
				}
			}
			reportClient := report.NewClient(dbClient)
			var report *models.Report
			if reportID > 0 {
				report, err = reportClient.FindById(reportID)
				if err != nil {
					style.Fatalf("unable to find reports: %s", err.Error())
				}
				if report == nil {
					style.Fatalf("Report with ID '%d' not found", reportID)
				}
			} else if filepath != "" {
				report, err = reportClient.FindByHash(filepath)
				if err != nil {
					style.Fatalf("unable to find reports: %s", err.Error())
				}
				if report == nil {
					style.Fatalf("Report with file path '%s' not found", filepath)
				}
			} else {
				style.Fatal("Please provide a report ID or file used in the report you want to show with `ipdex report show 1`")
			}
			if err := reportClient.Display(report, report.Stats, viper.GetString(config.OutputFormatOption), config.Detailed); err != nil {
				style.Fatal(err.Error())
			}
			fmt.Println()
		},
	}
	listCmd.Flags().UintVarP(&reportID, "id", "i", 0, "Report ID to search for")
	listCmd.Flags().StringVarP(&filepath, "file", "f", "", "Filepath to filter on to search for report")
	return listCmd
}
