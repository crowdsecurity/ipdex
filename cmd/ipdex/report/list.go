package report

import (
	"crowdsecurity/ipdex/cmd/ipdex/config"
	"crowdsecurity/ipdex/cmd/ipdex/style"
	"crowdsecurity/ipdex/pkg/database"
	"crowdsecurity/ipdex/pkg/display"
	"crowdsecurity/ipdex/pkg/report"
	"fmt"
	"strconv"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewListCommand() *cobra.Command {
	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all reports",
		Run: func(cmd *cobra.Command, args []string) {
			dbClient, err := database.NewClient(viper.GetString(config.SQLiteDBpathOption))
			if err != nil {
				style.Fatalf("unable to init database client: %s", err.Error())
			}

			reportClient := report.NewClient(dbClient)
			reports, err := reportClient.FindAll()
			if err != nil {
				style.Fatalf("unable to find reports: %s", err.Error())
			}

			fileTable := pterm.TableData{
				{"ID", "Created At", "Name", "File Path", "Number of IPs", "File Hash"},
			}
			queryTable := pterm.TableData{
				{"ID", "Created At", "Name", "Search Query", "Number of IPs", "Since"},
			}

			for _, report := range reports {
				if report.IsFile {
					fileTable = append(fileTable, []string{
						fmt.Sprintf("%d", report.ID),
						report.CreatedAt.Format("2006-01-02 15:04:05"),
						report.Name,
						report.FilePath,
						strconv.Itoa(len(report.IPs)),
						report.FileHash,
					})
				} else {
					queryTable = append(queryTable, []string{
						fmt.Sprintf("%d", report.ID),
						report.CreatedAt.Format("2006-01-02 15:04:05"),
						report.Name,
						report.Query,
						strconv.Itoa(len(report.IPs)),
						report.Since,
					})
				}

			}
			sectionStyle := pterm.NewStyle(pterm.FgWhite, pterm.Bold)
			display.PrintSection(sectionStyle, "Report on Files or Log Files")
			if err := pterm.DefaultTable.WithHasHeader().WithData(fileTable).Render(); err != nil {
				style.Fatal(err.Error())
			}
			display.PrintSection(sectionStyle, "Report on Search Queries")
			if err := pterm.DefaultTable.WithHasHeader().WithData(queryTable).Render(); err != nil {
				style.Fatal(err.Error())
			}

		},
	}
	return listCmd
}
