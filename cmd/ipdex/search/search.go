package search

import (
	"crowdsecurity/ipdex/cmd/ipdex/config"
	"crowdsecurity/ipdex/cmd/ipdex/style"
	"crowdsecurity/ipdex/pkg/cti"
	"crowdsecurity/ipdex/pkg/database"
	"crowdsecurity/ipdex/pkg/report"
	"crowdsecurity/ipdex/pkg/utils"
	"strings"

	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	Limit    = 1000
	MaxLimit = 1000
)

func SearchCommand(query string, since string, maxResult int) {
	dbClient, err := database.NewClient(viper.GetString(config.SQLiteDBpathOption))
	if err != nil {
		style.Fatalf("unable to init database client: %s", err.Error())
	}
	ctiClient, err := cti.NewCTIClient(viper.GetString(config.APIKeyOption), *dbClient.IP)
	if err != nil {
		style.Fatalf("unable to init cti client: %s", err.Error())
	}
	if Limit > maxResult && maxResult != 0 {
		Limit = maxResult
	}
	reportClient := report.NewClient(dbClient)
	paginator := cti.NewSearchPaginator(ctiClient, cti.SearchParams{
		Since: &since,
		Limit: &Limit,
		Query: &query,
	})
	itemList := make([]*cticlient.SmokeItem, 0)
	spinner, _ := pterm.DefaultSpinner.Start("Fetching data...")
	ipCache := make(map[string]bool, 0)
	for {
		items, err := paginator.Next()
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "too much ips requested") {
			Limit = 10
			paginator = cti.NewSearchPaginator(ctiClient, cti.SearchParams{
				Since: &since,
				Limit: &Limit,
				Query: &query,
			})
			continue
		}
		if err != nil {
			spinner.Fail("Error fetching data")
			if err.Error() == "unauthorized" {
				style.Error("\nInvalid API Key.\n")
				pterm.DefaultParagraph.Printfln("You can generate an API key on the %s", style.Bold.Render("CrowdSec Console"))
				style.Blue("→ \"https://app.crowdsec.net/settings/cti-api-keys\"")
				os.Exit(1)
			} else if strings.Contains(strings.ToLower(err.Error()), "too many requests") {
				style.Error("\nYou have exceeded the rate limit. Please try again later. (Rate limit reached)\n")
				pterm.DefaultParagraph.Printfln("You can upgrade your rate limit on the %s", style.Bold.Render("CrowdSec Console"))
				style.Blue("→ \"https://app.crowdsec.net/settings/cti-api-keys\"")
				os.Exit(1)
			} else if strings.Contains(strings.ToLower(err.Error()), "request quota exceeded") || strings.Contains(strings.ToLower(err.Error()), "limit exceeded") {
				style.Error("\nYou have exceeded your usage quota.\n")
				pterm.DefaultParagraph.Printfln("You can upgrade your quotas on the %s", style.Bold.Render("CrowdSec Console"))
				style.Blue("→ \"https://app.crowdsec.net/settings/cti-api-keys\"")
				os.Exit(1)
			} else {
				style.Fatalf("error running query '%s': %s", query, err.Error())
			}
		}
		if items == nil {
			break
		}
		if len(items) == 0 {
			spinner.Info(fmt.Sprintf("No results found for the query '%s'.", query))
			os.Exit(0)
		}
		for _, item := range items {
			if _, ok := ipCache[item.Ip]; ok {
				continue
			}
			ipCache[item.Ip] = true
			itemList = append(itemList, item)
		}
		if len(itemList) >= maxResult && maxResult != 0 {
			spinner.UpdateText(fmt.Sprintf("Fetched %d items, stopping...", len(itemList)))
			break
		}

		spinner.UpdateText(fmt.Sprintf("Fetched %d items...", len(itemList)))
	}

	spinner.Success("Fetching complete!")

	report, err := reportClient.Create(itemList, config.ReportName, false, "", true, query, since)
	if err != nil {
		style.Fatalf("unable to create report: %s", err)
	}
	stats := reportClient.GetStats(report)
	if err := reportClient.Display(report, stats, viper.GetString(config.OutputFormatOption), config.Detailed); err != nil {
		style.Fatal(err.Error())
	}
	fmt.Println()
	style.Infof("Created report with ID '%d'.", report.ID)
	style.Infof("View report                    ipdex report show %d", report.ID)
	style.Infof("View all IPs in report         ipdex report show %d -w", report.ID)
}

func NewSearchCommand() *cobra.Command {
	since := "30d"
	maxResult := 0
	var searchCmd = &cobra.Command{
		Use:   "search",
		Short: "Search CrowdSec CTI IPs from a given lucene query",
		Args:  cobra.MatchAll(cobra.ExactArgs(1)),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if apiKey := viper.GetString(config.APIKeyOption); apiKey == "" {
				return fmt.Errorf("please provide an api key with 'ipdex config set --api-key <API KEY>' command")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			if _, err := utils.ParseDuration(since); err != nil {
				style.Fatalf("invalid since duration '%s': %s", since, err.Error())
			}

			SearchCommand(args[0], since, maxResult)
		},
	}
	searchCmd.Flags().StringVarP(&since, "since", "s", since, "Duration on which to run the query (eg. 24h, 7d, 30d ...). Default and maximum duration is '30d'")
	searchCmd.Flags().IntVarP(&maxResult, "max", "m", 0, "Maximum of result to get from the query. Default is 0 (unlimited).")
	return searchCmd
}
