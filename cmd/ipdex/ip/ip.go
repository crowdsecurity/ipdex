package ip

import (
	"os"
	"strings"

	"github.com/crowdsecurity/ipdex/cmd/ipdex/config"
	"github.com/crowdsecurity/ipdex/cmd/ipdex/style"
	"github.com/crowdsecurity/ipdex/pkg/cti"
	"github.com/crowdsecurity/ipdex/pkg/database"
	"github.com/crowdsecurity/ipdex/pkg/display"
	"github.com/crowdsecurity/ipdex/pkg/report"

	"github.com/pterm/pterm"
	"github.com/spf13/viper"
)

func IPCommand(ipAddr string, forceRefresh bool, detailed bool) {
	dbClient, err := database.NewClient(viper.GetString(config.SQLiteDBpathOption))
	if err != nil {
		style.Fatalf("unable to init database client: %s", err.Error())
	}
	ctiClient, err := cti.NewCTIClient(viper.GetString(config.APIKeyOption), *dbClient.IP)
	if err != nil {
		style.Fatalf("unable to init cti client: %s", err.Error())
	}
	reportClient := report.NewClient(dbClient)

	data, found, err := ctiClient.Enrich(ipAddr, forceRefresh)
	if err != nil {
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
			style.Fatalf("error getting IP %s information: %s", ipAddr, err)
		}
	}

	if !found {
		style.Infof("IP address '%s' not found.", ipAddr)
		return
	}

	if _, err := reportClient.CreateOne(data); err != nil {
		style.Fatal(err.Error())
	}

	ipLastRefresh, err := reportClient.IPLastRefresh(ipAddr)
	if err != nil {
		style.Fatal(err.Error())
	}

	displayer := display.NewDisplay()
	if err := displayer.DisplayIP(data, ipLastRefresh, viper.GetString(config.OutputFormatOption), detailed); err != nil {
		style.Fatal(err.Error())
	}
}

/*
func NewIPCommand() *cobra.Command {
	var ipCmd = &cobra.Command{
		Use:   "ip",
		Short: "Show known information from CrowdSec CTI",
		Args:  cobra.MatchAll(cobra.ExactArgs(1)),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if apiKey := viper.GetString(config.APIKeyOption); apiKey == "" {
				style.MissingAPIKey()
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			ipAddr := args[0]
			IPCommand(ipAddr)
		},
	}

	return ipCmd
}
*/
