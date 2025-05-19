package file

import (
	"strings"

	"github.com/crowdsecurity/ipdex/cmd/ipdex/config"
	"github.com/crowdsecurity/ipdex/cmd/ipdex/style"
	"github.com/crowdsecurity/ipdex/pkg/cti"
	"github.com/crowdsecurity/ipdex/pkg/database"
	"github.com/crowdsecurity/ipdex/pkg/display"
	"github.com/crowdsecurity/ipdex/pkg/report"

	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
	"github.com/pterm/pterm"
	"github.com/spf13/viper"
)

var (
	ipRegex = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+`)
)

func FileCommand(file string, forceRefresh bool, yes bool) {
	outputFormat := viper.GetString(config.OutputFormatOption)
	filepath, err := filepath.Abs(file)
	if err != nil {
		style.Fatal(err.Error())
	}
	dbClient, err := database.NewClient(viper.GetString(config.SQLiteDBpathOption))
	if err != nil {
		style.Fatalf("unable to init database client: %s", err.Error())
	}
	ctiClient, err := cti.NewCTIClient(viper.GetString(config.APIKeyOption), *dbClient.IP)
	if err != nil {
		style.Fatalf("unable to init cti client: %s", err.Error())
	}
	reportClient := report.NewClient(dbClient)
	report, err := reportClient.FindByHash(filepath)
	if err != nil {
		style.Fatal(err.Error())
	}
	ipsToProcess := make([]string, 0)
	nbIPToProcess := 0
	reportExist := true
	if report == nil || len(report.IPs) == 0 {
		reportExist = false
	}
	if !reportExist {
		readFile, err := os.Open(filepath)
		if err != nil {
			style.Fatal(err.Error())
		}

		fileScanner := bufio.NewScanner(readFile)
		fileScanner.Split(bufio.ScanLines)
		for fileScanner.Scan() {
			line := fileScanner.Text()
			ipsMatch := ipRegex.FindAllString(line, -1)
			for _, ipAddr := range ipsMatch {
				if slices.Contains(ipsToProcess, ipAddr) {
					continue
				}
				if !config.IsValidIP(ipAddr) {
					continue
				}
				ipsToProcess = append(ipsToProcess, ipAddr)
			}
		}
		nbIPToProcess = len(ipsToProcess)
	} else {

		for _, ip := range report.IPs {
			ipsToProcess = append(ipsToProcess, ip.Ip)
		}
		expiredIPs, err := reportClient.GetExpiredIPFromReport(report.ID)
		if err != nil {
			style.Fatal(err.Error())
		}
		nbIPToProcess = len(expiredIPs)
		if outputFormat == display.HumanFormat && len(expiredIPs) > 0 {
			style.Infof("Report for file '%s' and same checksum already exists, updating it ...", filepath)
		}
	}
	if !yes {
		confirm, err := config.MaxIPsCheck(nbIPToProcess, viper.GetInt(config.MinIPsWarningOption))
		if err != nil {
			style.Fatal(err.Error())
		}
		if !confirm {
			return
		}
	}
	bar := pterm.DefaultProgressbar.WithTotal(len(ipsToProcess)).WithTitle("Processing items")

	if outputFormat == display.HumanFormat {
		bar, err = bar.Start()
		if err != nil {
			style.Fatal(err.Error())
		}
	}

	ipList := make([]*cticlient.SmokeItem, 0)
	for _, ipAddr := range ipsToProcess {
		if outputFormat == display.HumanFormat {
			bar.UpdateTitle("Enriching with CrowdSec CTI: " + ipAddr)
		}
		data, _, err := ctiClient.Enrich(ipAddr, forceRefresh)
		if err != nil {
			if _, barErr := bar.Stop(); barErr != nil {
				style.Fatal(barErr.Error())
			}
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
		ipList = append(ipList, data)
		if outputFormat == display.HumanFormat {
			bar.Increment()
		}
	}
	if outputFormat == display.HumanFormat {
		if _, err := bar.Stop(); err != nil {
			style.Fatal(err.Error())
		}
	}
	if !reportExist {
		report, err = reportClient.Create(ipList, config.ReportName, true, filepath, false, "", "")
		if err != nil {
			style.Fatalf("unable to create report: %s", err)
		}
	}
	stats := reportClient.GetStats(report)
	if err := reportClient.Display(report, stats, viper.GetString(config.OutputFormatOption), config.Detailed); err != nil {
		style.Fatal(err.Error())
	}
	if !reportExist && outputFormat == display.HumanFormat {
		style.Infof("Created report with ID '%d'.", report.ID)
	}
	if outputFormat == display.HumanFormat {
		fmt.Println()
		style.Infof("View report               ipdex report show %d", report.ID)
		style.Infof("View all IPs in report    ipdex report show %d d", report.ID)
	}
}

/*
func NewFileCommand() *cobra.Command {
	showIPs := false
	var ipCmd = &cobra.Command{
		Use:   "file",
		Short: "Show known information from CrowdSec CTI from a given file",
		Args:  cobra.MatchAll(cobra.ExactArgs(1)),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if apiKey := viper.GetString(config.APIKeyOption); apiKey == "" {
				return fmt.Errorf("please provide an api key with 'ipdex config set --api-key <API KEY>' command")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			FileCommand(args[0], showIPs)
		},
	}
	ipCmd.Flags().BoolVarP(&showIPs, "all", "a", false, "Show all the IPs of the report in a table")
	return ipCmd
}
*/
