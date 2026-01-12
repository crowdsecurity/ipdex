package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/crowdsecurity/ipdex/cmd/ipdex/config"
	"github.com/crowdsecurity/ipdex/cmd/ipdex/file"
	helper "github.com/crowdsecurity/ipdex/cmd/ipdex/init"
	"github.com/crowdsecurity/ipdex/cmd/ipdex/ip"
	"github.com/crowdsecurity/ipdex/cmd/ipdex/report"
	"github.com/crowdsecurity/ipdex/cmd/ipdex/search"
	"github.com/crowdsecurity/ipdex/cmd/ipdex/style"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	rootCmd = &cobra.Command{
		Use:   "ipdex",
		Short: "A simple CLI tool to gather insight about a list of IPs or a log file with the CrowdSec CTI",
		Long: `A simple CLI tool to gather insight about a list of IPs or a log file with the CrowdSec CTI.
	
Examples:
  ipdex init                             # Init ipdex the first time
  ipdex 1.2.3.4                          # Show info for a single IP
  ipdex ips.txt                          # Analyze a file containing a list of IPs
  ipdex /var/log/nginx/access.log        # Analyze log files
  ipdex report list                      # List all reports
  ipdex report show -i 1                 # Inspect a specific report
  ipdex config set --api-key <api-key>   # Set a new CrowdSec CTI API key
  ipdex config show                      # Show current configuration`,
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				if apiKey := viper.GetString(config.APIKeyOption); apiKey == "" {
					style.MissingAPIKey()
				}
				arg := args[0]
				if config.IsValidIP(arg) {
					ipAddr := args[0]
					if apiKey := viper.GetString(config.APIKeyOption); apiKey == "" {
						style.MissingAPIKey()
					}
					ip.IPCommand(ipAddr, config.ForceRefresh, config.Detailed)
					return
				} else if config.IsValidFilePath(arg) {
					if apiKey := viper.GetString(config.APIKeyOption); apiKey == "" {
						style.MissingAPIKey()
					}
					file.FileCommand(arg, config.ForceRefresh, config.Yes)
					return
				} else {
					if err := cmd.Help(); err != nil {
						style.Fatal(err.Error())
					}
					fmt.Println()
					style.Fatalf("'%s' is not a valid IP address or file path", args[0])
				}
			}
			if err := cmd.Help(); err != nil {
				style.Fatal(err.Error())
			}
		},
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.AddCommand(NewVersionCommand(), helper.NewInitCommand(), config.NewConfigCmd(), report.NewReportCommand(), search.NewSearchCommand())
	rootCmd.Flags().BoolVarP(&config.ForceRefresh, "refresh", "r", false, "Force refresh an IP or all the IPs of a report")
	rootCmd.Flags().BoolVarP(&config.Yes, "yes", "y", false, "Say automatically yes to the warning about the number of IPs to scan")
	rootCmd.PersistentFlags().BoolVarP(&config.Detailed, "detailed", "d", false, "Show all informations about an IP or a report")
	rootCmd.PersistentFlags().StringVarP(&config.OutputFormat, "output", "o", "", "Output format: human, json, or csv")
	rootCmd.PersistentFlags().StringVar(&config.OutputFilePath, "output-path", "", "Output file path for saving reports in the format specified by -o (saves report and details files separately)")
	rootCmd.Flags().StringVarP(&config.ReportName, "name", "n", "", "Report name when scanning a file or making a search query")
	rootCmd.Flags().BoolVarP(&config.Batching, "batch", "b", false, "Use batching to request the CrowdSec API. Make sure you have a premium API key to use this feature.")
}

func initConfig() {
	var cacheFolder string
	var configFolder string
	var err error
	// check if cache folder exists, if not create it
	cacheFolder, err = config.GetCacheFolder()
	if err != nil {
		style.Fatal(err.Error())
	}
	if _, err := os.Stat(cacheFolder); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(cacheFolder, os.ModePerm)
		if err != nil {
			style.Fatal(err.Error())
		}
	}

	// check if config folder exists, if not create it
	configFolder, err = config.GetConfigFolder()
	if err != nil {
		style.Fatal(err.Error())
	}
	if _, err := os.Stat(configFolder); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(configFolder, os.ModePerm)
		if err != nil {
			style.Fatal(err.Error())
		}
	}
	viper.AddConfigPath(configFolder)
	viper.SetConfigType("yaml")
	viper.SetConfigName(".ipdex")
	if err := viper.ReadInConfig(); err != nil {
		if len(os.Args) > 1 && os.Args[1] != "init" {
			style.Fatal("Configue ipdex with `ipdex init` ")
		}
	}

	sqliteDBPath := viper.GetString(config.SQLiteDBpathOption)
	if sqliteDBPath == "" {
		sqliteDBPath = filepath.Join(cacheFolder, config.DefaultSQLiteDBFile)
		viper.Set(config.SQLiteDBpathOption, sqliteDBPath)
	}

	if config.OutputFormat != "" {
		viper.Set(config.OutputFormatOption, config.OutputFormat)
	} else if viper.GetString(config.OutputFormatOption) == "" {
		viper.Set(config.OutputFormatOption, config.DefaultFormat)
	}

	if viper.GetInt(config.MinIPsWarningOption) == 0 {
		viper.Set(config.MinIPsWarningOption, config.MinIPsWarningOptionDefaultValue)
	}

	if !config.IsSupportedOutputFormat(viper.GetString(config.OutputFormatOption)) {
		style.Fatalf("output format '%s' is not supported", viper.GetString(config.OutputFormatOption))
	}

	if viper.GetString(config.ReportExpirationOption) == "" {
		viper.Set(config.ReportExpirationOption, config.ReportExpirationDefaultValue)
	}

	reportClient, err := report.GetReportClient()
	if err != nil {
		style.Fatal(err.Error())
	}
	if err := reportClient.DeleteExpiredReports(viper.GetString(config.ReportExpirationOption)); err != nil {
		style.Errorf("unable to delete expired reports: %s", err.Error())
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
