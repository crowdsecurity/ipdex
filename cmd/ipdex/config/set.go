package config

import (
	"github.com/crowdsecurity/ipdex/cmd/ipdex/style"
	"github.com/crowdsecurity/ipdex/pkg/display"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var apiKey string
var sqliteDBPath string
var minLimitCheck int
var reportExpiration string
var outputFormat string

func NewSetCmd() *cobra.Command {
	var setCmd = &cobra.Command{
		Use: "set",
		Run: func(cmd *cobra.Command, args []string) {
			if apiKey == "" && sqliteDBPath == "" && minLimitCheck == 0 && reportExpiration == "" && outputFormat == "" {
				if err := cmd.Help(); err != nil {
					style.Fatal(err.Error())
				}
				style.Fatal("Please provide a configuration option to set.")
			}
			if apiKey != "" {
				viper.Set(APIKeyOption, apiKey)
				style.Info("New API key saved")
			}
			if sqliteDBPath != "" {
				viper.Set(SQLiteDBpathOption, sqliteDBPath)
				style.Info("New API key saved")
			}
			if minLimitCheck > 0 {
				viper.Set(MinIPsWarningOption, minLimitCheck)
				style.Infof("New minimum number of IPs to be scanned is now: %d", minLimitCheck)
			}
			if reportExpiration != "" {
				viper.Set(ReportExpirationOption, reportExpiration)
				style.Infof("Expiration of report is set to %s", reportExpiration)
			}
			if outputFormat != "" {
				if !IsSupportedOutputFormat(outputFormat) {
					style.Fatalf("Unsupported output format: %s\nSupported output format are '%s' and '%s'", outputFormat, display.HumanFormat, display.JSONFormat)
				}
				viper.Set(OutputFormatOption, outputFormat)
				style.Infof("Output format is set to '%s'", outputFormat)
			}

			err := viper.WriteConfig()
			if err != nil {
				style.Fatalf("fail writing config: %s", err)
			}
		},
	}

	setCmd.Flags().StringVar(&apiKey, "api-key", "", "CTI API key")
	setCmd.Flags().StringVar(&outputFormat, "output-format", "", "Output Format: (human or json)")
	setCmd.Flags().StringVar(&sqliteDBPath, "sqlite", "", "SQLite DB path")
	setCmd.Flags().StringVar(&reportExpiration, "report-expiration", "", "Set report expiration duration (eg. 168h, 30d, 60d, 90d ...)")
	setCmd.Flags().IntVar(&minLimitCheck, "min-ips-warning", 0, "Minimum number of IPs to be scanned before displaying this warning")
	return setCmd
}
