package helper

import (
	"crowdsecurity/ipdex/cmd/ipdex/config"
	"crowdsecurity/ipdex/cmd/ipdex/style"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/AlecAivazis/survey/v2"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	Clean bool
)

func InitConfiguration() {
	pterm.DefaultParagraph.Printfln("You can generate an API key in the %s", style.Bold.Render("CrowdSec Console"))
	style.Blue("→ \"https://app.crowdsec.net/settings/cti-api-keys\"")
	fmt.Println()
	var apiKey string
	apiPrompt := &survey.Input{
		Message: "Enter your API key:",
	}
	apiValidator := survey.Required
	if err := survey.AskOne(apiPrompt, &apiKey, survey.WithValidator(apiValidator)); err != nil {
		log.Fatalf("Prompt failed: %v", err)
	}
	fmt.Println()

	style.Info("✅ API Key saved.")
	fmt.Println()

	pterm.DefaultParagraph.Printfln("🎉 Congratulations! You've just setup %s, you can now scan your first IP or your first file!", style.Bold.Render("ipdex"))
	style.Info("→ ipdex 1.2.3.4")
	style.Info("→ ipdex ips.txt")
	fmt.Println()

	pterm.DefaultParagraph.Printfln("When scanning files, %s will create a new report", style.Bold.Render("ipdex"))
	fmt.Printf("→ %s  # to scan a file\n", style.Bold.Render("ipdex ips.txt"))
	fmt.Printf("→ %s  # to scan a NGINX access log file\n", style.Bold.Render("ipdex /var/log/nginx/access.log"))

	fmt.Println()

	pterm.DefaultParagraph.Println("IPs result from CrowdSec CTI API are cached for 48h.")
	fmt.Printf("→ %s  # refresh IP cache\n", style.Bold.Render("ipdex 1.2.3.4 -r"))
	fmt.Printf("→ %s  # refresh all IPs cache from report\n", style.Bold.Render("ipdex ips.txt -r"))
	fmt.Println()

	pterm.DefaultParagraph.Printfln("CrowdSec quota for free tier is %s", style.Bold.Render("30 requests/week"))
	fmt.Printf("→ Everytime you will scan a file that contains more than %d IPs, you will get a warning\n", config.MinIPsWarningOptionDefaultValue)
	fmt.Printf("→ %s  # to increase minimum of IPs warning\n", style.Bold.Render("ipdex config set --min-ips-warning 500"))
	fmt.Println()

	cacheFolder, err := config.GetCacheFolder()
	if err != nil {
		style.Fatal(err.Error())
	}

	sqliteDBPath := filepath.Join(cacheFolder, config.DefaultSQLiteDBFile)

	viper.Set(config.APIKeyOption, apiKey)
	viper.Set(config.MinIPsWarningOption, config.MinIPsWarningOptionDefaultValue)
	viper.Set(config.ReportExpirationOption, config.ReportExpirationDefaultValue)
	viper.Set(config.SQLiteDBpathOption, sqliteDBPath)

	if err := viper.SafeWriteConfig(); err != nil {
		if err := viper.WriteConfig(); err != nil {
			style.Fatal(err.Error())
		}
	}

	// if clean init, remove existing database if it exists.
	if Clean {
		if _, err := os.Stat(sqliteDBPath); err == nil {
			err := os.Remove(sqliteDBPath)
			if err != nil {
				style.Errorf("Error deleting file: %s", err.Error())
			}
		} else {
			style.Errorf("error checking if current db exists: %s", err.Error())
		}
	}

	style.Info("🎮 ipdex initialized! 🎮")
}

func NewInitCommand() *cobra.Command {
	var initCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize the configuration",
		Run: func(cmd *cobra.Command, args []string) {
			InitConfiguration()
		},
	}
	initCmd.Flags().BoolVarP(&Clean, "clean", "c", false, "Clean init, remove existing database for cache.")
	return initCmd
}
