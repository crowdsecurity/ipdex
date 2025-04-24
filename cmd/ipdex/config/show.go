package config

import (
	"crowdsecurity/ipdex/cmd/ipdex/style"
	"crowdsecurity/ipdex/pkg/display"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/charmbracelet/lipgloss"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	maxKeyLength = 20
)

func CapitalizeWords(s string) string {
	words := strings.Fields(s)
	for i, word := range words {
		runes := []rune(word)
		if len(runes) > 0 {
			runes[0] = unicode.ToUpper(runes[0])
		}
		words[i] = string(runes)
	}
	return strings.Join(words, " ")
}

func NewShowCmd() *cobra.Command {
	var showCmd = &cobra.Command{
		Use:     "show",
		Short:   "Show configuration of ipdex",
		Aliases: []string{"list"},
		Run: func(cmd *cobra.Command, args []string) {
			sectionStyle := pterm.NewStyle(pterm.FgWhite, pterm.Bold)
			writer := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', tabwriter.AlignRight)
			rd := display.NewRowDisplay(writer, maxKeyLength)
			keyStyle := lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("15"))
			valueStyle := lipgloss.NewStyle()

			fmt.Println()

			display.PrintSection(sectionStyle, "Default Configuration")
			rd.PrintRow("Configuration File", viper.ConfigFileUsed(), keyStyle, valueStyle)
			cacheFolder, err := GetCacheFolder()
			if err != nil {
				style.Fatal(err.Error())
			}
			rd.PrintRow("Cache Folder", cacheFolder, keyStyle, valueStyle)

			configFolder, err := GetConfigFolder()
			if err != nil {
				style.Fatal(err.Error())
			}
			rd.PrintRow("Config Folder", configFolder, keyStyle, valueStyle)
			fmt.Println()

			display.PrintSection(sectionStyle, "User Configuration")
			for _, parameter := range Parameters {
				param := CapitalizeWords(strings.Replace(parameter, "_", " ", -1))
				rd.PrintRow(param, viper.GetString(parameter), keyStyle, valueStyle)
			}
			fmt.Println()

		},
	}

	return showCmd
}
