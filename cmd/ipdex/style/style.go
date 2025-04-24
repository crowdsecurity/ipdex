package style

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
)

var BlueStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("12")).
	Bold(true)

var Bold = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#FFFFFF")). // bright white
	Bold(true)

var RedStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("9"))

func Blue(s string) {
	fmt.Printf("%s\n", BlueStyle.Render(s))
}

func Bluef(format string, a ...interface{}) {
	fmt.Printf("%s\n", BlueStyle.Render(fmt.Sprintf(format, a...)))
}

func Error(s string) {
	fmt.Printf("%s\n", RedStyle.Render(s))
}

func Errorf(format string, a ...interface{}) {
	fmt.Printf("%s\n", RedStyle.Render(fmt.Sprintf(format, a...)))
}

func Fatal(s string) {
	fmt.Printf("%s\n", RedStyle.Render(s))
	os.Exit(1)
}

func Fatalf(format string, a ...interface{}) {
	fmt.Printf("%s\n", RedStyle.Render(fmt.Sprintf(format, a...)))
	os.Exit(1)
}

func Info(s string) {
	fmt.Printf("%s\n", Bold.Render(s))
}

func Infof(format string, a ...interface{}) {
	fmt.Printf("%s\n", Bold.Render(fmt.Sprintf(format, a...)))
}

func MissingAPIKey() {
	fmt.Printf("%s\n", RedStyle.Render(("No API key configured")))
	fmt.Printf("You can configure your API Key with `%s``\n", Bold.Render("ipdex config set --api-key <YOUR-API-KEY-HERE>"))
	fmt.Printf("You can visit \"%s\" to create your first API key!\n", Bold.Render("https://app.crowdsec.net/settings/cti-api-keys"))
	os.Exit(1)
}
