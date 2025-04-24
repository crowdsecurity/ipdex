package display

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/pterm/pterm"
)

func (r *RowDisplay) PrintRow(key string, value string, keyStyle lipgloss.Style, valueStyle lipgloss.Style) {
	labelWithPadding := fmt.Sprintf("%-*s", r.maxSpace, key)
	fmt.Fprintf(r.writer, "%s\t%s\n", keyStyle.Render(labelWithPadding), valueStyle.Render(value))
	r.writer.Flush()
}

func (r *RowDisplay) PrintValue(value string, style lipgloss.Style) {
	fmt.Fprintf(r.writer, "%s\n", style.Render(value))
	r.writer.Flush()
}

func PrintSection(sectionStyle *pterm.Style, section string) {
	sectionStyle.Println()
	sectionStyle.Printf("\033[4m%s\033[0m\n", section)
	sectionStyle.Println()
}

func CountryCodeToFlagEmoji(code string) string {
	if len(code) != 2 {
		return code // fallback to the original code
	}
	code = strings.ToUpper(code)
	r1 := rune(code[0]) - 'A' + 0x1F1E6
	r2 := rune(code[1]) - 'A' + 0x1F1E6
	return string([]rune{r1, r2})
}
func GetLevelStyle(style lipgloss.Style, level string) lipgloss.Style {
	switch level {
	case "high":
		style = style.Foreground(lipgloss.Color("9"))
	case "medium":
		style = style.Foreground(lipgloss.Color("11"))
	case "low":
		style = style.Foreground(lipgloss.Color("33"))
	default:
		style = style.Foreground(lipgloss.Color("7"))
	}

	return style
}

func GetReputationStyle(style lipgloss.Style, reputation string) lipgloss.Style {
	switch reputation {
	case "malicious":
		style = style.Foreground(lipgloss.Color("#F55B60"))
	case "suspicious":
		style = style.Foreground(lipgloss.Color("#FB923C"))
	case "known":
		style = style.Foreground(lipgloss.Color("#888BCE"))
	case "safe":
		style = style.Foreground(lipgloss.Color("#71E59B"))
	case "benign":
		style = style.Foreground(lipgloss.Color("#60A5FA"))
	default:
		style = style.Foreground(lipgloss.Color("7"))
	}

	return style
}

func GetPercentKnownColor(style lipgloss.Style, percent float64) lipgloss.Style {
	if percent <= 25.0 {
		style = style.Foreground(lipgloss.Color("#F55B60"))
	} else if percent <= 50.0 {
		style = style.Foreground(lipgloss.Color("#FB923C"))
	} else if percent <= 75.0 {
		style = style.Foreground(lipgloss.Color("#888BCE"))
	} else {
		style = style.Foreground(lipgloss.Color("#71E59B"))
	}

	return style
}

type KV struct {
	Key   string
	Value int
}

func getTopN(m map[string]int, n int) []KV {
	var sorted []KV
	for k, v := range m {
		sorted = append(sorted, KV{k, v})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	if len(sorted) > n {
		return sorted[:n]
	}
	return sorted
}

// Converts ISO country code to flag emoji
func getFlag(isoCode string) string {
	if isoCode == "N/A" {
		return ""
	}
	isoCode = strings.ToUpper(isoCode)
	if len(isoCode) != 2 {
		return "🏳️"
	}
	// Unicode regional indicator symbol: 🇦 is 0x1F1E6 + ('A' - 'A')
	runes := []rune{}
	for _, char := range isoCode {
		if char < 'A' || char > 'Z' {
			return "🏳️"
		}
		runes = append(runes, rune(0x1F1E6+char-'A'))
	}
	return string(runes)
}
