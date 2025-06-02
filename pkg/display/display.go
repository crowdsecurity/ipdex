package display

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/crowdsecurity/ipdex/cmd/ipdex/style"
	"github.com/crowdsecurity/ipdex/pkg/models"

	"github.com/charmbracelet/lipgloss"
	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
	"github.com/pterm/pterm"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	JSONFormat                = "json"
	HumanFormat               = "human"
	maxCVEDisplay             = 3
	maxBehaviorsDisplay       = 3
	maxClassificationDisplay  = 3
	maxBlocklistDisplay       = 3
	maxTargetCountriesDisplay = 3
	maxKeyLength              = 25
	maxTopDisplayReport       = 5
	maxKeyLen                 = 50
)

type Display struct {
}

func NewDisplay() *Display {
	return &Display{}
}

type RowDisplay struct {
	writer   *tabwriter.Writer
	maxSpace int
}

func NewRowDisplay(writer *tabwriter.Writer, maxSpace int) *RowDisplay {
	return &RowDisplay{
		writer:   writer,
		maxSpace: maxSpace,
	}
}

func (d *Display) DisplayIP(item *cticlient.SmokeItem, ipLastRefresh time.Time, format string, detailed bool) error {
	switch format {
	case HumanFormat:
		if err := displayIP(item, ipLastRefresh, detailed); err != nil {
			return err
		}
	case JSONFormat:
		if err := displayIPJSON(item); err != nil {
			return err
		}
	default:
		return fmt.Errorf("format '%s' not supported", format)
	}
	return nil
}

func displayIPJSON(item *cticlient.SmokeItem) error {
	jsonData, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", jsonData)
	return nil
}

func displayIP(item *cticlient.SmokeItem, ipLastRefresh time.Time, detailed bool) error {
	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("15"))
	levelStyle := lipgloss.NewStyle().Bold(true)
	valueStyle := lipgloss.NewStyle().Bold(true)
	writer := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', tabwriter.AlignRight)
	sectionStyle := pterm.NewStyle(pterm.FgWhite, pterm.Bold)
	rd := NewRowDisplay(writer, maxKeyLength)

	asName := "N/A"
	if item.AsName != nil {
		asName = *item.AsName
	}
	ipRange := "N/A"
	if item.IpRange != nil {
		ipRange = *item.IpRange
	}

	reverseDNS := "N/A"
	if item.ReverseDNS != nil {
		reverseDNS = *item.ReverseDNS
	}

	country := "N/A"
	if item.Location.Country != nil {
		country = *item.Location.Country
	}

	PrintSection(sectionStyle, "IP Information")

	reputationStr := item.Reputation
	if item.Reputation == "safe" {
		fps := ""
		for _, fp := range item.Classifications.FalsePositives {
			fps += fp.Label + ", "
		}
		fps = fps[:len(fps)-2]
		reputationStr += fmt.Sprintf(" (%s)", fps)
	}

	if item.History.FirstSeen == nil {
		item.History.FirstSeen = new(string)
		*item.History.FirstSeen = "N/A"
	}
	if item.History.LastSeen == nil {
		item.History.LastSeen = new(string)
		*item.History.LastSeen = "N/A"
	}

	rd.PrintRow("IP", item.Ip, keyStyle, valueStyle)
	rd.PrintRow("Reputation", reputationStr, keyStyle, GetReputationStyle(levelStyle, item.Reputation))
	rd.PrintRow("Confidence", item.Confidence, keyStyle, GetLevelStyle(levelStyle, item.Reputation))
	rd.PrintRow("Country", fmt.Sprintf("%s %s", country, getFlag(country)), keyStyle, valueStyle)
	rd.PrintRow("Autonomous System", asName, keyStyle, valueStyle)
	rd.PrintRow("Reverse DNS", reverseDNS, keyStyle, valueStyle)
	rd.PrintRow("Range", ipRange, keyStyle, valueStyle)
	rd.PrintRow("First Seen", strings.Split(*item.History.FirstSeen, "+")[0], keyStyle, valueStyle)
	rd.PrintRow("Last Seen", strings.Split(*item.History.LastSeen, "+")[0], keyStyle, valueStyle)
	rd.PrintRow("Console URL", fmt.Sprintf("https://app.crowdsec.net/cti/%s", item.Ip), keyStyle, valueStyle)
	rd.PrintRow("Last Local Refresh", ipLastRefresh.Format("2006-01-02 15:04:05"), keyStyle, valueStyle)

	PrintSection(sectionStyle, "Threat Information")

	//rd.PrintRow("In Community Blocklist", getIsCommunityBL(item.IsPartOfCommunityBlocklist()), keyStyle, communityBLStyle(item.IsPartOfCommunityBlocklist(), valueStyle))
	threatInfo := false
	if len(item.GetBehaviors()) > 0 {
		threatInfo = true
		cpt := 0
		total := len(item.Behaviors)
		rd.PrintRow("Behaviors", "", keyStyle, valueStyle)
		for _, behavior := range item.Behaviors {
			rd.PrintRow("", behavior.Label, keyStyle, valueStyle.Foreground(lipgloss.Color("#F55B60")))
			cpt++
			if !detailed {
				if cpt == maxBehaviorsDisplay {
					remaining := total - cpt
					if remaining > 0 {
						rd.PrintRow("", fmt.Sprintf("... and %d more\n", remaining), keyStyle, valueStyle)
					}
					break
				}
			}
		}
		fmt.Fprintln(writer)
	}

	if len(item.GetFalsePositives()) > 0 {
		threatInfo = true
		cpt := 0
		total := len(item.Classifications.FalsePositives)
		rd.PrintRow("False Positives", "", keyStyle, valueStyle)
		for _, falsePositive := range item.Classifications.FalsePositives {
			rd.PrintRow("", falsePositive.Label, keyStyle, valueStyle.Foreground(lipgloss.Color("#71E59B")))
			cpt++
			if !detailed {
				if cpt == maxClassificationDisplay {
					remaining := total - cpt
					if remaining > 0 {
						rd.PrintRow("", fmt.Sprintf("... and %d more\n", remaining), keyStyle, valueStyle)
					}
					break
				}
			}
		}
		fmt.Fprintln(writer)
	}

	if len(item.GetClassifications()) > 0 {
		threatInfo = true
		cpt := 0
		total := len(item.Classifications.Classifications)
		rd.PrintRow("Classifications", "", keyStyle, valueStyle)
		for _, classification := range item.Classifications.Classifications {
			rd.PrintRow("", classification.Label, keyStyle, valueStyle.Foreground(lipgloss.Color("#60A5FA")))
			cpt++
			if !detailed {
				if cpt == maxClassificationDisplay {
					remaining := total - cpt
					if remaining > 0 {
						rd.PrintRow("", fmt.Sprintf("... and %d more\n", remaining), keyStyle, valueStyle)
					}
					break
				}
			}
		}
		fmt.Fprintln(writer)
	}

	if len(item.References) > 0 {
		threatInfo = true
		cpt := 0
		total := len(item.References)
		rd.PrintRow("Blocklists", "", keyStyle, valueStyle)
		for _, blocklist := range item.References {
			rd.PrintRow("", blocklist.Label, keyStyle, valueStyle.Foreground(lipgloss.Color("#60A5FA")))
			cpt++
			if !detailed {
				if cpt == maxBlocklistDisplay {
					remaining := total - cpt
					if remaining > 0 {
						rd.PrintRow("", fmt.Sprintf("... and %d more\n", remaining), keyStyle, valueStyle)
					}
					break
				}
			}
		}
		fmt.Fprintln(writer)
	}

	if len(item.CVEs) > 0 {
		threatInfo = true
		cpt := 0
		total := len(item.CVEs)
		rd.PrintRow("Exploiting CVEs", "", keyStyle, valueStyle)
		sort.Sort(sort.Reverse(sort.StringSlice(item.CVEs)))

		for _, cve := range item.CVEs {
			rd.PrintRow("", cve, keyStyle, valueStyle.Foreground(lipgloss.Color("#F55B60")))
			cpt++
			if !detailed {
				if cpt == maxCVEDisplay {
					remaining := total - cpt
					if remaining > 0 {
						rd.PrintRow("", fmt.Sprintf("... and %d more", remaining), keyStyle, valueStyle)
					}
					break
				}
			}
		}
		fmt.Fprintln(writer)
	}

	topWriter := tabwriter.NewWriter(os.Stdout, 0, 8, 10, '\t', tabwriter.AlignRight)
	topRD := NewRowDisplay(topWriter, 20)
	targetCountries := getTopN(item.TargetCountries, maxTopDisplayReport)
	if len(targetCountries) > 0 {
		threatInfo = true
		cpt := 0
		total := len(targetCountries)
		rd.PrintRow("Target countries", "", keyStyle, valueStyle)
		for _, c := range targetCountries {
			flag := CountryCodeToFlagEmoji(c.Key)
			key := fmt.Sprintf("\t %s %s", flag, TruncateWithEllipsis(c.Key, maxKeyLen))
			topRD.PrintRow(key, fmt.Sprintf("%d%%", c.Value), keyStyle, valueStyle)
			cpt++
			if !detailed {
				if cpt == maxTargetCountriesDisplay {
					remaining := total - cpt
					if remaining > 0 {
						rd.PrintRow("", fmt.Sprintf("... and %d more", remaining), keyStyle, valueStyle)
					}
					break
				}
			}
		}
		topWriter.Flush()
	}
	if !threatInfo {
		rd.PrintRow("No threat information found.", "", keyStyle, valueStyle)
	}

	fmt.Println()

	writer.Flush()
	return nil
}

func (d *Display) DisplayReport(item *models.Report, stats *models.ReportStats, format string, withIPs bool) error {
	switch format {
	case HumanFormat:
		if err := displayReport(item, stats, withIPs); err != nil {
			return err
		}
	case JSONFormat:
		if err := displayReportJSON(item, stats); err != nil {
			return err
		}
	default:
		return fmt.Errorf("format '%s' not supported", format)
	}
	return nil
}

func displayReportJSON(item *models.Report, stats *models.ReportStats) error {
	jsonData, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", jsonData)

	jsonData, err = json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", jsonData)

	return nil
}

func TruncateWithEllipsis(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return "..."
	}
	return s[:max-3] + "..."
}

func displayReport(report *models.Report, stats *models.ReportStats, withIPs bool) error {
	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("15"))

	valueStyle := lipgloss.NewStyle().Bold(true)
	writer := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', tabwriter.AlignRight)
	sectionStyle := pterm.NewStyle(pterm.FgWhite, pterm.Bold)
	rd := NewRowDisplay(writer, maxKeyLength)

	PrintSection(sectionStyle, "General")
	rd.PrintRow("Report ID", strconv.Itoa(int(report.ID)), keyStyle, valueStyle)
	rd.PrintRow("Report Name", report.Name, keyStyle, valueStyle)
	rd.PrintRow("Creation Date", report.CreatedAt.Format("2006-01-02 15:04:05"), keyStyle, valueStyle)
	if report.IsFile {
		rd.PrintRow("File path", report.FilePath, keyStyle, valueStyle)
		rd.PrintRow("SHA256", report.FileHash, keyStyle, valueStyle)
	}
	if report.IsQuery {
		rd.PrintRow("Query", report.Query, keyStyle, valueStyle)
		rd.PrintRow("Since Duration", report.Since, keyStyle, valueStyle)
		rd.PrintRow("Since Time", report.SinceTime.Format("2006-01-02 15:04:05"), keyStyle, valueStyle)
	}
	rd.PrintRow("Number of IPs", strconv.Itoa(len(report.IPs)), keyStyle, valueStyle)

	knownIPPercent := float64(stats.NbIPs-stats.NbUnknownIPs) / float64(stats.NbIPs) * 100
	rd.PrintRow("Number of known IPs", fmt.Sprintf("%d (%.0f%%)", stats.NbIPs-stats.NbUnknownIPs, knownIPPercent), keyStyle, GetPercentKnownColor(valueStyle, knownIPPercent))

	PrintSection(sectionStyle, "Stats")

	topWriter := tabwriter.NewWriter(os.Stdout, 0, 8, 10, '\t', tabwriter.AlignRight)
	topRD := NewRowDisplay(topWriter, 50)

	TopReputation := getTopN(stats.TopReputation, maxTopDisplayReport)
	if len(TopReputation) > 0 {
		rd.PrintRow("🌟 Top Reputation", "", keyStyle, valueStyle)
		for _, stat := range TopReputation {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			topRD.PrintRow(fmt.Sprintf("\t %s", cases.Title(language.Und).String((TruncateWithEllipsis(stat.Key, maxKeyLen)))), fmt.Sprintf("%d (%.0f%%)", stat.Value, percent), keyStyle, GetReputationStyle(valueStyle, stat.Key))
		}
		topWriter.Flush()
	}
	fmt.Println()
	// Top Classifications
	topClassification := getTopN(stats.TopClassifications, maxTopDisplayReport)
	if len(topClassification) > 0 {
		rd.PrintRow("🗂️ Top Classifications", "", keyStyle, valueStyle)
		for _, stat := range topClassification {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			topRD.PrintRow(fmt.Sprintf("\t %s", TruncateWithEllipsis(stat.Key, maxKeyLen)), fmt.Sprintf("%d (%.0f%%)", stat.Value, percent), keyStyle, valueStyle)
		}
		topWriter.Flush()
	}
	fmt.Println()

	// Top Behaviors
	topBehaviors := getTopN(stats.TopBehaviors, maxTopDisplayReport)
	if len(topBehaviors) > 0 {
		rd.PrintRow("🤖 Top Behaviors", "", keyStyle, valueStyle)
		for _, stat := range topBehaviors {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			topRD.PrintRow(fmt.Sprintf("\t %s", TruncateWithEllipsis(stat.Key, maxKeyLen)), fmt.Sprintf("%d (%.0f%%)", stat.Value, percent), keyStyle, valueStyle)
		}
		topWriter.Flush()
	}
	fmt.Println()

	topBlocklists := getTopN(stats.TopBlocklists, maxTopDisplayReport)
	if len(topBlocklists) > 0 {
		rd.PrintRow("⛔ Top Blocklists", "", keyStyle, valueStyle)
		for _, stat := range topBlocklists {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			topRD.PrintRow(fmt.Sprintf("\t %s", TruncateWithEllipsis(stat.Key, maxKeyLen)), fmt.Sprintf("%d (%.0f%%)", stat.Value, percent), keyStyle, valueStyle)
		}
		topWriter.Flush()
	}
	fmt.Println()

	topCVEs := getTopN(stats.TopCVEs, maxTopDisplayReport)
	if len(topCVEs) > 0 {
		rd.PrintRow("💥 Top CVEs", "", keyStyle, valueStyle)
		for _, stat := range topCVEs {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			topRD.PrintRow(fmt.Sprintf("\t %s", TruncateWithEllipsis(stat.Key, maxKeyLen)), fmt.Sprintf("%d (%.0f%%)", stat.Value, percent), keyStyle, valueStyle)
		}
		topWriter.Flush()
	}
	fmt.Println()

	// Top IP Ranges
	TopIPRange := getTopN(stats.TopIPRange, maxTopDisplayReport)
	if len(TopIPRange) > 0 {
		rd.PrintRow("🌐 Top IP Ranges", "", keyStyle, valueStyle)
		for _, stat := range TopIPRange {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			topRD.PrintRow(fmt.Sprintf("\t %s", TruncateWithEllipsis(stat.Key, maxKeyLen)), fmt.Sprintf("%d (%.0f%%)", stat.Value, percent), keyStyle, valueStyle)
		}
		topWriter.Flush()
	}
	fmt.Println()

	// Top Autonomous Systems
	topAS := getTopN(stats.TopAS, maxTopDisplayReport)
	if len(topAS) > 0 {
		rd.PrintRow("🛰️ Top Autonomous Systems", "", keyStyle, valueStyle)
		for _, stat := range topAS {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			topRD.PrintRow(fmt.Sprintf("\t %s", TruncateWithEllipsis(stat.Key, maxKeyLen)), fmt.Sprintf("%d (%.0f%%)", stat.Value, percent), keyStyle, valueStyle)
		}
		topWriter.Flush()
	}
	fmt.Println()

	// Top Countries
	topCountry := getTopN(stats.TopCountries, maxTopDisplayReport)
	if len(topCountry) > 0 {
		rd.PrintRow("🌎 Top Countries", "", keyStyle, valueStyle)
		for _, stat := range topCountry {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			topRD.PrintRow(fmt.Sprintf("\t %s %s", TruncateWithEllipsis(stat.Key, maxKeyLen), getFlag(stat.Key)), fmt.Sprintf("%d (%.0f%%)", stat.Value, percent), keyStyle, valueStyle)
		}
		topWriter.Flush()
	}
	fmt.Println()
	maxLineLength := 25
	if withIPs {
		var tableData [][]string
		tableData = append(tableData, []string{"IP", "Country", "AS Name", "Reputation", "Confidence", "Reverse DNS", "Profile", "Behaviors", "Range"})
		for _, item := range report.IPs {
			country := "N/A"
			ipRange := "N/A"
			asName := "N/A"
			reverseDNS := "N/A"
			if item.ReverseDNS != nil && *item.ReverseDNS != "" {
				reverseDNS = *item.ReverseDNS
				if len(reverseDNS) > maxLineLength {
					reverseDNS = "..." + reverseDNS[len(reverseDNS)-maxLineLength:]
				}
			}
			if item.Location.Country != nil && *item.Location.Country != "" {
				country = *item.Location.Country
			}
			if item.IpRange != nil && *item.IpRange != "" {
				ipRange = *item.IpRange
			}
			if item.IpRange != nil && *item.IpRange != "" {
				ipRange = *item.IpRange
			}
			if item.AsName != nil && *item.AsName != "" {
				asName = *item.AsName
				if len(asName) > maxLineLength {
					asName = asName[:maxLineLength] + "..."
				}
			}
			behaviors := ""
			for i, behavior := range item.Behaviors {
				if len(behaviors)+len(behavior.Label) > maxLineLength {
					behaviors += "..."
					break
				}

				// Append the label
				if behaviors != "" {
					behaviors += ", "
				}
				behaviors += behavior.Label

				if i+1 < len(item.Behaviors) && len(behaviors)+len(item.Behaviors[i+1].Label)+2 > maxLineLength {
					behaviors += "..."
					break
				}
			}
			classif := "N/A"
			if len(item.Classifications.Classifications) > 0 {
				for _, classification := range item.Classifications.Classifications {
					if len(item.Classifications.Classifications) > 1 && strings.ToLower(classification.Label) == "crowdSec community blocklist" {
						continue
					}
					classif = classification.Label
				}
			}
			if len(item.Classifications.FalsePositives) > 0 {
				for _, classification := range item.Classifications.FalsePositives {
					classif = classification.Label
				}
			}

			if item.Reputation == "" {
				tableData = append(tableData, []string{
					item.Ip,
					"N/A",
					"N/A",
					"N/A",
					"N/A",
					"N/A",
					"N/A",
					"N/A",
					"N/A",
					"N/A",
				})
				continue
			}
			reputationStyle := GetReputationStyle(valueStyle, item.Reputation)

			tableData = append(tableData, []string{
				item.Ip,
				getFlag(country) + " " + country,
				asName,
				reputationStyle.Render(item.Reputation),
				GetLevelStyle(valueStyle, item.Confidence).Render(item.Confidence),
				reverseDNS,
				classif,
				behaviors,
				ipRange,
			})
		}
		fmt.Println()
		if err := pterm.DefaultTable.WithHasHeader().WithData(tableData).Render(); err != nil {
			style.Fatal(err.Error())
		}
	}

	return nil
}
