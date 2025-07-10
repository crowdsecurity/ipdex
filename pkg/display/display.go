package display

import (
	"encoding/csv"
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
	CSVFormat                 = "csv"
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
	case CSVFormat:
		// For CSV format, display in human format on screen AND save CSV file
		if err := displayIP(item, ipLastRefresh, detailed); err != nil {
			return err
		}
		if err := saveIPCSV(item, ipLastRefresh); err != nil {
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
	case CSVFormat:
		// For CSV format, display in human format on screen AND save CSV files
		if err := displayReport(item, stats, withIPs); err != nil {
			return err
		}
		if err := saveReportCSV(item, stats, withIPs); err != nil {
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
	ipsInBlocklistPercent := float64(stats.IPsBlockedByBlocklist) / float64(stats.NbIPs) * 100
	rd.PrintRow("Number of known IPs", fmt.Sprintf("%d (%.0f%%)", stats.NbIPs-stats.NbUnknownIPs, knownIPPercent), keyStyle, GetPercentKnownColor(valueStyle, knownIPPercent))
	rd.PrintRow("Number of IPs in Blocklist", fmt.Sprintf("%d (%.0f%%)", stats.IPsBlockedByBlocklist, ipsInBlocklistPercent), keyStyle, GetPercentKnownColor(valueStyle, knownIPPercent))
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

func saveReportCSV(item *models.Report, stats *models.ReportStats, withIPs bool) error {
	// Always save the report summary
	reportFilename := fmt.Sprintf("report.%d.csv", item.ID)
	reportFile, err := os.Create(reportFilename)
	if err != nil {
		return fmt.Errorf("failed to create report CSV file %s: %v", reportFilename, err)
	}
	defer reportFile.Close()

	reportWriter := csv.NewWriter(reportFile)
	defer reportWriter.Flush()

	// Collect all CSV rows
	var csvRows [][]string

	// General section
	csvRows = append(csvRows, []string{"General", "", ""})
	csvRows = append(csvRows, []string{"", "", ""})
	csvRows = append(csvRows, []string{"Report ID", strconv.Itoa(int(item.ID)), ""})
	csvRows = append(csvRows, []string{"Report Name", item.Name, ""})
	csvRows = append(csvRows, []string{"Creation Date", item.CreatedAt.Format("2006-01-02 15:04:05"), ""})

	if item.IsFile {
		csvRows = append(csvRows, []string{"File path", item.FilePath, ""})
		csvRows = append(csvRows, []string{"SHA256", item.FileHash, ""})
	}

	if item.IsQuery {
		csvRows = append(csvRows, []string{"Query", item.Query, ""})
		csvRows = append(csvRows, []string{"Since Duration", item.Since, ""})
		csvRows = append(csvRows, []string{"Since Time", item.SinceTime.Format("2006-01-02 15:04:05"), ""})
	}

	csvRows = append(csvRows, []string{"Number of IPs", strconv.Itoa(len(item.IPs)), ""})

	knownIPPercent := float64(stats.NbIPs-stats.NbUnknownIPs) / float64(stats.NbIPs) * 100
	ipsInBlocklistPercent := float64(stats.IPsBlockedByBlocklist) / float64(stats.NbIPs) * 100

	csvRows = append(csvRows, []string{"Number of known IPs", fmt.Sprintf("%d", stats.NbIPs-stats.NbUnknownIPs), fmt.Sprintf("%.0f%%", knownIPPercent)})
	csvRows = append(csvRows, []string{"Number of IPs in Blocklist", fmt.Sprintf("%d", stats.IPsBlockedByBlocklist), fmt.Sprintf("%.0f%%", ipsInBlocklistPercent)})

	// Empty line before Stats section
	csvRows = append(csvRows, []string{"", "", ""})

	// Stats section
	csvRows = append(csvRows, []string{"Stats", "", ""})
	csvRows = append(csvRows, []string{"", "", ""})

	// Top Reputation
	TopReputation := getTopN(stats.TopReputation, maxTopDisplayReport)
	if len(TopReputation) > 0 {
		csvRows = append(csvRows, []string{"🌟 Top Reputation", "", ""})
		for _, stat := range TopReputation {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			csvRows = append(csvRows, []string{cases.Title(language.Und).String(stat.Key), fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		csvRows = append(csvRows, []string{"", "", ""})
	}

	// Top Classifications
	topClassification := getTopN(stats.TopClassifications, maxTopDisplayReport)
	if len(topClassification) > 0 {
		csvRows = append(csvRows, []string{"🗂️ Top Classifications", "", ""})
		for _, stat := range topClassification {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			csvRows = append(csvRows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		csvRows = append(csvRows, []string{"", "", ""})
	}

	// Top Behaviors
	topBehaviors := getTopN(stats.TopBehaviors, maxTopDisplayReport)
	if len(topBehaviors) > 0 {
		csvRows = append(csvRows, []string{"🤖 Top Behaviors", "", ""})
		for _, stat := range topBehaviors {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			csvRows = append(csvRows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		csvRows = append(csvRows, []string{"", "", ""})
	}

	// Top Blocklists
	topBlocklists := getTopN(stats.TopBlocklists, maxTopDisplayReport)
	if len(topBlocklists) > 0 {
		csvRows = append(csvRows, []string{"⛔ Top Blocklists", "", ""})
		for _, stat := range topBlocklists {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			csvRows = append(csvRows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		csvRows = append(csvRows, []string{"", "", ""})
	}

	// Top CVEs
	topCVEs := getTopN(stats.TopCVEs, maxTopDisplayReport)
	if len(topCVEs) > 0 {
		csvRows = append(csvRows, []string{"💥 Top CVEs", "", ""})
		for _, stat := range topCVEs {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			csvRows = append(csvRows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		csvRows = append(csvRows, []string{"", "", ""})
	}

	// Top IP Ranges
	TopIPRange := getTopN(stats.TopIPRange, maxTopDisplayReport)
	if len(TopIPRange) > 0 {
		csvRows = append(csvRows, []string{"🌐 Top IP Ranges", "", ""})
		for _, stat := range TopIPRange {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			csvRows = append(csvRows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		csvRows = append(csvRows, []string{"", "", ""})
	}

	// Top Autonomous Systems
	topAS := getTopN(stats.TopAS, maxTopDisplayReport)
	if len(topAS) > 0 {
		csvRows = append(csvRows, []string{"🛰️ Top Autonomous Systems", "", ""})
		for _, stat := range topAS {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			csvRows = append(csvRows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		csvRows = append(csvRows, []string{"", "", ""})
	}

	// Top Countries
	topCountry := getTopN(stats.TopCountries, maxTopDisplayReport)
	if len(topCountry) > 0 {
		csvRows = append(csvRows, []string{"🌎 Top Countries", "", ""})
		for _, stat := range topCountry {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			csvRows = append(csvRows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		csvRows = append(csvRows, []string{"", "", ""})
	}

	// Write all rows at once
	for _, row := range csvRows {
		if err := reportWriter.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %v", err)
		}
	}

	fmt.Printf("Report summary saved to: %s\n", reportFilename)

	// If detailed IP information is requested, save to a separate file
	if withIPs {
		detailsFilename := fmt.Sprintf("details.%d.csv", item.ID)
		detailsFile, err := os.Create(detailsFilename)
		if err != nil {
			return fmt.Errorf("failed to create details CSV file %s: %v", detailsFilename, err)
		}
		defer detailsFile.Close()

		detailsWriter := csv.NewWriter(detailsFile)
		defer detailsWriter.Flush()

		// Collect all IP detail rows
		var detailRows [][]string

		// Header
		detailRows = append(detailRows, []string{
			"IP", "Country", "AS Name", "Reputation", "Confidence",
			"Reverse DNS", "Profile", "Behaviors", "Range", "First Seen", "Last Seen",
		})

		// IP data
		for _, ipItem := range item.IPs {
			country := "N/A"
			ipRange := "N/A"
			asName := "N/A"
			reverseDNS := "N/A"

			if ipItem.ReverseDNS != nil && *ipItem.ReverseDNS != "" {
				reverseDNS = *ipItem.ReverseDNS
			}
			if ipItem.Location.Country != nil && *ipItem.Location.Country != "" {
				country = *ipItem.Location.Country
			}
			if ipItem.IpRange != nil && *ipItem.IpRange != "" {
				ipRange = *ipItem.IpRange
			}
			if ipItem.AsName != nil && *ipItem.AsName != "" {
				asName = *ipItem.AsName
			}

			behaviors := ""
			for i, behavior := range ipItem.Behaviors {
				if i > 0 {
					behaviors += ", "
				}
				behaviors += behavior.Label
			}
			if behaviors == "" {
				behaviors = "N/A"
			}

			classif := "N/A"
			if len(ipItem.Classifications.Classifications) > 0 {
				for _, classification := range ipItem.Classifications.Classifications {
					if len(ipItem.Classifications.Classifications) > 1 && strings.ToLower(classification.Label) == "crowdsec community blocklist" {
						continue
					}
					classif = classification.Label
				}
			}
			if len(ipItem.Classifications.FalsePositives) > 0 {
				for _, classification := range ipItem.Classifications.FalsePositives {
					classif = classification.Label
				}
			}

			firstSeen := "N/A"
			lastSeen := "N/A"
			if ipItem.History.FirstSeen != nil && *ipItem.History.FirstSeen != "" {
				firstSeen = strings.Split(*ipItem.History.FirstSeen, "+")[0]
			}
			if ipItem.History.LastSeen != nil && *ipItem.History.LastSeen != "" {
				lastSeen = strings.Split(*ipItem.History.LastSeen, "+")[0]
			}

			reputation := ipItem.Reputation
			confidence := ipItem.Confidence
			if reputation == "" {
				reputation = "N/A"
				confidence = "N/A"
			}

			detailRows = append(detailRows, []string{
				ipItem.Ip, country, asName, reputation, confidence,
				reverseDNS, classif, behaviors, ipRange, firstSeen, lastSeen,
			})
		}

		// Write all detail rows at once
		for _, row := range detailRows {
			if err := detailsWriter.Write(row); err != nil {
				return fmt.Errorf("failed to write detail CSV row: %v", err)
			}
		}

		fmt.Printf("IP details saved to: %s\n", detailsFilename)
	}

	return nil
}

func saveIPCSV(item *cticlient.SmokeItem, ipLastRefresh time.Time) error {
	filename := fmt.Sprintf("ip.%s.csv", item.Ip)
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create IP CSV file %s: %v", filename, err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write the header
	if err := writer.Write([]string{
		"IP",
		"Reputation",
		"Confidence",
		"Country",
		"Autonomous System",
		"Reverse DNS",
		"Range",
		"First Seen",
		"Last Seen",
		"Console URL",
		"Last Local Refresh",
		"Behaviors",
		"False Positives",
		"Classifications",
		"Blocklists",
		"CVEs",
	}); err != nil {
		return err
	}

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

	reputationStr := item.Reputation
	if item.Reputation == "safe" {
		fps := ""
		for i, fp := range item.Classifications.FalsePositives {
			if i > 0 {
				fps += ", "
			}
			fps += fp.Label
		}
		if fps != "" {
			reputationStr += fmt.Sprintf(" (%s)", fps)
		}
	}

	firstSeen := "N/A"
	lastSeen := "N/A"
	if item.History.FirstSeen != nil && *item.History.FirstSeen != "" {
		firstSeen = strings.Split(*item.History.FirstSeen, "+")[0]
	}
	if item.History.LastSeen != nil && *item.History.LastSeen != "" {
		lastSeen = strings.Split(*item.History.LastSeen, "+")[0]
	}

	// Collect behaviors
	behaviors := ""
	for i, behavior := range item.Behaviors {
		if i > 0 {
			behaviors += ", "
		}
		behaviors += behavior.Label
	}
	if behaviors == "" {
		behaviors = "N/A"
	}

	// Collect false positives
	falsePositives := ""
	for i, fp := range item.Classifications.FalsePositives {
		if i > 0 {
			falsePositives += ", "
		}
		falsePositives += fp.Label
	}
	if falsePositives == "" {
		falsePositives = "N/A"
	}

	// Collect classifications
	classifications := ""
	for i, classification := range item.Classifications.Classifications {
		if i > 0 {
			classifications += ", "
		}
		classifications += classification.Label
	}
	if classifications == "" {
		classifications = "N/A"
	}

	// Collect blocklists
	blocklists := ""
	for i, blocklist := range item.References {
		if i > 0 {
			blocklists += ", "
		}
		blocklists += blocklist.Label
	}
	if blocklists == "" {
		blocklists = "N/A"
	}

	// Collect CVEs
	cves := ""
	for i, cve := range item.CVEs {
		if i > 0 {
			cves += ", "
		}
		cves += cve
	}
	if cves == "" {
		cves = "N/A"
	}

	// Write the data
	if err := writer.Write([]string{
		item.Ip,
		reputationStr,
		item.Confidence,
		country,
		asName,
		reverseDNS,
		ipRange,
		firstSeen,
		lastSeen,
		fmt.Sprintf("https://app.crowdsec.net/cti/%s", item.Ip),
		ipLastRefresh.Format("2006-01-02 15:04:05"),
		behaviors,
		falsePositives,
		classifications,
		blocklists,
		cves,
	}); err != nil {
		return err
	}

	fmt.Printf("IP details saved to: %s\n", filename)
	return nil
}
