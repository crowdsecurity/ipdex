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

/// Top level display strategy functions

func (d *Display) DisplayIP(item *cticlient.SmokeItem, ipLastRefresh time.Time, format string, detailed bool) error {
	switch format {
	case HumanFormat:
		if err := displayIPHuman(item, ipLastRefresh, detailed); err != nil {
			return err
		}
	case JSONFormat:
		if err := displayIPJSON(item); err != nil {
			return err
		}
	case CSVFormat:
		if err := displayIPCSV(item, ipLastRefresh); err != nil {
			return err
		}
	default:
		return fmt.Errorf("format '%s' not supported", format)
	}
	return nil
}

func (d *Display) DisplayReport(report *models.Report, stats *models.ReportStats, format string, withIPs bool, outputFilePath string) error {
	switch format {
	case HumanFormat:
		humanFormattedData := buildHumanReportData(report, stats, withIPs)
		if err := displayReportHuman(humanFormattedData); err != nil {
			return err
		}
		if outputFilePath != "" {
			if err := saveReportHuman(humanFormattedData, int(report.ID), outputFilePath); err != nil {
				return err
			}
		}
	case JSONFormat:
		if err := displayReportJSON(report, stats); err != nil {
			return err
		}
		if outputFilePath != "" {
			if err := saveReportJSON(report, stats, withIPs, outputFilePath); err != nil {
				return err
			}
		}
	case CSVFormat:
		csvReportRows := buildCSVReportRows(report, stats, withIPs, false)
		csvDetailRows := [][]string{}
		if err := displayCSVRows(csvReportRows); err != nil {
			return err
		}

		if withIPs {
			csvDetailRows = buildCSVDetailsRows(report)
			if err := displayCSVRows(csvDetailRows); err != nil {
				return err
			}
		}

		if outputFilePath != "" {
			if err := saveReportCSV(csvReportRows, csvDetailRows, int(report.ID), outputFilePath); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("format '%s' not supported", format)
	}

	return nil
}

/// IP display functions

func displayIPHuman(item *cticlient.SmokeItem, ipLastRefresh time.Time, detailed bool) error {
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

func displayIPJSON(item *cticlient.SmokeItem) error {
	jsonData, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", jsonData)
	return nil
}

func displayIPCSV(item *cticlient.SmokeItem, ipLastRefresh time.Time) error {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	// Build reputation with false positives if applicable
	reputation := item.Reputation
	if reputation == "safe" && len(item.Classifications.FalsePositives) > 0 {
		reputation = fmt.Sprintf("%s (%s)", reputation, Format(item.Classifications.FalsePositives, FormatCSV))
	}

	// Extract timestamps
	history := Format(item.History, FormatCSV)
	timestamps := strings.Split(history, ",")
	firstSeen, lastSeen := timestamps[0], timestamps[1]

	// Define fields in order with header and data
	type field struct {
		header string
		value  string
	}

	fieldsToDisplay := []field{
		{"IP", item.Ip},
		{"Reputation", reputation},
		{"Confidence", item.Confidence},
		{"Country", Format(item.Location, FormatCSV)},
		{"Autonomous System", Format(item.AsName, FormatCSV)},
		{"Reverse DNS", Format(item.ReverseDNS, FormatCSV)},
		{"Range", Format(item.IpRange, FormatCSV)},
		{"First Seen", firstSeen},
		{"Last Seen", lastSeen},
		{"Console URL", fmt.Sprintf("https://app.crowdsec.net/cti/%s", item.Ip)},
		{"Last Local Refresh", ipLastRefresh.Format("2006-01-02 15:04:05")},
		{"Behaviors", Format(item.Behaviors, FormatCSV)},
		{"False Positives", Format(item.Classifications.FalsePositives, FormatCSV)},
		{"Classifications", Format(item.Classifications.Classifications, FormatCSV)},
		{"Blocklists", Format(item.References, FormatCSV)},
		{"CVEs", Format(item.CVEs, FormatCSV)},
	}

	// Extract headers and values from fieldsToDisplay
	var headers, values []string
	for _, f := range fieldsToDisplay {
		headers = append(headers, f.header)
		values = append(values, f.value)
	}

	// Write headers
	if err := w.Write(headers); err != nil {
		return err
	}

	// Write data row
	return w.Write(values)
}

/// Report display functions

// // HumanReportData holds structured report data for formatting
type HumanReportData struct {
	General               []KeyValue
	TopSections           []TopSection
	IPTableData           [][]string
	Stats                 *models.ReportStats
	KnownIPPercent        float64
	IPsInBlocklistPercent float64
}

type KeyValue struct {
	Key   string
	Value string
}

type TopSection struct {
	Title string
	Emoji string
	Items []TopItem
}

type TopItem struct {
	Key     string
	Value   int
	Percent float64
}

// buildHumanReportData extracts report data into a structured format (used by both display and save)
func buildHumanReportData(report *models.Report, stats *models.ReportStats, withIPs bool) *HumanReportData {
	data := &HumanReportData{
		Stats: stats,
	}

	// General section
	data.General = []KeyValue{
		{"Report ID", strconv.Itoa(int(report.ID))},
		{"Report Name", report.Name},
		{"Creation Date", report.CreatedAt.Format("2006-01-02 15:04:05")},
	}

	if report.IsFile {
		data.General = append(data.General,
			KeyValue{"File path", report.FilePath},
			KeyValue{"SHA256", report.FileHash},
		)
	}

	if report.IsQuery {
		data.General = append(data.General,
			KeyValue{"Query", report.Query},
			KeyValue{"Since Duration", report.Since},
			KeyValue{"Since Time", report.SinceTime.Format("2006-01-02 15:04:05")},
		)
	}

	data.General = append(data.General, KeyValue{"Number of IPs", strconv.Itoa(len(report.IPs))})

	data.KnownIPPercent = float64(stats.NbIPs-stats.NbUnknownIPs) / float64(stats.NbIPs) * 100
	data.IPsInBlocklistPercent = float64(stats.IPsBlockedByBlocklist) / float64(stats.NbIPs) * 100

	data.General = append(data.General,
		KeyValue{"Number of known IPs", fmt.Sprintf("%d (%.0f%%)", stats.NbIPs-stats.NbUnknownIPs, data.KnownIPPercent)},
		KeyValue{"Number of IPs in Blocklist", fmt.Sprintf("%d (%.0f%%)", stats.IPsBlockedByBlocklist, data.IPsInBlocklistPercent)},
	)

	// Build top sections
	buildSection := func(title, emoji string, topStats []KV) *TopSection {
		if len(topStats) == 0 {
			return nil
		}
		section := &TopSection{Title: title, Emoji: emoji}
		for _, stat := range topStats {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			section.Items = append(section.Items, TopItem{
				Key:     stat.Key,
				Value:   stat.Value,
				Percent: percent,
			})
		}
		return section
	}

	sections := []*TopSection{
		buildSection("Top Reputation", "🌟", getTopN(stats.TopReputation, maxTopDisplayReport)),
		buildSection("Top Classifications", "🗂️", getTopN(stats.TopClassifications, maxTopDisplayReport)),
		buildSection("Top Behaviors", "🤖", getTopN(stats.TopBehaviors, maxTopDisplayReport)),
		buildSection("Top Blocklists", "⛔", getTopN(stats.TopBlocklists, maxTopDisplayReport)),
		buildSection("Top CVEs", "💥", getTopN(stats.TopCVEs, maxTopDisplayReport)),
		buildSection("Top IP Ranges", "🌐", getTopN(stats.TopIPRange, maxTopDisplayReport)),
		buildSection("Top Autonomous Systems", "🛰️", getTopN(stats.TopAS, maxTopDisplayReport)),
		buildSection("Top Countries", "🌎", getTopN(stats.TopCountries, maxTopDisplayReport)),
	}

	for _, section := range sections {
		if section != nil {
			data.TopSections = append(data.TopSections, *section)
		}
	}

	// Build IP table data if requested
	if withIPs {
		maxLineLength := 25
		data.IPTableData = [][]string{{"IP", "Country", "AS Name", "Reputation", "Confidence", "Reverse DNS", "Profile", "Behaviors", "Range"}}

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
					if len(item.Classifications.Classifications) > 1 && strings.ToLower(classification.Label) == "crowdsec community blocklist" {
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
				data.IPTableData = append(data.IPTableData, []string{
					item.Ip, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A",
				})
				continue
			}

			data.IPTableData = append(data.IPTableData, []string{
				item.Ip,
				country,
				asName,
				item.Reputation,
				item.Confidence,
				reverseDNS,
				classif,
				behaviors,
				ipRange,
			})
		}
	}

	return data
}

func displayReportHuman(data *HumanReportData) error {
	keyStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
	valueStyle := lipgloss.NewStyle().Bold(true)
	writer := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', tabwriter.AlignRight)
	sectionStyle := pterm.NewStyle(pterm.FgWhite, pterm.Bold)
	rd := NewRowDisplay(writer, maxKeyLength)

	// Display General section
	PrintSection(sectionStyle, "General")
	for i, kv := range data.General {
		// Apply special styling for known IPs percentages
		if i == len(data.General)-2 {
			rd.PrintRow(kv.Key, kv.Value, keyStyle, GetPercentKnownColor(valueStyle, data.KnownIPPercent))
		} else if i == len(data.General)-1 {
			rd.PrintRow(kv.Key, kv.Value, keyStyle, GetPercentKnownColor(valueStyle, data.KnownIPPercent))
		} else {
			rd.PrintRow(kv.Key, kv.Value, keyStyle, valueStyle)
		}
	}

	PrintSection(sectionStyle, "Stats")

	topWriter := tabwriter.NewWriter(os.Stdout, 0, 8, 10, '\t', tabwriter.AlignRight)
	topRD := NewRowDisplay(topWriter, 50)

	// Display top sections
	for _, section := range data.TopSections {
		rd.PrintRow(section.Emoji+" "+section.Title, "", keyStyle, valueStyle)
		for _, item := range section.Items {
			displayKey := fmt.Sprintf("\t %s", TruncateWithEllipsis(item.Key, maxKeyLen))
			displayValue := fmt.Sprintf("%d (%.0f%%)", item.Value, item.Percent)

			// Apply special styling for reputation
			if section.Title == "Top Reputation" {
				displayKey = fmt.Sprintf("\t %s", cases.Title(language.Und).String(TruncateWithEllipsis(item.Key, maxKeyLen)))
				topRD.PrintRow(displayKey, displayValue, keyStyle, GetReputationStyle(valueStyle, item.Key))
			} else if section.Title == "Top Countries" {
				displayKey = fmt.Sprintf("\t %s %s", TruncateWithEllipsis(item.Key, maxKeyLen), getFlag(item.Key))
				topRD.PrintRow(displayKey, displayValue, keyStyle, valueStyle)
			} else {
				topRD.PrintRow(displayKey, displayValue, keyStyle, valueStyle)
			}
		}
		topWriter.Flush()
		fmt.Println()
	}

	// Display IP table if available
	if len(data.IPTableData) > 1 {
		// Apply styling to the table data
		var styledTableData [][]string
		styledTableData = append(styledTableData, data.IPTableData[0]) // Header

		for i := 1; i < len(data.IPTableData); i++ {
			row := data.IPTableData[i]
			if len(row) < 9 {
				styledTableData = append(styledTableData, row)
				continue
			}

			country := row[1]
			reputation := row[3]
			confidence := row[4]

			styledRow := []string{
				row[0], // IP
				getFlag(country) + " " + country,
				row[2], // AS Name
				GetReputationStyle(valueStyle, reputation).Render(reputation),
				GetLevelStyle(valueStyle, confidence).Render(confidence),
				row[5], // Reverse DNS
				row[6], // Profile
				row[7], // Behaviors
				row[8], // Range
			}
			styledTableData = append(styledTableData, styledRow)
		}

		if err := pterm.DefaultTable.WithHasHeader().WithData(styledTableData).Render(); err != nil {
			style.Fatal(err.Error())
		}
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

func buildCSVReportRows(report *models.Report, stats *models.ReportStats, withIPs bool, includeEmojis bool) [][]string {
	var rows [][]string

	// General section
	rows = append(rows, []string{"General", "", ""})
	rows = append(rows, []string{"", "", ""})
	rows = append(rows, []string{"Report ID", strconv.Itoa(int(report.ID)), ""})
	rows = append(rows, []string{"Report Name", report.Name, ""})
	rows = append(rows, []string{"Creation Date", report.CreatedAt.Format("2006-01-02 15:04:05"), ""})

	if report.IsFile {
		rows = append(rows, []string{"File path", report.FilePath, ""})
		rows = append(rows, []string{"SHA256", report.FileHash, ""})
	}

	if report.IsQuery {
		rows = append(rows, []string{"Query", report.Query, ""})
		rows = append(rows, []string{"Since Duration", report.Since, ""})
		rows = append(rows, []string{"Since Time", report.SinceTime.Format("2006-01-02 15:04:05"), ""})
	}

	rows = append(rows, []string{"Number of IPs", strconv.Itoa(len(report.IPs)), ""})

	knownIPPercent := float64(stats.NbIPs-stats.NbUnknownIPs) / float64(stats.NbIPs) * 100
	ipsInBlocklistPercent := float64(stats.IPsBlockedByBlocklist) / float64(stats.NbIPs) * 100

	rows = append(rows, []string{"Number of known IPs", fmt.Sprintf("%d", stats.NbIPs-stats.NbUnknownIPs), fmt.Sprintf("%.0f%%", knownIPPercent)})
	rows = append(rows, []string{"Number of IPs in Blocklist", fmt.Sprintf("%d", stats.IPsBlockedByBlocklist), fmt.Sprintf("%.0f%%", ipsInBlocklistPercent)})

	// Empty line before Stats section
	rows = append(rows, []string{"", "", ""})

	// Stats section
	rows = append(rows, []string{"Stats", "", ""})
	rows = append(rows, []string{"", "", ""})

	// Helper function to format section titles with optional emojis
	sectionTitle := func(emoji, title string) string {
		if includeEmojis {
			return emoji + " " + title
		}
		return title
	}

	// Top Reputation
	TopReputation := getTopN(stats.TopReputation, maxTopDisplayReport)
	if len(TopReputation) > 0 {
		rows = append(rows, []string{sectionTitle("🌟", "Top Reputation"), "", ""})
		for _, stat := range TopReputation {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			rows = append(rows, []string{cases.Title(language.Und).String(stat.Key), fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		rows = append(rows, []string{"", "", ""})
	}

	// Top Classifications
	topClassification := getTopN(stats.TopClassifications, maxTopDisplayReport)
	if len(topClassification) > 0 {
		rows = append(rows, []string{sectionTitle("🗂️", "Top Classifications"), "", ""})
		for _, stat := range topClassification {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			rows = append(rows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		rows = append(rows, []string{"", "", ""})
	}

	// Top Behaviors
	topBehaviors := getTopN(stats.TopBehaviors, maxTopDisplayReport)
	if len(topBehaviors) > 0 {
		rows = append(rows, []string{sectionTitle("🤖", "Top Behaviors"), "", ""})
		for _, stat := range topBehaviors {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			rows = append(rows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		rows = append(rows, []string{"", "", ""})
	}

	// Top Blocklists
	topBlocklists := getTopN(stats.TopBlocklists, maxTopDisplayReport)
	if len(topBlocklists) > 0 {
		rows = append(rows, []string{sectionTitle("⛔", "Top Blocklists"), "", ""})
		for _, stat := range topBlocklists {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			rows = append(rows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		rows = append(rows, []string{"", "", ""})
	}

	// Top CVEs
	topCVEs := getTopN(stats.TopCVEs, maxTopDisplayReport)
	if len(topCVEs) > 0 {
		rows = append(rows, []string{sectionTitle("💥", "Top CVEs"), "", ""})
		for _, stat := range topCVEs {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			rows = append(rows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		rows = append(rows, []string{"", "", ""})
	}

	// Top IP Ranges
	TopIPRange := getTopN(stats.TopIPRange, maxTopDisplayReport)
	if len(TopIPRange) > 0 {
		rows = append(rows, []string{sectionTitle("🌐", "Top IP Ranges"), "", ""})
		for _, stat := range TopIPRange {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			rows = append(rows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		rows = append(rows, []string{"", "", ""})
	}

	// Top Autonomous Systems
	topAS := getTopN(stats.TopAS, maxTopDisplayReport)
	if len(topAS) > 0 {
		rows = append(rows, []string{sectionTitle("🛰️", "Top Autonomous Systems"), "", ""})
		for _, stat := range topAS {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			rows = append(rows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		rows = append(rows, []string{"", "", ""})
	}

	// Top Countries
	topCountry := getTopN(stats.TopCountries, maxTopDisplayReport)
	if len(topCountry) > 0 {
		rows = append(rows, []string{sectionTitle("🌎", "Top Countries"), "", ""})
		for _, stat := range topCountry {
			percent := float64(stat.Value) / float64(stats.NbIPs) * 100
			rows = append(rows, []string{stat.Key, fmt.Sprintf("%d", stat.Value), fmt.Sprintf("%.0f%%", percent)})
		}
		rows = append(rows, []string{"", "", ""})
	}

	return rows
}

func buildCSVDetailsRows(report *models.Report) [][]string {
	var rows [][]string

	//Header row
	rows = append(rows, []string{
		"IP", "Country", "AS Name", "Reputation", "Confidence",
		"Reverse DNS", "Profile", "Behaviors", "Range", "First Seen", "Last Seen",
	})

	for _, ipItem := range report.IPs {
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

		rows = append(rows, []string{
			ipItem.Ip, country, asName, reputation, confidence,
			reverseDNS, classif, behaviors, ipRange, firstSeen, lastSeen,
		})
	}

	return rows
}

func displayCSVRows(rows [][]string) error {
	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func saveReportHuman(data *HumanReportData, reportID int, outputFilePath string) error {
	// Save the report summary
	reportFilename := fmt.Sprintf("%s/report-%d.txt", outputFilePath, reportID)
	reportFile, err := os.Create(reportFilename)
	if err != nil {
		return fmt.Errorf("failed to create report text file %s: %v", reportFilename, err)
	}
	defer reportFile.Close()

	writer := tabwriter.NewWriter(reportFile, 0, 8, 1, '\t', tabwriter.AlignRight)

	// General section
	fmt.Fprintln(writer, "═══════════════════════════════════════════════════════════════")
	fmt.Fprintln(writer, "General")
	fmt.Fprintln(writer, "═══════════════════════════════════════════════════════════════")
	for _, kv := range data.General {
		fmt.Fprintf(writer, "%s:\t%s\n", kv.Key, kv.Value)
	}

	// Stats section
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "═══════════════════════════════════════════════════════════════")
	fmt.Fprintln(writer, "Stats")
	fmt.Fprintln(writer, "═══════════════════════════════════════════════════════════════")

	// Display top sections
	for _, section := range data.TopSections {
		fmt.Fprintf(writer, "%s:\n", section.Title)
		for _, item := range section.Items {
			displayKey := item.Key
			if section.Title == "Top Reputation" {
				displayKey = cases.Title(language.Und).String(item.Key)
			}
			fmt.Fprintf(writer, "  %s:\t%d (%.0f%%)\n", displayKey, item.Value, item.Percent)
		}
		fmt.Fprintln(writer, "")
	}

	writer.Flush()
	fmt.Printf("Report summary saved to: %s\n", reportFilename)

	// If detailed IP information is requested, save to a separate file
	if len(data.IPTableData) > 1 {
		detailsFilename := fmt.Sprintf("%s/details-%d.txt", outputFilePath, reportID)
		detailsFile, err := os.Create(detailsFilename)
		if err != nil {
			return fmt.Errorf("failed to create details text file %s: %v", detailsFilename, err)
		}
		defer detailsFile.Close()

		detailsWriter := tabwriter.NewWriter(detailsFile, 0, 8, 2, ' ', 0)

		// Header
		fmt.Fprintln(detailsWriter, "IP\tCountry\tAS Name\tReputation\tConfidence\tReverse DNS\tProfile\tBehaviors\tRange")
		fmt.Fprintln(detailsWriter, "─────────────────\t──────────\t─────────────────────────\t──────────\t──────────\t─────────────────────────\t─────────────────────────\t─────────────────────────\t─────────────────")

		// Write IP data rows (skip header row)
		for i := 1; i < len(data.IPTableData); i++ {
			row := data.IPTableData[i]
			fmt.Fprintf(detailsWriter, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8],
			)
		}

		detailsWriter.Flush()
		fmt.Printf("IP details saved to: %s\n", detailsFilename)
	}

	return nil
}

func saveReportJSON(report *models.Report, stats *models.ReportStats, withIPs bool, outputFilePath string) error {
	// Save the report summary
	reportFilename := fmt.Sprintf("%s/report-%d.json", outputFilePath, report.ID)
	reportFile, err := os.Create(reportFilename)
	if err != nil {
		return fmt.Errorf("failed to create report JSON file %s: %v", reportFilename, err)
	}
	defer reportFile.Close()

	// Create a combined structure with report and stats
	type ReportOutput struct {
		Report *models.Report      `json:"report"`
		Stats  *models.ReportStats `json:"stats"`
	}

	output := ReportOutput{
		Report: report,
		Stats:  stats,
	}

	encoder := json.NewEncoder(reportFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to write JSON: %v", err)
	}

	fmt.Printf("Report summary saved to: %s\n", reportFilename)

	// If detailed IP information is requested, save to a separate file
	if withIPs {
		detailsFilename := fmt.Sprintf("%s/details-%d.json", outputFilePath, report.ID)
		detailsFile, err := os.Create(detailsFilename)
		if err != nil {
			return fmt.Errorf("failed to create details JSON file %s: %v", detailsFilename, err)
		}
		defer detailsFile.Close()

		encoder := json.NewEncoder(detailsFile)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report.IPs); err != nil {
			return fmt.Errorf("failed to write detail JSON: %v", err)
		}

		fmt.Printf("IP details saved to: %s\n", detailsFilename)
	}

	return nil
}

func saveReportCSV(csvReportRows [][]string, csvDetailRows [][]string, reportID int, outputFilePath string) error {
	// Always save the report summary
	reportFilename := fmt.Sprintf("%s/report-%d.csv", outputFilePath, reportID)
	reportFile, err := os.Create(reportFilename)
	if err != nil {
		return fmt.Errorf("failed to create report CSV file %s: %v", reportFilename, err)
	}
	defer reportFile.Close()

	reportWriter := csv.NewWriter(reportFile)
	defer reportWriter.Flush()

	// Write all rows
	for _, row := range csvReportRows {
		if err := reportWriter.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %v", err)
		}
	}

	fmt.Printf("Report summary saved to: %s\n", reportFilename)

	if len(csvDetailRows) > 1 {
		detailsFilename := fmt.Sprintf("%s/details-%d.csv", outputFilePath, reportID)
		detailsFile, err := os.Create(detailsFilename)
		if err != nil {
			return fmt.Errorf("failed to create details CSV file %s: %v", detailsFilename, err)
		}
		defer detailsFile.Close()

		detailsWriter := csv.NewWriter(detailsFile)
		defer detailsWriter.Flush()

		// Write all detail rows
		for _, row := range csvDetailRows {
			if err := detailsWriter.Write(row); err != nil {
				return fmt.Errorf("failed to write detail CSV row: %v", err)
			}
		}
		fmt.Printf("IP details included in: %s\n", detailsFilename)
	}

	return nil
}

//// Utility functions

func TruncateWithEllipsis(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return "..."
	}
	return s[:max-3] + "..."
}
