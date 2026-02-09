package pdf

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	mimage "github.com/johnfercher/maroto/v2/pkg/components/image"
	"github.com/johnfercher/maroto/v2/pkg/components/line"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/border"
	"github.com/johnfercher/maroto/v2/pkg/consts/extension"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/crowdsecurity/ipdex/pkg/models"
)

const (
	maxTopDisplay = 5
)

// GenerateReport creates a PDF report and saves it to the specified directory
// using the naming convention report-<id>.pdf
func GenerateReport(report *models.Report, stats *models.ReportStats, withIPs bool, outputDir string) error {
	g := &generator{
		report:  report,
		stats:   stats,
		withIPs: withIPs,
	}

	outputPath := filepath.Join(outputDir, fmt.Sprintf("report-%d.pdf", report.ID))
	return g.generate(outputPath)
}

type generator struct {
	report  *models.Report
	stats   *models.ReportStats
	withIPs bool
	layout  *LayoutManager
}

func (g *generator) generate(outputPath string) error {
	cfg := config.NewBuilder().
		WithPageNumber().
		WithLeftMargin(LeftMargin).
		WithTopMargin(TopMargin).
		WithRightMargin(RightMargin).
		Build()

	m := maroto.New(cfg)
	g.layout = NewLayoutManager(m)

	// Add header
	g.addHeader()

	// Add executive summary
	g.addExecutiveSummary()

	// Add general info section
	g.addGeneralInfo()

	// Add charts section
	if err := g.addCharts(); err != nil {
		return fmt.Errorf("failed to add charts: %w", err)
	}

	// Add statistics section
	g.addStatistics()

	// Add IP table if requested
	if g.withIPs && len(g.report.IPs) > 0 {
		g.addIPTable()
	}

	// Add glossary section
	g.addGlossary()

	// Add footer
	g.addFooter()

	// Generate and save PDF
	doc, err := m.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate PDF: %w", err)
	}

	if err := doc.Save(outputPath); err != nil {
		return fmt.Errorf("failed to save PDF: %w", err)
	}

	fmt.Printf("PDF report saved to: %s\n", outputPath)
	return nil
}

func (g *generator) addHeader() {
	maliciousCount := 0
	if count, ok := g.stats.TopReputation["malicious"]; ok {
		maliciousCount = count
	}
	maliciousPercent := percent(maliciousCount, g.stats.NbIPs)
	riskLevel := GetRiskLevel(maliciousPercent)
	riskColor := GetRiskColor(riskLevel)
	riskLabel := GetRiskLabel(riskLevel)

	g.layout.AddRow(RowHeightTitle,
		col.New(3).Add(
			mimage.NewFromBytes(LogoPNG, extension.Png, props.Rect{
				Center:  true,
				Percent: 80,
			}),
		),
		col.New(6).Add(
			text.New("ipdex Report", WithTop(StyleTitle, 5)),
			text.New(g.report.Name, props.Text{
				Size:  FontSizeH1,
				Align: align.Left,
				Color: DarkGray,
				Top:   18,
			}),
		),
		col.New(3).Add(
			text.New(riskLabel, props.Text{
				Size:  12,
				Style: fontstyle.Bold,
				Align: align.Right,
				Color: riskColor,
				Top:   8,
			}),
		),
	)

	// Purple line separator
	g.layout.AddRowDirect(2,
		col.New(12).Add(
			line.New(props.Line{
				Color:     PurpleDark,
				Thickness: 2,
			}),
		),
	)

	g.layout.AddSpacer(RowHeightSpacer)
}

func (g *generator) addExecutiveSummary() {
	// Calculate risk metrics
	maliciousCount := 0
	suspiciousCount := 0
	if count, ok := g.stats.TopReputation["malicious"]; ok {
		maliciousCount = count
	}
	if count, ok := g.stats.TopReputation["suspicious"]; ok {
		suspiciousCount = count
	}

	maliciousPercent := percent(maliciousCount, g.stats.NbIPs)
	threatPercent := percent(maliciousCount+suspiciousCount, g.stats.NbIPs)
	knownPercent := percent(g.stats.NbIPs-g.stats.NbUnknownIPs, g.stats.NbIPs)

	riskLevel := GetRiskLevel(maliciousPercent)
	riskColor := GetRiskColor(riskLevel)
	riskBgColor := GetRiskBgColor(riskLevel)
	riskLabel := GetRiskLabel(riskLevel)

	// Get risk statement parts
	riskParts := g.getRiskStatementParts(riskLevel, maliciousPercent, threatPercent)

	// Section title
	g.layout.AddRow(RowHeightH1,
		col.New(12).Add(text.New("Executive Summary", StyleH1)),
	)

	// Risk indicator panel with colored background on left, summary on right
	riskPanelStyle := props.Cell{
		BackgroundColor: riskBgColor,
	}

	g.layout.AddRow(36,
		// Left panel: Risk indicator with colored background
		col.New(3).Add(
			text.New(riskLabel, props.Text{
				Size:  FontSizeH1,
				Style: fontstyle.Bold,
				Color: riskColor,
				Align: align.Center,
				Top:   12,
			}),
		).WithStyle(&riskPanelStyle),
		// Right panel: Summary text with natural language
		col.New(9).Add(
			text.New(riskParts.Summary, WithTop(WithLeft(StyleBody, 5), 5)),
			text.New(riskParts.CTA, WithTop(WithLeft(StyleBody, 5), 18)),
		),
	)

	g.layout.AddSpacer(RowHeightSpacerLg)

	// Key findings
	g.layout.AddRow(RowHeightBody,
		col.New(12).Add(text.New("Key Findings", StyleH2)),
	)

	// Finding 1: Coverage
	g.layout.AddRow(RowHeightBody,
		col.New(12).Add(
			text.New(fmt.Sprintf("• Known to CrowdSec intelligence: %.0f%% (%d of %d IPs)",
				knownPercent, g.stats.NbIPs-g.stats.NbUnknownIPs, g.stats.NbIPs),
				WithLeft(StyleSmall, 5)),
		),
	)

	// Finding 2: Threat breakdown
	if maliciousCount > 0 || suspiciousCount > 0 {
		threatText := fmt.Sprintf("• Flagged as malicious or suspicious: %.0f%%", threatPercent)
		if maliciousCount > 0 && suspiciousCount > 0 {
			threatText += fmt.Sprintf(" (%d malicious, %d suspicious)", maliciousCount, suspiciousCount)
		} else if maliciousCount > 0 {
			threatText += fmt.Sprintf(" (%d malicious)", maliciousCount)
		} else {
			threatText += fmt.Sprintf(" (%d suspicious)", suspiciousCount)
		}
		g.layout.AddRow(RowHeightBody,
			col.New(12).Add(text.New(threatText, WithLeft(StyleSmall, 5))),
		)
	} else {
		g.layout.AddRow(RowHeightBody,
			col.New(12).Add(
				text.New("• No IPs were flagged as malicious or suspicious.", WithLeft(StyleSmall, 5)),
			),
		)
	}

	// Finding 3: Top behavior if present
	if len(g.stats.TopBehaviors) > 0 {
		topBehaviors := getTopN(g.stats.TopBehaviors, 1)
		if len(topBehaviors) > 0 {
			behaviorPercent := percent(topBehaviors[0].Value, g.stats.NbIPs)
			g.layout.AddRow(RowHeightBody,
				col.New(12).Add(
					text.New(fmt.Sprintf("• Most common activity type: %s (%.0f%% of IPs)",
						topBehaviors[0].Key, behaviorPercent), WithLeft(StyleSmall, 5)),
				),
			)
		}
	}

	// Finding 4: Blocklist presence
	if g.stats.IPsBlockedByBlocklist > 0 {
		blocklistPercent := percent(g.stats.IPsBlockedByBlocklist, g.stats.NbIPs)
		g.layout.AddRow(RowHeightBody,
			col.New(12).Add(
				text.New(fmt.Sprintf("• On security blocklists: %d IPs (%.0f%%)",
					g.stats.IPsBlockedByBlocklist, blocklistPercent), WithLeft(StyleSmall, 5)),
			),
		)
	}

	g.layout.AddSpacer(RowHeightSpacerLg)
}

// RiskStatementParts holds the summary text for the executive summary
type RiskStatementParts struct {
	Summary string // Natural language summary of findings
	CTA     string // Call to action recommendation
}

// percentToNaturalLanguage converts a percentage to natural language description
func percentToNaturalLanguage(pct float64) string {
	switch {
	case pct >= 90:
		return "Nearly all"
	case pct >= 75:
		return "A large majority"
	case pct >= 60:
		return "Over half"
	case pct >= 50:
		return "About half"
	case pct >= 40:
		return "Nearly half"
	case pct >= 30:
		return "About a third"
	case pct >= 20:
		return "About a quarter"
	default:
		return "A portion"
	}
}

// getRiskStatementParts returns natural language risk summary based on analysis
func (g *generator) getRiskStatementParts(level RiskLevel, maliciousPercent, threatPercent float64) RiskStatementParts {
	parts := RiskStatementParts{}

	// Select the relevant percentage for natural language description
	var pct float64
	switch level {
	case RiskLevelHigh:
		pct = maliciousPercent
	case RiskLevelMedium:
		pct = threatPercent
	}
	proportion := percentToNaturalLanguage(pct)

	switch level {
	case RiskLevelHigh:
		parts.Summary = fmt.Sprintf(
			"This analysis of %d IPs reveals significant security concerns. %s (%.0f%%) "+
				"have been confirmed as malicious by the CrowdSec threat intelligence network.",
			g.stats.NbIPs, proportion, maliciousPercent)
		parts.CTA = "We recommend enabling CrowdSec blocklists to automatically block these known threats."
	case RiskLevelMedium:
		parts.Summary = fmt.Sprintf(
			"This analysis of %d IPs shows moderate security concerns. %s (%.0f%%) "+
				"display suspicious or malicious behavior patterns that warrant attention.",
			g.stats.NbIPs, proportion, threatPercent)
		parts.CTA = "Consider reviewing high-risk IPs and enabling blocklists for added protection."
	default:
		parts.Summary = fmt.Sprintf(
			"This analysis of %d IPs shows minimal security concerns. The majority appear safe "+
				"or have no significant history of malicious activity.",
			g.stats.NbIPs)
		parts.CTA = "Continue routine monitoring. Blocklists can help prevent emerging threats."
	}
	return parts
}

func (g *generator) addGeneralInfo() {
	// Section title
	g.layout.AddRow(RowHeightH1,
		col.New(12).Add(text.New("General Information", StyleH1)),
	)

	// Info rows helper
	addInfoRow := func(label, value string) {
		g.layout.AddRow(RowHeightBody,
			col.New(4).Add(text.New(label+":", StyleLabel)),
			col.New(8).Add(text.New(value, StyleValue)),
		)
	}

	addInfoRow("Report ID", strconv.Itoa(int(g.report.ID)))
	addInfoRow("Created At", g.report.CreatedAt.Format("2006-01-02 15:04:05"))

	if g.report.IsFile {
		addInfoRow("Source", "File scan")
		addInfoRow("File Path", g.report.FilePath)
		addInfoRow("SHA256", truncateMiddle(g.report.FileHash, 50))
	}

	if g.report.IsQuery {
		addInfoRow("Source", "Threat search")
		addInfoRow("Search Query", g.report.Query)
		addInfoRow("Time Window", g.report.Since)
	}

	addInfoRow("Total IPs Analyzed", strconv.Itoa(g.stats.NbIPs))

	knownPercent := percent(g.stats.NbIPs-g.stats.NbUnknownIPs, g.stats.NbIPs)
	blocklistPercent := percent(g.stats.IPsBlockedByBlocklist, g.stats.NbIPs)

	addInfoRow("Known to CrowdSec", fmt.Sprintf("%d (%.1f%%)", g.stats.NbIPs-g.stats.NbUnknownIPs, knownPercent))
	addInfoRow("IPs on Blocklists", fmt.Sprintf("%d (%.1f%%)", g.stats.IPsBlockedByBlocklist, blocklistPercent))

	g.layout.AddSpacer(RowHeightSpacerLg)
}

func (g *generator) addCharts() error {
	// Section title - Maroto handles page breaks naturally
	g.layout.AddRow(RowHeightH1,
		col.New(12).Add(text.New("Threat Overview", StyleH1)),
	)

	// Try to add reputation pie chart
	if len(g.stats.TopReputation) > 0 {
		pieChartBytes, err := GenerateReputationPieChart(g.stats)
		if err == nil && pieChartBytes != nil {
			g.layout.AddRow(RowHeightH2,
				col.New(12).Add(text.New("Reputation Distribution", StyleH2)),
			)

			// Add the pie chart image
			g.layout.AddRow(RowHeightChart,
				col.New(6).Add(
					mimage.NewFromBytes(pieChartBytes, extension.Png, props.Rect{
						Center:  true,
						Percent: 100,
					}),
				),
				col.New(6).Add(
					g.buildReputationLegend()...,
				),
			)
			g.layout.AddSpacer(RowHeightSpacer)
		} else {
			// Fallback to text-based display if chart fails
			g.addReputationText()
		}
	}

	// Add top countries with bar chart
	if len(g.stats.TopCountries) > 0 {
		g.addTopItemsWithChart("Top Source Countries", g.stats.TopCountries, "Countries with the highest number of flagged IPs")
	}

	// Add top behaviors with bar chart
	if len(g.stats.TopBehaviors) > 0 {
		g.addTopItemsWithChart("Top Activity Types", g.stats.TopBehaviors, "Most common activity types seen in this report")
	}

	g.layout.AddSpacer(RowHeightSpacer)
	return nil
}

func (g *generator) buildReputationLegend() []core.Component {
	var components []core.Component

	topRep := getTopN(g.stats.TopReputation, maxTopDisplay)
	for _, item := range topRep {
		percent := percent(item.Value, g.stats.NbIPs)
		color := GetReputationColor(item.Key)
		components = append(components,
			text.New(fmt.Sprintf("- %s: %d (%.1f%%)",
				cases.Title(language.Und).String(item.Key), item.Value, percent), props.Text{
				Size:  9,
				Color: color,
				Top:   float64(len(components) * 6),
			}),
		)
	}
	return components
}

func (g *generator) addReputationText() {
	g.layout.AddRow(RowHeightH2,
		col.New(12).Add(text.New("Reputation Distribution", StyleH2)),
	)

	topRep := getTopN(g.stats.TopReputation, maxTopDisplay)
	for _, item := range topRep {
		pct := percent(item.Value, g.stats.NbIPs)
		color := GetReputationColor(item.Key)
		g.layout.AddRow(RowHeightBody,
			col.New(6).Add(
				text.New(cases.Title(language.Und).String(item.Key), WithLeft(WithColor(StyleSmall, color), 10)),
			),
			col.New(6).Add(
				text.New(fmt.Sprintf("%d (%.1f%%)", item.Value, pct), WithColor(StyleSmall, color)),
			),
		)
	}
	g.layout.AddSpacer(RowHeightSpacer)
}

func (g *generator) addTopItemsWithChart(title string, data map[string]int, description string) {
	topItems := getTopN(data, maxTopDisplay)
	if len(topItems) == 0 {
		return
	}

	// Section header with description - Maroto handles page breaks
	g.layout.AddRow(RowHeightH2,
		col.New(12).Add(text.New(title, StyleH2)),
	)

	g.layout.AddRow(RowHeightDesc,
		col.New(12).Add(text.New(description, WithLeft(StyleDescription, 5))),
	)

	// Try to generate bar chart
	chartBytes, err := GenerateTopBarChart(data, "", maxTopDisplay)
	if err == nil && chartBytes != nil {
		g.layout.AddRow(RowHeightBarChart,
			col.New(7).Add(
				mimage.NewFromBytes(chartBytes, extension.Png, props.Rect{
					Center:  true,
					Percent: 95,
				}),
			),
			col.New(5).Add(
				g.buildItemsLegend(topItems)...,
			),
		)
	} else {
		// Fallback to text-based display
		for _, item := range topItems {
			pct := percent(item.Value, g.stats.NbIPs)
			g.layout.AddRow(RowHeightBody,
				col.New(8).Add(text.New(truncate(item.Key, 35), WithLeft(StyleSmall, 10))),
				col.New(4).Add(text.New(fmt.Sprintf("%d (%.1f%%)", item.Value, pct), StyleSmall)),
			)
		}
	}

	g.layout.AddSpacer(RowHeightSpacer)
}

func (g *generator) buildItemsLegend(items []KV) []core.Component {
	var components []core.Component

	for i, item := range items {
		percent := percent(item.Value, g.stats.NbIPs)
		components = append(components,
			text.New(fmt.Sprintf("%d. %s", i+1, truncate(item.Key, 25)), props.Text{
				Size:  8,
				Color: DarkGray,
				Top:   float64(i * 8),
			}),
			text.New(fmt.Sprintf("   %d IPs (%.1f%%)", item.Value, percent), props.Text{
				Size:  7,
				Color: DarkGray,
				Top:   float64(i*8) + 4,
			}),
		)
	}
	return components
}

func (g *generator) addStatistics() {
	// Section title
	g.layout.AddRow(RowHeightH1,
		col.New(12).Add(text.New("Statistics", StyleH1)),
	)

	// Add statistics tables with proper page break handling
	g.addStatTable("Top Classifications", g.stats.TopClassifications)
	g.addStatTable("Top Blocklists", g.stats.TopBlocklists)
	g.addStatTable("Top CVEs", g.stats.TopCVEs)
	g.addStatTable("Top IP Ranges", g.stats.TopIPRange)
	g.addStatTable("Top Autonomous Systems", g.stats.TopAS)

	g.layout.AddSpacer(RowHeightSpacer)
}

func (g *generator) addStatTable(title string, data map[string]int) {
	if len(data) == 0 {
		return
	}

	topItems := getTopN(data, maxTopDisplay)

	// Ensure space for title + header + at least MinListItems data rows before starting
	// This prevents orphan headers where the title appears but no data fits
	minRows := min(MinListItems, len(topItems))
	minHeight := RowHeightH2 + RowHeightTableRow + (RowHeightTableRow * float64(minRows))
	g.layout.EnsureSpace(minHeight)

	// Render title and header
	g.renderStatTableHeader(title, false)

	// Row styling for zebra striping
	evenRowStyle := props.Cell{
		BackgroundColor: White,
		BorderType:      border.Bottom,
		BorderColor:     LightGray,
	}
	oddRowStyle := props.Cell{
		BackgroundColor: LightGray,
		BorderType:      border.Bottom,
		BorderColor:     LightGray,
	}

	// Render items with page break handling
	for i, item := range topItems {
		// Check if we need a page break before this item
		if g.layout.Remaining() < RowHeightTableRow {
			g.layout.NewPage()
			// Re-render title and header with "(continued)" suffix
			g.renderStatTableHeader(title, true)
		}

		pct := percent(item.Value, g.stats.NbIPs)
		rowStyle := &evenRowStyle
		if i%2 == 1 {
			rowStyle = &oddRowStyle
		}

		g.layout.AddRow(RowHeightTableRow,
			col.New(8).Add(text.New(truncate(item.Key, 45), WithLeft(StyleSmall, 5))).WithStyle(rowStyle),
			col.New(4).Add(text.New(fmt.Sprintf("%d (%.1f%%)", item.Value, pct), StyleValueRight)).WithStyle(rowStyle),
		)
	}

	g.layout.AddSpacer(RowHeightSpacer) // Spacer between tables
}

// renderStatTableHeader renders the table title and column headers
func (g *generator) renderStatTableHeader(title string, continued bool) {
	displayTitle := title
	if continued {
		displayTitle = title + " (continued)"
	}
	g.layout.AddRow(RowHeightH2,
		col.New(12).Add(text.New(displayTitle, StyleH2)),
	)

	// Column headers for better alignment
	headerStyle := props.Cell{
		BackgroundColor: PurpleLight,
	}
	g.layout.AddRow(RowHeightTableRow,
		col.New(8).Add(text.New("Name", WithLeft(StyleTableHeader, 5))).WithStyle(&headerStyle),
		col.New(4).Add(text.New("Count (%)", StyleTableHeader)).WithStyle(&headerStyle),
	)
}

func (g *generator) addIPTable() {
	// Ensure space for section title + header + at least 3 rows
	minHeight := RowHeightH1 + RowHeightTableHead + (RowHeightTableRow * 3)
	g.layout.EnsureSpace(minHeight)

	// Section title
	g.layout.AddRow(RowHeightH1,
		col.New(12).Add(text.New("IP Address Details", StyleH1)),
	)

	// Render table header
	g.renderIPTableHeader(false)

	// Table rows
	rowStyle := props.Cell{
		BorderType:  border.Bottom,
		BorderColor: LightGray,
	}

	for i, ip := range g.report.IPs {
		// Check if we need a page break
		if g.layout.Remaining() < RowHeightTableRow {
			g.layout.NewPage()
			// Re-render header on new page
			g.renderIPTableHeader(true)
		}

		// Alternate row colors
		if i%2 == 0 {
			rowStyle.BackgroundColor = White
		} else {
			rowStyle.BackgroundColor = LightGray
		}

		country := "N/A"
		if ip.Location.Country != nil && *ip.Location.Country != "" {
			country = *ip.Location.Country
		}

		asName := "N/A"
		if ip.AsName != nil && *ip.AsName != "" {
			asName = truncate(*ip.AsName, 15)
		}

		reputation := ip.Reputation
		if reputation == "" {
			reputation = "unknown"
		}

		confidence := ip.Confidence
		if confidence == "" {
			confidence = "N/A"
		}

		behaviors := "N/A"
		if len(ip.Behaviors) > 0 {
			var behaviorLabels []string
			for _, b := range ip.Behaviors {
				behaviorLabels = append(behaviorLabels, b.Label)
			}
			behaviors = truncate(strings.Join(behaviorLabels, ", "), 20)
		}

		ipRange := "N/A"
		if ip.IpRange != nil && *ip.IpRange != "" {
			ipRange = truncate(*ip.IpRange, 18)
		}

		// Color-code reputation
		repColor := GetReputationColor(reputation)
		repTextStyle := props.Text{
			Size:  FontSizeTiny,
			Color: repColor,
			Style: fontstyle.Bold,
		}

		g.layout.AddRow(RowHeightTableRow,
			col.New(2).Add(text.New(ip.Ip, StyleTableCell)).WithStyle(&rowStyle),
			col.New(1).Add(text.New(country, StyleTableCell)).WithStyle(&rowStyle),
			col.New(2).Add(text.New(asName, StyleTableCell)).WithStyle(&rowStyle),
			col.New(2).Add(text.New(reputation, repTextStyle)).WithStyle(&rowStyle),
			col.New(1).Add(text.New(confidence, StyleTableCell)).WithStyle(&rowStyle),
			col.New(2).Add(text.New(behaviors, StyleTableCell)).WithStyle(&rowStyle),
			col.New(2).Add(text.New(ipRange, StyleTableCell)).WithStyle(&rowStyle),
		)
	}
}

// renderIPTableHeader renders the IP table header
func (g *generator) renderIPTableHeader(continued bool) {
	title := "IP Address Details"
	if continued {
		title += " (continued)"
		g.layout.AddRow(RowHeightH2,
			col.New(12).Add(text.New(title, StyleH2)),
		)
	}

	g.layout.AddRow(RowHeightTableHead,
		col.New(2).Add(text.New("IP", StyleTableHeader)).WithStyle(&CellStyleHeader),
		col.New(1).Add(text.New("Country", StyleTableHeader)).WithStyle(&CellStyleHeader),
		col.New(2).Add(text.New("AS Name", StyleTableHeader)).WithStyle(&CellStyleHeader),
		col.New(2).Add(text.New("Reputation", StyleTableHeader)).WithStyle(&CellStyleHeader),
		col.New(1).Add(text.New("Conf.", StyleTableHeader)).WithStyle(&CellStyleHeader),
		col.New(2).Add(text.New("Behaviors", StyleTableHeader)).WithStyle(&CellStyleHeader),
		col.New(2).Add(text.New("Range", StyleTableHeader)).WithStyle(&CellStyleHeader),
	)
}

func (g *generator) addGlossary() {
	// Ensure space for section title + subtitle + at least one subsection header + 2 definitions
	minHeight := RowHeightH1 + RowHeightBody + RowHeightH2 + (RowHeightBody * 4)
	g.layout.EnsureSpace(minHeight)

	// Section title
	g.layout.AddRow(RowHeightH1,
		col.New(12).Add(text.New("Glossary & Terminology", StyleH1)),
	)

	g.layout.AddRow(RowHeightBody,
		col.New(12).Add(text.New("Plain-language explanations of terms used in this report.", StyleSmall)),
	)

	g.layout.AddSpacer(RowHeightSpacer)

	// Reputation levels - always include
	g.addGlossarySection("Reputation Levels", ReputationDefinitions, true)

	// Confidence levels
	g.addGlossarySection("Confidence Levels", ConfidenceDefinitions, false)

	// Dynamic behaviors - only include if behaviors are present
	relevantBehaviors := GetRelevantBehaviors(g.stats.TopBehaviors)
	if len(relevantBehaviors) > 0 {
		g.addGlossarySection("Activity Types (from this report)", relevantBehaviors, false)
	}

	// Key terms - conditionally include based on report data
	var keyTerms []TermDefinition
	for _, def := range KeyTermDefinitions {
		switch def.Term {
		case "CVE":
			if ShouldIncludeCVEDefinition(g.stats.TopCVEs) {
				keyTerms = append(keyTerms, def)
			}
		case "Blocklist":
			if ShouldIncludeBlocklistDefinition(g.stats.TopBlocklists) {
				keyTerms = append(keyTerms, def)
			}
		case "Autonomous System (AS)":
			if ShouldIncludeASDefinition(g.stats.TopAS) {
				keyTerms = append(keyTerms, def)
			}
		case "IP Range":
			if len(g.stats.TopIPRange) > 0 {
				keyTerms = append(keyTerms, def)
			}
		}
	}

	if len(keyTerms) > 0 {
		g.addGlossarySection("Key Terms", keyTerms, false)
	}

	g.layout.AddSpacer(RowHeightSpacerXl)
}

// addGlossarySection renders a glossary subsection with proper page breaks
func (g *generator) addGlossarySection(title string, definitions []TermDefinition, useReputationColors bool) {
	if len(definitions) == 0 {
		return
	}

	// Ensure space for subsection header + at least 2 definitions
	minHeight := RowHeightH2 + (RowHeightBody * 4)
	g.layout.EnsureSpace(minHeight)

	// Subsection header
	g.layout.AddRow(RowHeightH2,
		col.New(12).Add(text.New(title, StyleH2)),
	)

	// Render definitions with page break handling
	for _, def := range definitions {
		// Check if we need a page break
		if g.layout.Remaining() < RowHeightBody*2 {
			g.layout.NewPage()
			// Re-render subsection title
			g.layout.AddRow(RowHeightH2,
				col.New(12).Add(text.New(title+" (continued)", StyleH2)),
			)
		}

		// Determine term color
		termStyle := StyleGlossaryTerm
		if useReputationColors {
			color := GetReputationColor(strings.ToLower(def.Term))
			termStyle = WithColor(StyleGlossaryTerm, color)
		}

		// Use wider term column (4 cols instead of 2) to prevent wrapping
		g.layout.AddRow(RowHeightBody,
			col.New(4).Add(text.New(formatGlossaryTerm(def.Term), WithLeft(termStyle, 5))),
			col.New(8).Add(text.New(def.Definition, StyleGlossaryDef)),
		)

		g.layout.AddSpacer(2) // Small spacer between definitions
	}

	g.layout.AddSpacer(RowHeightSpacer)
}

// formatGlossaryTerm formats a term with non-breaking spaces for known phrases
func formatGlossaryTerm(term string) string {
	// Replace spaces with non-breaking spaces for known multi-word terms
	// This prevents awkward line breaks within terms
	knownPhrases := []string{
		"High Confidence",
		"Medium Confidence",
		"Low Confidence",
		"Autonomous System (AS)",
		"IP Range",
	}

	for _, phrase := range knownPhrases {
		if term == phrase {
			// Use regular space - Maroto handles wrapping at cell level
			return term
		}
	}
	return term
}

func (g *generator) addFooter() {
	g.layout.AddSpacer(RowHeightSpacerXl)

	// Separator line
	g.layout.AddRowDirect(2,
		col.New(12).Add(
			line.New(props.Line{
				Color:     LightGray,
				Thickness: 1,
			}),
		),
	)

	// URLs for clickable links
	crowdsecURL := "https://crowdsec.net"
	consoleURL := "https://app.crowdsec.net"

	// Footer content
	g.layout.AddRow(RowHeightSpacerLg,
		col.New(6).Add(
			text.New("Generated by ipdex - CrowdSec CTI Tool", StyleFooter),
			text.New(time.Now().Format("2006-01-02 15:04:05"), WithTop(StyleFooter, 10)),
		),
		col.New(6).Add(
			text.New("crowdsec.net", props.Text{
				Size:      FontSizeFooter,
				Color:     PurpleDark,
				Align:     align.Right,
				Hyperlink: &crowdsecURL,
			}),
			text.New("app.crowdsec.net", props.Text{
				Size:      FontSizeFooter,
				Color:     PurpleDark,
				Align:     align.Right,
				Top:       10,
				Hyperlink: &consoleURL,
			}),
		),
	)
}

// truncateMiddle truncates a string in the middle with ellipsis
func truncateMiddle(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 5 {
		return s[:max]
	}
	half := (max - 3) / 2
	return s[:half] + "..." + s[len(s)-half:]
}

func percent(part, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}
