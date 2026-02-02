package pdf

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/image"
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

// GenerateReport creates a PDF report and saves it to the specified path
func GenerateReport(report *models.Report, stats *models.ReportStats, withIPs bool, outputPath string) error {
	g := &generator{
		report:  report,
		stats:   stats,
		withIPs: withIPs,
	}

	return g.generate(outputPath)
}

type generator struct {
	report  *models.Report
	stats   *models.ReportStats
	withIPs bool
}

func (g *generator) generate(outputPath string) error {
	cfg := config.NewBuilder().
		WithPageNumber().
		WithLeftMargin(10).
		WithTopMargin(10).
		WithRightMargin(10).
		Build()

	m := maroto.New(cfg)

	// Add header
	g.addHeader(m)

	// Add general info section
	g.addGeneralInfo(m)

	// Add charts section
	if err := g.addCharts(m); err != nil {
		return fmt.Errorf("failed to add charts: %w", err)
	}

	// Add statistics section
	g.addStatistics(m)

	// Add IP table if requested
	if g.withIPs && len(g.report.IPs) > 0 {
		g.addIPTable(m)
	}

	// Add footer
	g.addFooter(m)

	// Generate and save PDF
	doc, err := m.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate PDF: %w", err)
	}

	if err := doc.Save(outputPath); err != nil {
		return fmt.Errorf("failed to save PDF: %w", err)
	}

	return nil
}

func (g *generator) addHeader(m core.Maroto) {
	m.AddRow(30,
		col.New(3).Add(
			image.NewFromBytes(LogoPNG, extension.Png, props.Rect{
				Center:  true,
				Percent: 80,
			}),
		),
		col.New(9).Add(
			text.New("ipdex Report", props.Text{
				Size:  24,
				Style: fontstyle.Bold,
				Align: align.Left,
				Color: PurpleDark,
				Top:   5,
			}),
			text.New(g.report.Name, props.Text{
				Size:  14,
				Align: align.Left,
				Color: DarkGray,
				Top:   18,
			}),
		),
	)

	// Purple line separator
	m.AddRow(2,
		col.New(12).Add(
			line.New(props.Line{
				Color:     PurpleDark,
				Thickness: 2,
			}),
		),
	)

	m.AddRow(5) // Spacer
}

func (g *generator) addGeneralInfo(m core.Maroto) {
	// Section title
	m.AddRow(8,
		col.New(12).Add(
			text.New("General Information", props.Text{
				Size:  14,
				Style: fontstyle.Bold,
				Color: PurpleDark,
			}),
		),
	)

	// Info rows
	infoStyle := props.Text{Size: 10, Color: DarkGray}
	valueStyle := props.Text{Size: 10, Style: fontstyle.Bold, Color: Black}

	addInfoRow := func(m core.Maroto, label, value string) {
		m.AddRow(6,
			col.New(4).Add(text.New(label+":", infoStyle)),
			col.New(8).Add(text.New(value, valueStyle)),
		)
	}

	addInfoRow(m, "Report ID", strconv.Itoa(int(g.report.ID)))
	addInfoRow(m, "Creation Date", g.report.CreatedAt.Format("2006-01-02 15:04:05"))

	if g.report.IsFile {
		addInfoRow(m, "File Path", g.report.FilePath)
		addInfoRow(m, "SHA256", truncateMiddle(g.report.FileHash, 50))
	}

	if g.report.IsQuery {
		addInfoRow(m, "Query", g.report.Query)
		addInfoRow(m, "Since", g.report.Since)
	}

	addInfoRow(m, "Total IPs", strconv.Itoa(g.stats.NbIPs))

	knownPercent := float64(g.stats.NbIPs-g.stats.NbUnknownIPs) / float64(g.stats.NbIPs) * 100
	blocklistPercent := float64(g.stats.IPsBlockedByBlocklist) / float64(g.stats.NbIPs) * 100

	addInfoRow(m, "Known IPs", fmt.Sprintf("%d (%.1f%%)", g.stats.NbIPs-g.stats.NbUnknownIPs, knownPercent))
	addInfoRow(m, "IPs in Blocklist", fmt.Sprintf("%d (%.1f%%)", g.stats.IPsBlockedByBlocklist, blocklistPercent))

	m.AddRow(8) // Spacer
}

func (g *generator) addCharts(m core.Maroto) error {
	// Section title
	m.AddRow(8,
		col.New(12).Add(
			text.New("Threat Overview", props.Text{
				Size:  14,
				Style: fontstyle.Bold,
				Color: PurpleDark,
			}),
		),
	)

	// Add reputation distribution as proper rows
	if len(g.stats.TopReputation) > 0 {
		m.AddRow(6,
			col.New(12).Add(
				text.New("Reputation Distribution", props.Text{
					Size:  11,
					Style: fontstyle.Bold,
					Color: DarkGray,
				}),
			),
		)

		topRep := getTopN(g.stats.TopReputation, maxTopDisplay)
		for _, item := range topRep {
			percent := float64(item.Value) / float64(g.stats.NbIPs) * 100
			color := GetReputationColor(item.Key)
			m.AddRow(5,
				col.New(6).Add(
					text.New(cases.Title(language.Und).String(item.Key), props.Text{
						Size:  9,
						Color: color,
						Left:  10,
					}),
				),
				col.New(6).Add(
					text.New(fmt.Sprintf("%d (%.1f%%)", item.Value, percent), props.Text{
						Size:  9,
						Color: color,
					}),
				),
			)
		}
		m.AddRow(5) // Spacer
	}

	// Add top countries as text table
	if len(g.stats.TopCountries) > 0 {
		g.addTopItemsSection(m, "Top Countries", g.stats.TopCountries)
	}

	// Add top behaviors as text table
	if len(g.stats.TopBehaviors) > 0 {
		g.addTopItemsSection(m, "Top Behaviors", g.stats.TopBehaviors)
	}

	m.AddRow(5) // Spacer
	return nil
}

func (g *generator) addTopItemsSection(m core.Maroto, title string, data map[string]int) {
	topItems := getTopN(data, maxTopDisplay)
	if len(topItems) == 0 {
		return
	}

	m.AddRow(6,
		col.New(12).Add(
			text.New(title, props.Text{
				Size:  11,
				Style: fontstyle.Bold,
				Color: DarkGray,
			}),
		),
	)

	for _, item := range topItems {
		percent := float64(item.Value) / float64(g.stats.NbIPs) * 100
		m.AddRow(5,
			col.New(6).Add(
				text.New(truncate(item.Key, 30), props.Text{
					Size:  9,
					Color: DarkGray,
					Left:  10,
				}),
			),
			col.New(6).Add(
				text.New(fmt.Sprintf("%d (%.1f%%)", item.Value, percent), props.Text{
					Size:  9,
					Color: DarkGray,
				}),
			),
		)
	}

	m.AddRow(5) // Spacer
}

func (g *generator) addStatistics(m core.Maroto) {
	// Section title
	m.AddRow(8,
		col.New(12).Add(
			text.New("Statistics", props.Text{
				Size:  14,
				Style: fontstyle.Bold,
				Color: PurpleDark,
			}),
		),
	)

	// Add statistics in a grid layout
	g.addStatTable(m, "Top Classifications", g.stats.TopClassifications)
	g.addStatTable(m, "Top Blocklists", g.stats.TopBlocklists)
	g.addStatTable(m, "Top CVEs", g.stats.TopCVEs)
	g.addStatTable(m, "Top IP Ranges", g.stats.TopIPRange)
	g.addStatTable(m, "Top Autonomous Systems", g.stats.TopAS)

	m.AddRow(5) // Spacer
}

func (g *generator) addStatTable(m core.Maroto, title string, data map[string]int) {
	if len(data) == 0 {
		return
	}

	topItems := getTopN(data, maxTopDisplay)

	// Title
	m.AddRow(6,
		col.New(12).Add(
			text.New(title, props.Text{
				Size:  11,
				Style: fontstyle.Bold,
				Color: DarkGray,
			}),
		),
	)

	// Items
	for _, item := range topItems {
		percent := float64(item.Value) / float64(g.stats.NbIPs) * 100
		m.AddRow(5,
			col.New(8).Add(
				text.New(truncate(item.Key, 40), props.Text{
					Size:  9,
					Color: DarkGray,
					Left:  5,
				}),
			),
			col.New(4).Add(
				text.New(fmt.Sprintf("%d (%.1f%%)", item.Value, percent), props.Text{
					Size:  9,
					Color: DarkGray,
					Align: align.Right,
				}),
			),
		)
	}

	m.AddRow(3) // Spacer between tables
}

func (g *generator) addIPTable(m core.Maroto) {
	// Section title
	m.AddRow(8,
		col.New(12).Add(
			text.New("IP Address Details", props.Text{
				Size:  14,
				Style: fontstyle.Bold,
				Color: PurpleDark,
			}),
		),
	)

	// Table header
	headerStyle := props.Cell{
		BackgroundColor: PurpleLight,
	}
	headerTextStyle := props.Text{
		Size:  8,
		Style: fontstyle.Bold,
		Color: White,
		Align: align.Center,
	}

	m.AddRow(7,
		col.New(2).Add(text.New("IP", headerTextStyle)).WithStyle(&headerStyle),
		col.New(1).Add(text.New("Country", headerTextStyle)).WithStyle(&headerStyle),
		col.New(2).Add(text.New("AS Name", headerTextStyle)).WithStyle(&headerStyle),
		col.New(2).Add(text.New("Reputation", headerTextStyle)).WithStyle(&headerStyle),
		col.New(1).Add(text.New("Conf.", headerTextStyle)).WithStyle(&headerStyle),
		col.New(2).Add(text.New("Behaviors", headerTextStyle)).WithStyle(&headerStyle),
		col.New(2).Add(text.New("Range", headerTextStyle)).WithStyle(&headerStyle),
	)

	// Table rows
	rowStyle := props.Cell{
		BorderType:  border.Bottom,
		BorderColor: LightGray,
	}
	cellTextStyle := props.Text{
		Size:  7,
		Color: DarkGray,
	}

	for i, ip := range g.report.IPs {
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
			Size:  7,
			Color: repColor,
			Style: fontstyle.Bold,
		}

		m.AddRow(6,
			col.New(2).Add(text.New(ip.Ip, cellTextStyle)).WithStyle(&rowStyle),
			col.New(1).Add(text.New(country, cellTextStyle)).WithStyle(&rowStyle),
			col.New(2).Add(text.New(asName, cellTextStyle)).WithStyle(&rowStyle),
			col.New(2).Add(text.New(reputation, repTextStyle)).WithStyle(&rowStyle),
			col.New(1).Add(text.New(confidence, cellTextStyle)).WithStyle(&rowStyle),
			col.New(2).Add(text.New(behaviors, cellTextStyle)).WithStyle(&rowStyle),
			col.New(2).Add(text.New(ipRange, cellTextStyle)).WithStyle(&rowStyle),
		)
	}
}

func (g *generator) addFooter(m core.Maroto) {
	m.AddRow(10) // Spacer

	// Separator line
	m.AddRow(2,
		col.New(12).Add(
			line.New(props.Line{
				Color:     LightGray,
				Thickness: 1,
			}),
		),
	)

	// Footer content
	m.AddRow(8,
		col.New(6).Add(
			text.New("Generated by ipdex - CrowdSec CTI Tool", props.Text{
				Size:  8,
				Color: DarkGray,
			}),
			text.New(time.Now().Format("2006-01-02 15:04:05"), props.Text{
				Size:  8,
				Color: DarkGray,
				Top:   10,
			}),
		),
		col.New(6).Add(
			text.New("https://crowdsec.net", props.Text{
				Size:  8,
				Color: PurpleDark,
				Align: align.Right,
			}),
			text.New("https://app.crowdsec.net", props.Text{
				Size:  8,
				Color: PurpleDark,
				Align: align.Right,
				Top:   10,
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

// GetOutputPath constructs the full PDF output path
func GetOutputPath(outputDir string, reportID uint) string {
	return filepath.Join(outputDir, fmt.Sprintf("report_%d.pdf", reportID))
}
