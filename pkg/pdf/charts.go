package pdf

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"

	"github.com/crowdsecurity/ipdex/pkg/models"
)

// Chart dimensions - use 2x for higher DPI rendering
const (
	chartDPIMultiplier = 2
	pieChartWidth      = 400 * chartDPIMultiplier
	pieChartHeight     = 300 * chartDPIMultiplier
	barChartWidth      = 400 * chartDPIMultiplier
	barChartHeight     = 250 * chartDPIMultiplier
	barWidth           = 30 * chartDPIMultiplier
)

// integerValueFormatter formats values as integers (no decimal places)
func integerValueFormatter(v interface{}) string {
	if typed, isFloat := v.(float64); isFloat {
		return fmt.Sprintf("%d", int(typed))
	}
	return fmt.Sprintf("%v", v)
}

// chartColors for pie/bar charts
var chartColors = []drawing.Color{
	{R: 245, G: 91, B: 96, A: 255},   // Red (malicious)
	{R: 251, G: 146, B: 60, A: 255},  // Orange (suspicious)
	{R: 136, G: 139, B: 206, A: 255}, // Purple (known)
	{R: 113, G: 229, B: 155, A: 255}, // Green (safe)
	{R: 96, G: 165, B: 250, A: 255},  // Blue (benign)
	{R: 128, G: 128, B: 128, A: 255}, // Gray (unknown)
	{R: 247, G: 170, B: 22, A: 255},  // Gold
	{R: 79, G: 75, B: 154, A: 255},   // Purple dark
}

// reputationColorMap for consistent coloring
var reputationColorMap = map[string]drawing.Color{
	"malicious":  {R: 245, G: 91, B: 96, A: 255},
	"suspicious": {R: 251, G: 146, B: 60, A: 255},
	"known":      {R: 136, G: 139, B: 206, A: 255},
	"safe":       {R: 113, G: 229, B: 155, A: 255},
	"benign":     {R: 96, G: 165, B: 250, A: 255},
	"unknown":    {R: 128, G: 128, B: 128, A: 255},
}

// KV represents a key-value pair for sorting
type KV struct {
	Key   string
	Value int
}

// getTopN returns top N items from a map sorted by value
func getTopN(m map[string]int, n int) []KV {
	var items []KV
	for k, v := range m {
		items = append(items, KV{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Value > items[j].Value
	})
	if len(items) > n {
		items = items[:n]
	}
	return items
}

// GenerateReputationPieChart creates a pie chart for reputation distribution
func GenerateReputationPieChart(stats *models.ReportStats) ([]byte, error) {
	if stats == nil || len(stats.TopReputation) == 0 {
		return nil, nil
	}

	var values []chart.Value
	for rep, count := range stats.TopReputation {
		clr, ok := reputationColorMap[rep]
		if !ok {
			clr = reputationColorMap["unknown"]
		}
		values = append(values, chart.Value{
			Label: rep,
			Value: float64(count),
			Style: chart.Style{
				FillColor:   clr,
				StrokeColor: drawing.Color{R: 255, G: 255, B: 255, A: 255},
				StrokeWidth: 2,
			},
		})
	}

	// Sort values by count descending for consistent ordering
	sort.Slice(values, func(i, j int) bool {
		return values[i].Value > values[j].Value
	})

	pie := chart.PieChart{
		Width:  pieChartWidth,
		Height: pieChartHeight,
		Values: values,
		Background: chart.Style{
			FillColor: drawing.Color{R: 255, G: 255, B: 255, A: 255},
		},
		// Larger font for labels at higher DPI
		Font: nil, // Uses default
	}

	buffer := bytes.NewBuffer(nil)
	if err := pie.Render(chart.PNG, buffer); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// GenerateTopBarChart creates a horizontal bar chart for top items
func GenerateTopBarChart(data map[string]int, title string, limit int) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	topItems := getTopN(data, limit)
	if len(topItems) == 0 {
		return nil, nil
	}

	var bars []chart.Value
	for i, item := range topItems {
		bars = append(bars, chart.Value{
			Label: truncate(item.Key, 20),
			Value: float64(item.Value),
			Style: chart.Style{
				FillColor:   chartColors[i%len(chartColors)],
				StrokeColor: drawing.Color{R: 255, G: 255, B: 255, A: 255},
				StrokeWidth: 1,
			},
		})
	}

	// Find max value for Y-axis range
	maxValue := 0.0
	for _, item := range topItems {
		if float64(item.Value) > maxValue {
			maxValue = float64(item.Value)
		}
	}

	barChart := chart.BarChart{
		Title:      title,
		TitleStyle: chart.StyleTextDefaults(),
		Width:      barChartWidth,
		Height:     barChartHeight,
		BarWidth:   barWidth,
		Bars:       bars,
		Background: chart.Style{
			FillColor: drawing.Color{R: 255, G: 255, B: 255, A: 255},
		},
		XAxis: chart.Style{
			FontSize:  8 * chartDPIMultiplier,
			FontColor: drawing.Color{R: 60, G: 60, B: 60, A: 255},
		},
		YAxis: chart.YAxis{
			Style: chart.Style{
				FontSize:  8 * chartDPIMultiplier,
				FontColor: drawing.Color{R: 60, G: 60, B: 60, A: 255},
			},
			ValueFormatter: integerValueFormatter,
			Range: &chart.ContinuousRange{
				Min: 0,
				Max: maxValue * 1.1, // Add 10% padding at top
			},
		},
	}

	buffer := bytes.NewBuffer(nil)
	if err := barChart.Render(chart.PNG, buffer); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// GenerateCountriesBarChart creates a bar chart for top countries
func GenerateCountriesBarChart(stats *models.ReportStats, limit int) ([]byte, error) {
	return GenerateTopBarChart(stats.TopCountries, "Top Countries", limit)
}

// GenerateBehaviorsBarChart creates a bar chart for top behaviors
func GenerateBehaviorsBarChart(stats *models.ReportStats, limit int) ([]byte, error) {
	return GenerateTopBarChart(stats.TopBehaviors, "Top Behaviors", limit)
}

// truncate shortens a string to max length with ellipsis
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return "..."
	}
	return s[:max-3] + "..."
}

