package display

import (
	"fmt"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

const (
	FormatHuman = "human"
	FormatCSV   = "csv"
)

// Helper function to safely get string value or default to "N/A"
func strOrNA(ptr *string) string {
	if ptr != nil && *ptr != "" {
		return *ptr
	}
	return "N/A"
}

// Format is a generic formatting function that takes any CTI type and formats it
// according to the specified format (human or csv). Defaults to human format.
func Format(data interface{}, format ...string) string {
	// Default to human format if not specified
	outputFormat := FormatHuman
	if len(format) > 0 && format[0] != "" {
		outputFormat = format[0]
	}

	// Type switch to determine which format function to use
	switch v := data.(type) {
	case *cticlient.CTIBehavior:
		return FormatCTIBehavior(v, outputFormat)
	case []*cticlient.CTIBehavior:
		return FormatCTIBehaviors(v, outputFormat)
	case cticlient.CTIClassification:
		return FormatCTIClassification(v, outputFormat)
	case []cticlient.CTIClassification:
		return FormatCTIClassifications(v, outputFormat)
	case cticlient.CTIReferences:
		return FormatCTIReference(v, outputFormat)
	case []cticlient.CTIReferences:
		return FormatCTIReferences(v, outputFormat)
	case *cticlient.CTIAttackDetails:
		return FormatCTIAttackDetails(v, outputFormat)
	case []*cticlient.CTIAttackDetails:
		return FormatCTIAttackDetailsSlice(v, outputFormat)
	case cticlient.CTIHistory:
		return FormatCTIHistory(v, outputFormat)
	case cticlient.CTILocationInfo:
		return FormatCTILocationInfo(v, outputFormat)
	case cticlient.CTIScore:
		return FormatCTIScore(v, outputFormat)
	case cticlient.CTIScores:
		return FormatCTIScores(v, outputFormat)
	case []string:
		return FormatCVEs(v, outputFormat)
	case map[string]int:
		return FormatTargetCountries(v, outputFormat)
	case *string:
		return strOrNA(v)
	case string:
		if v == "" {
			return "N/A"
		}
		return v
	case nil:
		return "N/A"
	default:
		// Fallback to string representation
		return fmt.Sprintf("%v", v)
	}
}

// FormatCTIBehavior formats a CTIBehavior for display
func FormatCTIBehavior(b *cticlient.CTIBehavior, format string) string {
	if b == nil {
		return "N/A"
	}

	switch format {
	case FormatCSV:
		return b.Label
	default:
		return b.Label
	}
}

// FormatCTIBehaviors formats multiple CTIBehaviors for display
func FormatCTIBehaviors(behaviors []*cticlient.CTIBehavior, format string) string {
	if len(behaviors) == 0 {
		return "N/A"
	}

	labels := make([]string, len(behaviors))
	for i, b := range behaviors {
		labels[i] = FormatCTIBehavior(b, format)
	}

	switch format {
	case FormatCSV:
		return strings.Join(labels, ", ")
	default:
		return strings.Join(labels, ", ")
	}
}

// FormatCTIClassification formats a CTIClassification for display
func FormatCTIClassification(c cticlient.CTIClassification, format string) string {
	switch format {
	case FormatCSV:
		return c.Label
	default:
		return c.Label
	}
}

// FormatCTIClassifications formats multiple CTIClassifications for display
func FormatCTIClassifications(classifications []cticlient.CTIClassification, format string) string {
	if len(classifications) == 0 {
		return "N/A"
	}

	labels := make([]string, len(classifications))
	for i, c := range classifications {
		labels[i] = FormatCTIClassification(c, format)
	}

	switch format {
	case FormatCSV:
		return strings.Join(labels, ", ")
	default:
		return strings.Join(labels, ", ")
	}
}

// FormatCTIReference formats a CTIReferences for display
func FormatCTIReference(r cticlient.CTIReferences, format string) string {
	switch format {
	case FormatCSV:
		return r.Label
	default:
		return r.Label
	}
}

// FormatCTIReferences formats multiple CTIReferences for display
func FormatCTIReferences(references []cticlient.CTIReferences, format string) string {
	if len(references) == 0 {
		return "N/A"
	}

	labels := make([]string, len(references))
	for i, r := range references {
		labels[i] = FormatCTIReference(r, format)
	}

	switch format {
	case FormatCSV:
		return strings.Join(labels, ", ")
	default:
		return strings.Join(labels, ", ")
	}
}

// FormatCTIAttackDetails formats a CTIAttackDetails for display
func FormatCTIAttackDetails(ad *cticlient.CTIAttackDetails, format string) string {
	if ad == nil {
		return "N/A"
	}

	switch format {
	case FormatCSV:
		return ad.Label
	default:
		return fmt.Sprintf("%s: %s", ad.Label, ad.Description)
	}
}

// FormatCTIAttackDetailsSlice formats multiple CTIAttackDetails for display
func FormatCTIAttackDetailsSlice(attackDetails []*cticlient.CTIAttackDetails, format string) string {
	if len(attackDetails) == 0 {
		return "N/A"
	}

	labels := make([]string, len(attackDetails))
	for i, ad := range attackDetails {
		labels[i] = FormatCTIAttackDetails(ad, format)
	}

	switch format {
	case FormatCSV:
		return strings.Join(labels, ", ")
	default:
		return strings.Join(labels, "\n")
	}
}

// FormatCTIHistory formats a CTIHistory for display
func FormatCTIHistory(h cticlient.CTIHistory, format string) string {
	firstSeen := strOrNA(h.FirstSeen)
	lastSeen := strOrNA(h.LastSeen)

	// Remove timezone info if present
	if firstSeen != "N/A" {
		firstSeen = strings.Split(firstSeen, "+")[0]
	}
	if lastSeen != "N/A" {
		lastSeen = strings.Split(lastSeen, "+")[0]
	}

	switch format {
	case FormatCSV:
		return fmt.Sprintf("%s,%s", firstSeen, lastSeen)
	default:
		return fmt.Sprintf("First seen: %s, Last seen: %s (Age: %d days)", firstSeen, lastSeen, h.DaysAge)
	}
}

// FormatCTILocationInfo formats a CTILocationInfo for display
func FormatCTILocationInfo(loc cticlient.CTILocationInfo, format string) string {
	country := strOrNA(loc.Country)
	city := strOrNA(loc.City)

	switch format {
	case FormatCSV:
		if city != "N/A" {
			return fmt.Sprintf("%s, %s", city, country)
		}
		return country
	default:
		if city != "N/A" {
			return fmt.Sprintf("%s, %s", city, country)
		}
		return country
	}
}

// FormatCTIScore formats a CTIScore for display
func FormatCTIScore(score cticlient.CTIScore, format string) string {
	switch format {
	case FormatCSV:
		return fmt.Sprintf("%d", score.Total)
	default:
		return fmt.Sprintf("Total: %d (Aggressiveness: %d, Threat: %d, Trust: %d, Anomaly: %d)",
			score.Total, score.Aggressiveness, score.Threat, score.Trust, score.Anomaly)
	}
}

// FormatCTIScores formats a CTIScores for display
func FormatCTIScores(scores cticlient.CTIScores, format string) string {
	switch format {
	case FormatCSV:
		return fmt.Sprintf("%d,%d,%d,%d",
			scores.Overall.Total, scores.LastDay.Total, scores.LastWeek.Total, scores.LastMonth.Total)
	default:
		return fmt.Sprintf("Overall: %d, Last Day: %d, Last Week: %d, Last Month: %d",
			scores.Overall.Total, scores.LastDay.Total, scores.LastWeek.Total, scores.LastMonth.Total)
	}
}

// FormatCVEs formats CVEs for display
func FormatCVEs(cves []string, format string) string {
	if len(cves) == 0 {
		return "N/A"
	}

	switch format {
	case FormatCSV:
		return strings.Join(cves, ", ")
	default:
		return strings.Join(cves, ", ")
	}
}

// FormatTargetCountries formats target countries map for display
func FormatTargetCountries(countries map[string]int, format string) string {
	if len(countries) == 0 {
		return "N/A"
	}

	switch format {
	case FormatCSV:
		parts := make([]string, 0, len(countries))
		for country, count := range countries {
			parts = append(parts, fmt.Sprintf("%s:%d", country, count))
		}
		return strings.Join(parts, "; ")
	default:
		parts := make([]string, 0, len(countries))
		for country, count := range countries {
			parts = append(parts, fmt.Sprintf("%s (%d%%)", country, count))
		}
		return strings.Join(parts, ", ")
	}
}
