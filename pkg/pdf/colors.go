package pdf

import (
	"github.com/johnfercher/maroto/v2/pkg/props"
)

// CrowdSec brand colors (from logo.svg)
var (
	PurpleDark  = &props.Color{Red: 62, Green: 58, Blue: 120}   // #3e3a78
	PurpleLight = &props.Color{Red: 79, Green: 75, Blue: 154}   // #4f4b9a
	Gold        = &props.Color{Red: 247, Green: 170, Blue: 22}  // #f7aa16
	AlertRed    = &props.Color{Red: 235, Green: 90, Blue: 97}   // #eb5a61
	White       = &props.Color{Red: 255, Green: 255, Blue: 255}
	LightGray   = &props.Color{Red: 240, Green: 240, Blue: 240}
	DarkGray    = &props.Color{Red: 60, Green: 60, Blue: 60}
	Black       = &props.Color{Red: 0, Green: 0, Blue: 0}
)

// ReputationColors maps reputation levels to colors
var ReputationColors = map[string]*props.Color{
	"malicious":  {Red: 245, Green: 91, Blue: 96},   // #F55B60
	"suspicious": {Red: 251, Green: 146, Blue: 60},  // #FB923C
	"known":      {Red: 136, Green: 139, Blue: 206}, // #888BCE
	"safe":       {Red: 113, Green: 229, Blue: 155}, // #71E59B
	"benign":     {Red: 96, Green: 165, Blue: 250},  // #60A5FA
	"unknown":    {Red: 128, Green: 128, Blue: 128}, // Gray
}

// GetReputationColor returns the color for a reputation level
func GetReputationColor(reputation string) *props.Color {
	if color, ok := ReputationColors[reputation]; ok {
		return color
	}
	return ReputationColors["unknown"]
}

// Traffic light colors for risk assessment
var (
	RiskHigh   = &props.Color{Red: 220, Green: 38, Blue: 38}   // Red #DC2626
	RiskMedium = &props.Color{Red: 245, Green: 158, Blue: 11}  // Amber #F59E0B
	RiskLow    = &props.Color{Red: 34, Green: 197, Blue: 94}   // Green #22C55E

	// Lighter versions for backgrounds
	RiskHighBg   = &props.Color{Red: 254, Green: 226, Blue: 226} // Light red #FEE2E2
	RiskMediumBg = &props.Color{Red: 254, Green: 243, Blue: 199} // Light amber #FEF3C7
	RiskLowBg    = &props.Color{Red: 220, Green: 252, Blue: 231} // Light green #DCFCE7
)

// RiskLevel represents the overall risk assessment
type RiskLevel int

const (
	RiskLevelLow RiskLevel = iota
	RiskLevelMedium
	RiskLevelHigh
)

// GetRiskLevel determines the risk level based on malicious IP percentage
func GetRiskLevel(maliciousPercent float64) RiskLevel {
	if maliciousPercent >= 30 {
		return RiskLevelHigh
	}
	if maliciousPercent >= 10 {
		return RiskLevelMedium
	}
	return RiskLevelLow
}

// GetRiskColor returns the appropriate color for a risk level
func GetRiskColor(level RiskLevel) *props.Color {
	switch level {
	case RiskLevelHigh:
		return RiskHigh
	case RiskLevelMedium:
		return RiskMedium
	default:
		return RiskLow
	}
}

// GetRiskBgColor returns the background color for a risk level
func GetRiskBgColor(level RiskLevel) *props.Color {
	switch level {
	case RiskLevelHigh:
		return RiskHighBg
	case RiskLevelMedium:
		return RiskMediumBg
	default:
		return RiskLowBg
	}
}

// GetRiskLabel returns a human-readable label for the risk level
func GetRiskLabel(level RiskLevel) string {
	switch level {
	case RiskLevelHigh:
		return "HIGH RISK"
	case RiskLevelMedium:
		return "MEDIUM RISK"
	default:
		return "LOW RISK"
	}
}
