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
