package pdf

import (
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/props"
)

// Typography sizes
const (
	FontSizeTitle      = 24.0 // Main document title
	FontSizeH1         = 14.0 // Section headings
	FontSizeH2         = 11.0 // Subsection headings
	FontSizeBody       = 10.0 // Regular body text
	FontSizeSmall      = 9.0  // Secondary text, bullets
	FontSizeXSmall     = 8.0  // Table cells, legends
	FontSizeTiny       = 7.0  // Fine print, table data
	FontSizeFooter     = 8.0  // Footer text
)

// Row heights (consistent spacing)
const (
	RowHeightTitle     = 30.0 // Main header row
	RowHeightH1        = 10.0 // Section heading
	RowHeightH2        = 8.0  // Subsection heading
	RowHeightBody      = 6.0  // Body text row
	RowHeightTableRow  = 6.0  // Table data row
	RowHeightTableHead = 7.0  // Table header row
	RowHeightChart     = 60.0 // Chart with legend
	RowHeightBarChart  = 50.0 // Bar chart
	RowHeightSpacer    = 5.0  // Standard spacer
	RowHeightSpacerLg  = 8.0  // Large spacer between sections
	RowHeightSpacerXl  = 10.0 // Extra large spacer
	RowHeightDesc      = 4.0  // Description/subtitle row
)

// Minimum items to show with a section title (prevents orphan headings)
const (
	MinListItems = 3
)

// Text style presets
var (
	// Headings
	StyleTitle = props.Text{
		Size:  FontSizeTitle,
		Style: fontstyle.Bold,
		Color: PurpleDark,
	}

	StyleH1 = props.Text{
		Size:  FontSizeH1,
		Style: fontstyle.Bold,
		Color: PurpleDark,
	}

	StyleH2 = props.Text{
		Size:  FontSizeH2,
		Style: fontstyle.Bold,
		Color: DarkGray,
	}

	StyleH2Continued = props.Text{
		Size:  FontSizeH2,
		Style: fontstyle.Bold,
		Color: DarkGray,
	}

	// Body text
	StyleBody = props.Text{
		Size:  FontSizeBody,
		Color: DarkGray,
	}

	StyleBodyBold = props.Text{
		Size:  FontSizeBody,
		Style: fontstyle.Bold,
		Color: Black,
	}

	StyleSmall = props.Text{
		Size:  FontSizeSmall,
		Color: DarkGray,
	}

	StyleSmallItalic = props.Text{
		Size:  FontSizeSmall,
		Color: DarkGray,
		Style: fontstyle.Italic,
	}

	StyleXSmall = props.Text{
		Size:  FontSizeXSmall,
		Color: DarkGray,
	}

	// Table styles
	StyleTableHeader = props.Text{
		Size:  FontSizeXSmall,
		Style: fontstyle.Bold,
		Color: White,
		Align: align.Center,
	}

	StyleTableCell = props.Text{
		Size:  FontSizeTiny,
		Color: DarkGray,
	}

	StyleTableCellRight = props.Text{
		Size:  FontSizeTiny,
		Color: DarkGray,
		Align: align.Right,
	}

	// Labels and values
	StyleLabel = props.Text{
		Size:  FontSizeBody,
		Color: DarkGray,
	}

	StyleValue = props.Text{
		Size:  FontSizeBody,
		Style: fontstyle.Bold,
		Color: Black,
	}

	StyleValueRight = props.Text{
		Size:  FontSizeSmall,
		Color: DarkGray,
		Align: align.Right,
	}

	// Footer
	StyleFooter = props.Text{
		Size:  FontSizeFooter,
		Color: DarkGray,
	}

	StyleFooterLink = props.Text{
		Size:  FontSizeFooter,
		Color: PurpleDark,
		Align: align.Right,
	}

	// Descriptions
	StyleDescription = props.Text{
		Size:  FontSizeXSmall,
		Color: DarkGray,
	}

	// Glossary styles
	StyleGlossaryTerm = props.Text{
		Size:  FontSizeXSmall,
		Style: fontstyle.Bold,
		Color: DarkGray,
	}

	StyleGlossaryDef = props.Text{
		Size:  FontSizeTiny,
		Color: DarkGray,
	}
)

// Cell style presets
var (
	CellStyleHeader = props.Cell{
		BackgroundColor: PurpleLight,
	}

	CellStyleAltRow = props.Cell{
		BackgroundColor: LightGray,
	}

	CellStyleWhite = props.Cell{
		BackgroundColor: White,
	}
)

// WithTop returns a copy of the text props with a Top offset
func WithTop(p props.Text, top float64) props.Text {
	p.Top = top
	return p
}

// WithLeft returns a copy of the text props with a Left offset
func WithLeft(p props.Text, left float64) props.Text {
	p.Left = left
	return p
}

// WithColor returns a copy of the text props with a different color
func WithColor(p props.Text, color *props.Color) props.Text {
	p.Color = color
	return p
}

// WithAlign returns a copy of the text props with alignment
func WithAlign(p props.Text, a align.Type) props.Text {
	p.Align = a
	return p
}
