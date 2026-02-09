package pdf

import (
	"github.com/johnfercher/maroto/v2/pkg/core"
)

// Page dimensions for A4 in mm (default Maroto page size)
const (
	PageHeight   = 297.0 // A4 height in mm
	PageWidth    = 210.0 // A4 width in mm
	TopMargin    = 10.0
	BottomMargin = 10.0
	LeftMargin   = 10.0
	RightMargin  = 10.0

	// Reserve space for page number footer
	FooterHeight = 10.0

	// Usable height per page
	UsableHeight = PageHeight - TopMargin - BottomMargin - FooterHeight
)

// LayoutManager tracks vertical position and handles page breaks
type LayoutManager struct {
	maroto   core.Maroto
	cursorY  float64 // Current Y position on the page
	pageNum  int     // Current page number
}

// NewLayoutManager creates a new layout manager
func NewLayoutManager(m core.Maroto) *LayoutManager {
	return &LayoutManager{
		maroto:  m,
		cursorY: 0,
		pageNum: 1,
	}
}

// Remaining returns the remaining vertical space on the current page
func (l *LayoutManager) Remaining() float64 {
	return UsableHeight - l.cursorY
}

// AddRow adds a row and tracks vertical position
func (l *LayoutManager) AddRow(height float64, cols ...core.Col) {
	l.maroto.AddRow(height, cols...)
	l.cursorY += height
}

// AddSpacer adds vertical spacing
func (l *LayoutManager) AddSpacer(height float64) {
	l.maroto.AddRow(height)
	l.cursorY += height
}

// AddRowDirect adds a row without cols (for lines/separators) and tracks position
func (l *LayoutManager) AddRowDirect(height float64, cols ...core.Col) {
	l.maroto.AddRow(height, cols...)
	l.cursorY += height
}

// EnsureSpace checks if there's enough space for content, forces page break if not
// Returns true if a new page was started
func (l *LayoutManager) EnsureSpace(minHeight float64) bool {
	if l.Remaining() < minHeight {
		l.NewPage()
		return true
	}
	return false
}

// NewPage resets cursor tracking for a new page
// Maroto handles actual page breaks automatically when content overflows
func (l *LayoutManager) NewPage() {
	l.cursorY = 0
	l.pageNum++
}

// GetMaroto returns the underlying maroto instance for direct access when needed
func (l *LayoutManager) GetMaroto() core.Maroto {
	return l.maroto
}

// ResetCursor resets cursor to top of page (use after manual page operations)
func (l *LayoutManager) ResetCursor() {
	l.cursorY = 0
}

// Block represents a renderable content block with known dimensions
type Block interface {
	// MinHeight returns the minimum height needed (title + first few items)
	MinHeight() float64
	// Height returns the full height if rendered without splitting
	Height() float64
	// Render draws the block, handling page breaks internally if needed
	Render(l *LayoutManager)
}

// SectionBlock represents a section with title and content
type SectionBlock struct {
	Title       string
	TitleHeight float64
	Items       []BlockItem
	ItemHeight  float64
	MinItems    int // Minimum items to show with title (prevents orphans)
	RenderTitle func(l *LayoutManager, title string, continued bool)
	RenderItem  func(l *LayoutManager, item BlockItem, index int)
}

// BlockItem represents a single item in a section
type BlockItem struct {
	Label   string
	Value   int
	Percent float64
	Extra   string // For additional context like AS name
}

// MinHeight returns minimum height (title + MinItems items)
func (s *SectionBlock) MinHeight() float64 {
	itemCount := min(s.MinItems, len(s.Items))
	return s.TitleHeight + (float64(itemCount) * s.ItemHeight)
}

// Height returns full height
func (s *SectionBlock) Height() float64 {
	return s.TitleHeight + (float64(len(s.Items)) * s.ItemHeight)
}

// Render draws the section with proper page break handling
func (s *SectionBlock) Render(l *LayoutManager) {
	if len(s.Items) == 0 {
		return
	}

	// Ensure we have space for title + minimum items
	l.EnsureSpace(s.MinHeight())

	// Render title
	s.RenderTitle(l, s.Title, false)

	// Render items with page break handling
	for i, item := range s.Items {
		// Check if we need a page break
		if l.Remaining() < s.ItemHeight {
			l.NewPage()
			// Re-render title with "(continued)" suffix
			s.RenderTitle(l, s.Title, true)
		}
		s.RenderItem(l, item, i)
	}
}

// ChartBlock represents a chart with optional legend
type ChartBlock struct {
	Title        string
	TitleHeight  float64
	ChartHeight  float64
	Description  string
	DescHeight   float64
	RenderFunc   func(l *LayoutManager)
}

// MinHeight returns the minimum height needed
func (c *ChartBlock) MinHeight() float64 {
	return c.TitleHeight + c.DescHeight + c.ChartHeight
}

// Height returns full height (same as min for charts)
func (c *ChartBlock) Height() float64 {
	return c.MinHeight()
}

// Render draws the chart block
func (c *ChartBlock) Render(l *LayoutManager) {
	l.EnsureSpace(c.MinHeight())
	c.RenderFunc(l)
}
