package pdf

import (
	"testing"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/config"
)

func TestLayoutManager_EnsureSpace(t *testing.T) {
	tests := []struct {
		name           string
		cursorY        float64
		minHeight      float64
		expectNewPage  bool
	}{
		{
			name:          "enough space available",
			cursorY:       50,
			minHeight:     100,
			expectNewPage: false,
		},
		{
			name:          "not enough space - need new page",
			cursorY:       UsableHeight - 50,
			minHeight:     100,
			expectNewPage: true,
		},
		{
			name:          "exact fit",
			cursorY:       UsableHeight - 100,
			minHeight:     100,
			expectNewPage: false,
		},
		{
			name:          "at page boundary",
			cursorY:       UsableHeight,
			minHeight:     10,
			expectNewPage: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewBuilder().Build()
			m := maroto.New(cfg)
			lm := NewLayoutManager(m)
			lm.cursorY = tt.cursorY

			newPage := lm.EnsureSpace(tt.minHeight)
			if newPage != tt.expectNewPage {
				t.Errorf("EnsureSpace(%f) with cursorY=%f: got newPage=%v, want %v",
					tt.minHeight, tt.cursorY, newPage, tt.expectNewPage)
			}
		})
	}
}

func TestLayoutManager_Remaining(t *testing.T) {
	cfg := config.NewBuilder().Build()
	m := maroto.New(cfg)
	lm := NewLayoutManager(m)

	// Initially should have full usable height
	if got := lm.Remaining(); got != UsableHeight {
		t.Errorf("Remaining() at start = %f, want %f", got, UsableHeight)
	}

	// After adding a row, remaining should decrease
	lm.AddSpacer(50)
	expected := UsableHeight - 50
	if got := lm.Remaining(); got != expected {
		t.Errorf("Remaining() after 50pt spacer = %f, want %f", got, expected)
	}
}

func TestLayoutManager_NewPage(t *testing.T) {
	cfg := config.NewBuilder().Build()
	m := maroto.New(cfg)
	lm := NewLayoutManager(m)

	// Add some content
	lm.AddSpacer(100)
	if lm.cursorY != 100 {
		t.Errorf("cursorY after spacer = %f, want 100", lm.cursorY)
	}

	// Force new page
	lm.NewPage()
	if lm.cursorY != 0 {
		t.Errorf("cursorY after NewPage = %f, want 0", lm.cursorY)
	}
	if lm.pageNum != 2 {
		t.Errorf("pageNum after NewPage = %d, want 2", lm.pageNum)
	}
}

func TestSectionBlock_MinHeight(t *testing.T) {
	tests := []struct {
		name       string
		titleH     float64
		itemH      float64
		minItems   int
		itemCount  int
		wantHeight float64
	}{
		{
			name:       "more items than minimum",
			titleH:     10,
			itemH:      5,
			minItems:   3,
			itemCount:  10,
			wantHeight: 10 + (5 * 3), // title + 3 items
		},
		{
			name:       "fewer items than minimum",
			titleH:     10,
			itemH:      5,
			minItems:   3,
			itemCount:  2,
			wantHeight: 10 + (5 * 2), // title + 2 items (all available)
		},
		{
			name:       "exactly minimum items",
			titleH:     10,
			itemH:      5,
			minItems:   3,
			itemCount:  3,
			wantHeight: 10 + (5 * 3),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := make([]BlockItem, tt.itemCount)
			block := &SectionBlock{
				TitleHeight: tt.titleH,
				ItemHeight:  tt.itemH,
				MinItems:    tt.minItems,
				Items:       items,
			}

			if got := block.MinHeight(); got != tt.wantHeight {
				t.Errorf("MinHeight() = %f, want %f", got, tt.wantHeight)
			}
		})
	}
}

func TestSectionBlock_Height(t *testing.T) {
	items := make([]BlockItem, 5)
	block := &SectionBlock{
		TitleHeight: 10,
		ItemHeight:  6,
		Items:       items,
	}

	want := 10.0 + (6.0 * 5) // title + all 5 items
	if got := block.Height(); got != want {
		t.Errorf("Height() = %f, want %f", got, want)
	}
}

func TestPageDimensions(t *testing.T) {
	// Verify constants are reasonable for A4
	if PageHeight != 297 {
		t.Errorf("PageHeight = %f, want 297 (A4)", PageHeight)
	}
	if PageWidth != 210 {
		t.Errorf("PageWidth = %f, want 210 (A4)", PageWidth)
	}

	// Verify usable height calculation
	expectedUsable := PageHeight - TopMargin - BottomMargin - FooterHeight
	if UsableHeight != expectedUsable {
		t.Errorf("UsableHeight = %f, want %f", UsableHeight, expectedUsable)
	}
}
