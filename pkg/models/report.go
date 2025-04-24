package models

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

type Report struct {
	ID        uint
	CreatedAt time.Time
	Name      string
	FilePath  string
	IsFile    bool
	IsQuery   bool
	Query     string
	Since     string
	SinceTime time.Time
	IPs       []*cticlient.SmokeItem
	FileHash  string
	Stats     *ReportStats
}

type ReportStats struct {
	NbIPs              int
	TopReputation      map[string]int
	TopBehaviors       map[string]int
	TopClassifications map[string]int
	TopCountries       map[string]int
	TopCVEs            map[string]int
	TopAS              map[string]int
	TopIPRange         map[string]int
	TopBlocklists      map[string]int
	NbUnknownIPs       int
	AverageBNScore     float64
}
