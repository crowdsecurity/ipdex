package stats

import (
	"github.com/crowdsecurity/ipdex/pkg/models"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

func GetIPsStats(ips []*cticlient.SmokeItem) *models.ReportStats {
	stats := &models.ReportStats{
		NbIPs:                 0,
		NbUnknownIPs:          0,
		TopReputation:         make(map[string]int, 0),
		TopBehaviors:          make(map[string]int, 0),
		TopClassifications:    make(map[string]int, 0),
		TopCountries:          make(map[string]int, 0),
		TopAS:                 make(map[string]int, 0),
		TopCVEs:               make(map[string]int, 0),
		TopIPRange:            make(map[string]int, 0),
		TopBlocklists:         make(map[string]int, 0),
		AverageBNScore:        0.0,
		IPsBlockedByBlocklist: 0,
	}
	sumBNScore := 0

	for _, ip := range ips {
		stats.NbIPs += 1
		if ip.Reputation == "" {
			stats.NbUnknownIPs += 1
			continue
		}
		sumBNScore += ip.GetBackgroundNoiseScore()

		if _, ok := stats.TopReputation[ip.Reputation]; !ok {
			stats.TopReputation[ip.Reputation] = 0
		}
		stats.TopReputation[ip.Reputation] += 1

		if ip.Location.Country != nil && *ip.Location.Country != "N/A" {
			if _, ok := stats.TopCountries[*ip.Location.Country]; !ok {
				stats.TopCountries[*ip.Location.Country] = 0
			}
			stats.TopCountries[*ip.Location.Country] += 1
		}

		if ip.AsName != nil && *ip.AsName != "N/A" {
			if _, ok := stats.TopAS[*ip.AsName]; !ok {
				stats.TopAS[*ip.AsName] = 0
			}
			stats.TopAS[*ip.AsName] += 1
		}

		if ip.IpRange != nil && *ip.IpRange != "N/A" {
			if _, ok := stats.TopIPRange[*ip.IpRange]; !ok {
				stats.TopIPRange[*ip.IpRange] = 0
			}
			stats.TopIPRange[*ip.IpRange] += 1
		}

		if len(ip.GetBehaviors()) > 0 {
			for _, behavior := range ip.Behaviors {
				if _, ok := stats.TopBehaviors[behavior.Label]; !ok {
					stats.TopBehaviors[behavior.Label] = 0
				}
				stats.TopBehaviors[behavior.Label] += 1
			}
		}

		if len(ip.GetFalsePositives()) > 0 {
			for _, fp := range ip.Classifications.FalsePositives {
				if _, ok := stats.TopClassifications[fp.Label]; !ok {
					stats.TopClassifications[fp.Label] = 0
				}
				stats.TopClassifications[fp.Label] += 1
			}
		}
		if len(ip.GetClassifications()) > 0 {
			for _, classification := range ip.Classifications.Classifications {
				if _, ok := stats.TopClassifications[classification.Label]; !ok {
					stats.TopClassifications[classification.Label] = 0
				}
				stats.TopClassifications[classification.Label] += 1
			}
		}

		if len(ip.References) > 0 {
			for _, blocklist := range ip.References {
				if _, ok := stats.TopBlocklists[blocklist.Label]; !ok {
					stats.TopBlocklists[blocklist.Label] = 0
				}
				stats.TopBlocklists[blocklist.Label] += 1
			}
			stats.IPsBlockedByBlocklist += 1
		}

		if len(ip.CVEs) > 0 {
			for _, cve := range ip.CVEs {
				if _, ok := stats.TopCVEs[cve]; !ok {
					stats.TopCVEs[cve] = 0
				}
				stats.TopCVEs[cve] += 1
			}
		}

	}
	if stats.NbIPs > 0 {
		stats.AverageBNScore = float64(sumBNScore / stats.NbIPs)
	}

	stats.TopReputation["unknown"] = stats.NbUnknownIPs
	stats.TopAS["unknown"] = stats.NbUnknownIPs
	stats.TopCountries["unknown"] = stats.NbUnknownIPs
	stats.TopIPRange["unknown"] = stats.NbUnknownIPs

	return stats
}
