package cti

import (
	"fmt"
	"net/http"
	"time"

	"github.com/crowdsecurity/ipdex/pkg/database"
	"github.com/crowdsecurity/ipdex/pkg/version"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

const (
	baseURL    = "https://cti.api.crowdsec.net/v2"
	searchPath = "/smoke/search"
	timeout    = 10 * time.Second
)

var (
	UserAgent = fmt.Sprintf("ipdex-%s", version.String())
)

type CTI struct {
	apiKey     string
	client     CrowdsecClient
	db         *database.IPClient
	httpClient *http.Client
}

type CrowdsecClient interface {
	GetIPInfo(ip string) (*cticlient.SmokeItem, error)
	SearchIPs(ipAddrs []string) (*cticlient.SearchIPResponse, error)
}

func NewCTIClient(apiKey string, dbClient database.IPClient) (*CTI, error) {
	client := cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey(apiKey), cticlient.WithUserAgent(UserAgent))

	return &CTI{
		apiKey: apiKey,
		client: client,
		db:     &dbClient,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (c *CTI) EnrichBatch(ipAddrs []string, forceRefresh bool) ([]*cticlient.SmokeItem, error) {
	var data []*cticlient.SmokeItem

	// Check if the IPs are in the database, and remove them from the list if they are
	for i := 0; i < len(ipAddrs); {
		item, err := c.db.Find(ipAddrs[i])
		if err != nil {
			continue
		}
		if item != nil && !forceRefresh {
			data = append(data, item)
			ipAddrs = append(ipAddrs[:i], ipAddrs[i+1:]...)
		} else {
			i++
		}
	}

	ipRestCache := make(map[string]bool)

	// Check the remaining IPs in the list
	items, err := c.client.SearchIPs(ipAddrs)
	if err != nil {
		return nil, err
	}

	for _, item := range items.Items {
		data = append(data, &item)
		if item.Ip != "" {
			ipRestCache[item.Ip] = true
		}
	}

	// Account for missing IPs
	for _, ip := range ipAddrs {
		if _, ok := ipRestCache[ip]; !ok {
			data = append(data, &cticlient.SmokeItem{Ip: ip})
		}
	}
	return data, nil
}

func (c *CTI) Enrich(ipAddr string, forceRefresh bool) (*cticlient.SmokeItem, bool, error) {
	var data *cticlient.SmokeItem
	var err error
	data, err = c.db.Find(ipAddr)
	if err != nil && !forceRefresh { // dont exit if there is an err to find in DB but we want to refresh
		return nil, false, err
	}

	// exist in cache
	if data != nil && !forceRefresh {
		return data, true, nil
	}
	data, err = c.client.GetIPInfo(ipAddr)
	if err != nil {
		return data, false, err
	}
	found := true
	// If IP is not found, the IP field is be empty
	if data.Ip == "" {
		data.Ip = ipAddr
		found = false
	}

	return data, found, nil
}
