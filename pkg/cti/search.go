package cti

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

type SearchParams struct {
	Since *string `json:"since"`
	Page  *int    `json:"page"`
	Limit *int    `json:"limit"`
	Query *string `json:"query"`
}

type SearchResponse struct {
	Items []*cticlient.SmokeItem `json:"items"`
	Links *Links                 `json:"_links"`
}

type Links struct {
	Self  Link `json:"self"`
	Next  Link `json:"next"`
	Prev  Link `json:"prev"`
	First Link `json:"first"`
}

type Link struct {
	Href string `json:"href"`
}

type SearchPaginator struct {
	client      *CTI
	params      SearchParams
	currentPage int
	done        bool
}

func (c *CTI) doRequest(ctx context.Context, method string, endpoint string, params map[string]string) ([]byte, error) {
	url := baseURL + endpoint
	if len(params) > 0 {
		url += "?"
		for k, v := range params {
			url += fmt.Sprintf("%s=%s&", k, v)
		}
	}
	url = strings.TrimSuffix(url, "&")
	req, err := http.NewRequestWithContext(ctx, method, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden {
			return nil, cticlient.ErrUnauthorized
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, cticlient.ErrLimit
		}

		if resp.StatusCode == http.StatusNotFound {
			return nil, cticlient.ErrNotFound
		}

		return nil, fmt.Errorf("unexpected http code : %s", resp.Status)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return respBody, nil
}

func (c *CTI) Search(params SearchParams) (*SearchResponse, error) {
	ctx := context.TODO()
	paramsMap := make(map[string]string)

	if params.Page != nil {
		paramsMap["page"] = fmt.Sprintf("%d", *params.Page)
	}

	if params.Since != nil {
		paramsMap["since"] = *params.Since
	}

	if params.Limit != nil {
		paramsMap["limit"] = fmt.Sprintf("%d", *params.Limit)
	}

	if params.Query != nil && *params.Query != "" {
		paramsMap["query"] = url.QueryEscape(*params.Query)
	} else {
		return nil, fmt.Errorf("query is required")
	}

	body, err := c.doRequest(ctx, http.MethodGet, searchPath, paramsMap)
	if err != nil {
		return nil, err
	}

	searchResponse := SearchResponse{}

	err = json.Unmarshal(body, &searchResponse)
	if err != nil {
		return nil, err
	}

	return &searchResponse, nil
}

func (p *SearchPaginator) Next() ([]*cticlient.SmokeItem, error) {
	if p.done {
		return nil, nil
	}
	p.params.Page = &p.currentPage
	resp, err := p.client.Search(p.params)
	if err != nil {
		return nil, err
	}
	p.currentPage++
	if resp.Links.Next.Href == "" {
		p.done = true
	}
	return resp.Items, nil
}

func NewSearchPaginator(client *CTI, params SearchParams) *SearchPaginator {
	startPage := 1
	if params.Page != nil {
		startPage = *params.Page
	}
	return &SearchPaginator{
		client:      client,
		params:      params,
		currentPage: startPage,
	}
}
