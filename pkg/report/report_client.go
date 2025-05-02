package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/crowdsecurity/ipdex/cmd/ipdex/style"
	"github.com/crowdsecurity/ipdex/pkg/database"
	"github.com/crowdsecurity/ipdex/pkg/display"
	"github.com/crowdsecurity/ipdex/pkg/models"
	"github.com/crowdsecurity/ipdex/pkg/stats"
	"github.com/crowdsecurity/ipdex/pkg/utils"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

type ReportClient struct {
	reportClient *database.ReportClient
	ipClient     *database.IPClient
}

func NewClient(dbClient *database.Client) *ReportClient {
	return &ReportClient{
		reportClient: dbClient.Report,
		ipClient:     dbClient.IP,
	}
}

func (r *ReportClient) FindById(reportID uint) (*models.Report, error) {
	reportRecord, err := r.reportClient.FindById(reportID)
	if err != nil {
		return nil, err
	}
	if reportRecord == nil {
		return nil, nil
	}
	report, err := dbReportToReport(reportRecord)
	if err != nil {
		return nil, err
	}
	return report, nil
}

func (r *ReportClient) FindByHash(filepath string) (*models.Report, error) {
	reportRecord, err := r.reportClient.FindByHash(filepath)
	if err != nil {
		return nil, err
	}
	if reportRecord == nil {
		return nil, nil
	}

	report, err := dbReportToReport(reportRecord)
	if err != nil {
		return nil, err
	}
	return report, nil
}

func dbReportToReport(report *database.Report) (*models.Report, error) {
	ipList := make([]*cticlient.SmokeItem, 0)
	for _, ip := range report.IPs {
		var ipCTI *cticlient.SmokeItem
		if err := json.Unmarshal([]byte(ip.CtiData), &ipCTI); err != nil {
			return nil, err
		}
		ipList = append(ipList, ipCTI)
	}
	reportStats := models.ReportStats{}
	if report.StatsReport.Stats != "" {
		if err := json.Unmarshal([]byte(report.StatsReport.Stats), &reportStats); err != nil {
			return nil, err
		}
	}

	return &models.Report{
		CreatedAt: report.CreatedAt,
		Name:      report.Name,
		FilePath:  report.FilePath,
		IsFile:    report.IsFile,
		IPs:       ipList,
		ID:        report.ID,
		FileHash:  report.FileHash,
		Stats:     &reportStats,
		IsQuery:   report.IsQuery,
		Query:     report.Query,
		Since:     report.Since,
		SinceTime: report.SinceTime,
	}, nil
}

func (r *ReportClient) FindAll() ([]*models.Report, error) {
	reports, err := r.reportClient.FindAll()
	if err != nil {
		return nil, fmt.Errorf("unable to get reports: %s", err.Error())
	}
	if len(reports) == 0 {
		style.Infof("No reports found.")
		return make([]*models.Report, 0), nil
	}

	ret := make([]*models.Report, 0)
	for _, report := range reports {
		report, err := dbReportToReport(report)
		if err != nil {
			return nil, err
		}
		ret = append(ret, report)
	}

	return ret, nil
}

func (r *ReportClient) CreateOne(ip *cticlient.SmokeItem) (*database.IP, error) {
	return r.ipClient.Create(ip.Ip, ip)
}

func (r *ReportClient) IPLastRefresh(ip string) (time.Time, error) {
	return r.ipClient.GetLastRefresh(ip)
}

func (r *ReportClient) Create(ips []*cticlient.SmokeItem, name string, isFile bool, filePath string, isQuery bool, query string, since string) (*models.Report, error) {
	ipRecords, err := r.ipClient.CreateBatch(ips)
	if err != nil {
		return nil, fmt.Errorf("fail to create batch ips: %s", err.Error())
	}

	stats := stats.GetIPsStats(ips)
	statsStr, err := json.Marshal(stats)
	if err != nil {
		return nil, err
	}
	reportStats := database.ReportStats{
		Stats: string(statsStr),
	}

	var sinceTime time.Time
	if isQuery && since != "" {
		sinceDuration, err := utils.ParseDuration(since)
		if err != nil {
			return nil, fmt.Errorf("can't parse since duration '%s': %s", since, err)
		}
		sinceTime = time.Now().Add(-sinceDuration)
	}

	if name == "" {
		name = utils.GenerateRandomName()
	}

	reportRecord := database.Report{
		Name:        name,
		FilePath:    filePath,
		IsFile:      isFile,
		IPs:         ipRecords,
		StatsReport: reportStats,
		IsQuery:     isQuery,
		Query:       query,
		Since:       since,
		SinceTime:   sinceTime,
	}

	err = r.reportClient.Create(&reportRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to create report: %s", err.Error())
	}

	return &models.Report{
		ID:        reportRecord.ID,
		CreatedAt: reportRecord.CreatedAt,
		Name:      reportRecord.Name,
		FilePath:  reportRecord.FilePath,
		IsFile:    reportRecord.IsFile,
		IPs:       ips,
		FileHash:  reportRecord.FileHash,
		Stats:     stats,
		IsQuery:   reportRecord.IsQuery,
		Query:     reportRecord.Query,
		Since:     reportRecord.Since,
		SinceTime: reportRecord.SinceTime,
	}, nil
}

func (r *ReportClient) GetStats(report *models.Report) *models.ReportStats {
	return stats.GetIPsStats(report.IPs)
}

func (r *ReportClient) GetExpiredIPFromReport(reportID uint) ([]string, error) {
	ret := make([]string, 0)
	expiredIPs, err := r.reportClient.GetExpiredIPsFromReport(reportID)
	if err != nil {
		return nil, err
	}
	for _, ip := range expiredIPs {
		ret = append(ret, ip.Value)
	}
	return ret, nil
}

func (r *ReportClient) Display(report *models.Report, stats *models.ReportStats, outputFormat string, withIPs bool) error {
	displayer := display.NewDisplay()
	return displayer.DisplayReport(report, stats, outputFormat, withIPs)
}

func (r *ReportClient) DeleteExpiredReports(expiration string) error {
	duration, err := utils.ParseDuration(expiration)
	if err != nil {
		return err
	}
	expirationDate := time.Now().Add(-duration)
	if err := r.reportClient.DeleteExpiredSince(expirationDate); err != nil {
		return err
	}
	return nil
}

func (r *ReportClient) Exist(filepath string) (*models.Report, bool, error) {
	reportRecord, exist, err := r.reportClient.FilePathExist(filepath)
	if err != nil {
		return &models.Report{}, false, err
	}
	if !exist {
		return &models.Report{}, false, nil
	}

	ipList := make([]*cticlient.SmokeItem, 0)
	for _, ip := range reportRecord.IPs {
		var ipCTI *cticlient.SmokeItem
		if err := json.Unmarshal([]byte(ip.CtiData), &ipCTI); err != nil {
			return nil, false, err
		}
		ipList = append(ipList, ipCTI)
	}
	reportStats := models.ReportStats{}
	if err := json.Unmarshal([]byte(reportRecord.StatsReport.Stats), &reportStats); err != nil {
		return nil, false, err
	}

	return &models.Report{
		ID:        reportRecord.ID,
		CreatedAt: reportRecord.CreatedAt,
		Name:      reportRecord.Name,
		FilePath:  reportRecord.FilePath,
		IsFile:    reportRecord.IsFile,
		IPs:       ipList,
		FileHash:  reportRecord.FileHash,
		Stats:     &reportStats,
	}, true, nil
}
