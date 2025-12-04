package database

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/crowdsecurity/ipdex/cmd/ipdex/config"
	"gorm.io/gorm"
)

type ReportClient struct {
	db *gorm.DB
}

type Report struct {
	gorm.Model
	Name        string
	FilePath    string
	IsFile      bool
	FileHash    string
	IsQuery     bool
	Query       string
	Since       string
	SinceTime   time.Time
	IPs         []IP        `gorm:"many2many:report_ips;"`
	StatsReport ReportStats `gorm:"constraint:OnDelete:CASCADE;"`
}

type ReportStats struct {
	gorm.Model
	ReportID uint   `gorm:"uniqueIndex"` // ensure one-to-one
	Stats    string `gorm:"type:text"`   // store JSON as string
}

func NewReportClient(db *gorm.DB) (*ReportClient, error) {
	if err := db.AutoMigrate(&Report{}); err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(&ReportStats{}); err != nil {
		return nil, err
	}

	return &ReportClient{
		db: db,
	}, nil
}

func (r *ReportClient) GetExpiredIPsFromReport(reportID uint) ([]*IP, error) {
	var IPs []*IP
	cutoff := time.Now().Add(-ipExpiration)

	err := r.db.
		Joins("JOIN report_ips ON report_ips.ip_id = ips.id").
		Where("report_ips.report_id = ?", reportID).
		Where("ips.updated_at > ?", cutoff).
		Find(&IPs).Error

	if err != nil {
		return nil, fmt.Errorf("unable to fetch IPs: %w", err)
	}
	return IPs, nil
}

func (r *ReportClient) FindById(reportID uint) (*Report, error) {
	var report Report
	result := r.db.Preload("StatsReport").First(&report, reportID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}

	// Load IPs using Association API
	err := r.db.Model(&report).Association("IPs").Find(&report.IPs)
	if err != nil {
		return nil, err
	}

	return &report, nil
}

func (r *ReportClient) FindByHash(filepath string) (*Report, error) {
	var report Report

	hash, err := ComputeFileHash(filepath)
	if err != nil {
		return nil, err
	}

	result := r.db.Preload("StatsReport").Where("file_hash = ?", hash).First(&report)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}

	// Load IPs using Association API
	err = r.db.Model(&report).Association("IPs").Find(&report.IPs)
	if err != nil {
		return nil, err
	}

	return &report, nil
}

func (r *ReportClient) Create(report *Report) error {
	if report.IsFile {
		hash, err := ComputeFileHash(report.FilePath)
		if err != nil {
			return fmt.Errorf("failed to compute file hash: %w", err)
		}
		report.FileHash = hash
	}

	result := r.db.Omit("IPs").Create(report)
	if result.Error != nil {
		return fmt.Errorf("creating report in database failed: %v", result.Error)
	}

	allIPs := report.IPs
	for batch := range slices.Chunk(allIPs, config.BatchSize) {
		report.IPs = batch
		if err := r.db.Model(report).Association("IPs").Append(batch); err != nil {
			return fmt.Errorf("failed to associate IPs with report: %w", err)
		}
	}

	return nil
}

func (r *ReportClient) Find(reportID string) (*Report, error) {
	var report Report
	result := r.db.First(&report, reportID)
	if result.Error != nil {
		return nil, result.Error
	}
	return &report, nil
}

func (r *ReportClient) FindAll() ([]*Report, error) {
	reports := []*Report{}

	// First, get all reports with StatsReport only
	result := r.db.Preload("StatsReport").Find(&reports)
	if result.Error != nil {
		return nil, result.Error
	}

	// Then load IPs using Association API for each report (GORM handles batching internally)
	for _, report := range reports {
		err := r.db.Model(report).Association("IPs").Find(&report.IPs)
		if err != nil {
			return nil, err
		}
	}

	return reports, nil
}

func (r *ReportClient) DeleteExpiredSince(expirationDate time.Time) error {
	var expiredReports []Report
	r.db.Where("created_at < ?", expirationDate).Find(&expiredReports)

	for _, report := range expiredReports {
		err := r.db.Model(&report).Association("IPs").Clear() // remove from join table
		if err != nil {
			return err
		}
		result := r.db.Delete(&report)
		if result.Error != nil {
			return result.Error
		}
	}

	return nil
}

func (r *ReportClient) FilePathExist(filePath string) (*Report, bool, error) {
	var reports []Report
	result := r.db.Model(&Report{}).Where("file_path = ?", filePath).Find(&reports)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, false, nil
		}
		return nil, false, result.Error
	}
	if len(reports) == 0 {
		return nil, false, nil
	}

	// Load IPs using Association API
	err := r.db.Model(&reports[0]).Association("IPs").Find(&reports[0].IPs)
	if err != nil {
		return nil, false, err
	}

	return &reports[0], true, nil
}
