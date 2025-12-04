package database

import (
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Client struct {
	IP     *IPClient
	Report *ReportClient
}

func NewClient(sqliteDBPath string) (*Client, error) {
	client := &Client{}
	db, err := gorm.Open(sqlite.Open(sqliteDBPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return client, err
	}

	client.IP, err = NewIPClient(db)
	if err != nil {
		return client, err
	}
	client.Report, err = NewReportClient(db)
	if err != nil {
		return client, err
	}

	return client, nil
}
