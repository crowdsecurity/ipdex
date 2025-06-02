package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	ipExpiration = 48 * time.Hour
)

type IPClient struct {
	db *gorm.DB
}

type IP struct {
	gorm.Model
	Value   string `gorm:"uniqueIndex"`
	CtiData string
	Reports []Report `gorm:"many2many:report_ips;"`
}

func NewIPClient(db *gorm.DB) (*IPClient, error) {
	if err := db.AutoMigrate(&IP{}); err != nil {
		return nil, err
	}

	return &IPClient{
		db: db,
	}, nil
}

func (i *IPClient) Create(ipAddr string, ctiData *cticlient.SmokeItem) (*IP, error) {
	// check if the IP exist and is not expired
	record := &IP{}
	currentTime := time.Now()
	expirationDate := currentTime.Add(-ipExpiration)
	result := i.db.Preload("Reports").First(&record, "value = ? AND created_at > ?", ipAddr, expirationDate)
	if result.Error != nil {
		if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, result.Error
		}
	} else {
		// don't create entry if the IP already exists and is not expired
		return record, nil
	}

	data, err := json.Marshal(ctiData)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal cti data: %s", err.Error())
	}
	ipRecord := &IP{Value: ipAddr, CtiData: string(data)}
	result = i.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "value"}}, // Conflict on 'value' column
		DoUpdates: clause.Assignments(map[string]interface{}{"cti_data": ipRecord.CtiData, "updated_at": gorm.Expr("CURRENT_TIMESTAMP")}),
	}).Create(&ipRecord)
	if result.Error != nil {
		return nil, result.Error
	}
	return ipRecord, nil
}

func (i *IPClient) CreateBatch(ips []*cticlient.SmokeItem) ([]IP, error) {
	ret := make([]IP, 0)
	for _, ip := range ips {
		data, err := json.Marshal(ip)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal cti data: %s", err.Error())
		}
		record := IP{Value: ip.Ip, CtiData: string(data)}
		ret = append(ret, record)
		result := i.db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "value"}}, // Conflict on 'value' column
			DoUpdates: clause.Assignments(map[string]interface{}{"cti_data": record.CtiData, "updated_at": gorm.Expr("CURRENT_TIMESTAMP")}),
		}).Create(&record)
		ret = append(ret, record)
		if result.Error != nil {
			return ret, result.Error
		}
	}
	return ret, nil
}

func (i *IPClient) Find(ipAddr string) (*cticlient.SmokeItem, error) {
	var data IP
	result := i.db.Preload("Reports").First(&data, "value = ?", ipAddr)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	var ctiData cticlient.SmokeItem
	if err := json.Unmarshal([]byte(data.CtiData), &ctiData); err != nil {
		return nil, err
	}

	return &ctiData, nil
}

func (i *IPClient) GetLastRefresh(value string) (time.Time, error) {
	var ip IP
	result := i.db.Where("value = ?", value).First(&ip)
	if result.Error != nil {
		return time.Time{}, result.Error
	}
	return ip.UpdatedAt, nil
}
