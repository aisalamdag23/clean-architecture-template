package sql

import (
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

// DBFactory sqlx.DB factory
type DBFactory struct{}

// NewDBFactory ...
func NewDBFactory() *DBFactory {
	return &DBFactory{}
}

// Create creates sqlx.DB instance
func (f DBFactory) Create(driverName, dsn string, maxOpenConn int, connMaxLifetime time.Duration) (*sqlx.DB, error) {
	db, err := sqlx.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(maxOpenConn)
	db.SetConnMaxLifetime(connMaxLifetime)

	return db, nil
}
