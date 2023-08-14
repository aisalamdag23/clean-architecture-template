package db

import (
	"context"
	"errors"

	"github.com/jmoiron/sqlx"

	"github.com/aisalamdag23/clean-architecture-template/internal/handler/healthcheck"
)

type dbHealthCheck struct {
	db *sqlx.DB
}

func HealthCheck(db *sqlx.DB) healthcheck.HealthChecker {
	return &dbHealthCheck{db: db}
}

func (c *dbHealthCheck) HealthCheck(context.Context) (interface{}, error) {
	err := c.db.Ping()
	if err != nil {
		return nil, errors.New("ping failed")
	}
	return map[string]interface{}{
		"stats": c.db.Stats(),
	}, nil
}
