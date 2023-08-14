package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/mysql"
	_ "github.com/golang-migrate/migrate/source/file"

	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/config"
	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/logger"
	mysqldsn "github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/sql/mysql"
)

var (
	// CommitHash will be set at compile time with current git commit
	CommitHash string
	// Tag will be set at compile time with current branch or tag
	Tag string
)

func main() {
	if err := run(CommitHash, Tag); err != nil {
		log.Fatalln(err)
	}
}

func run(commitHash string, tag string) error {
	cfg, err := config.Load(commitHash, tag)
	if err != nil {
		return fmt.Errorf("unable to load configurations: '%v'", err)
	}

	lgr := logger.NewLogger(cfg.General.LogLevel)

	lgr.Info(fmt.Sprintf("Migrations based on commit %s, tag %s", commitHash, tag))

	db, err := createDB(cfg)
	if err != nil {
		return fmt.Errorf("unable to create DB: '%v'", err)
	}
	driver, _ := mysql.WithInstance(db, &mysql.Config{})
	m, err := migrate.NewWithDatabaseInstance("file://db/migrations", cfg.DB.Driver, driver)
	if err != nil {
		return fmt.Errorf("unable to create migration instance: '%v'", err)
	}

	if len(os.Args) >= 1 && os.Args[1] == "down" {
		err = m.Down()
	} else {
		err = m.Up()
	}
	if err != nil {
		if err.Error() != "no change" {
			return err
		}
		lgr.Warn("No changes")
	}

	lgr.Info("Migration completed successfully")

	return nil
}

func createDB(cfg *config.Config) (*sql.DB, error) {
	dsnFactory := mysqldsn.NewDSNFactory()
	dsn := dsnFactory.Create(
		cfg.DB.Protocol,
		cfg.DB.Credentials.Host,
		cfg.DB.Credentials.DBName,
		cfg.DB.Credentials.User,
		cfg.DB.Credentials.Pass,
		cfg.DB.ReadTimeoutSec,
		cfg.DB.WriteTimeoutSec,
	)

	connMaxLifetime, err := time.ParseDuration(fmt.Sprintf("%ds", cfg.DB.ConnLifetimeSec))
	if err != nil {
		return nil, err
	}

	db, err := sql.Open(cfg.DB.Driver, dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(cfg.DB.MaxOpenConn)
	db.SetConnMaxLifetime(connMaxLifetime)

	return db, nil
}
