package registry

import (
	"context"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/aisalamdag23/clean-architecture-template/internal/handler/healthcheck"
	dbstorage "github.com/aisalamdag23/clean-architecture-template/internal/storage/db"
	"github.com/aisalamdag23/clean-architecture-template/internal/usecase/email"

	"github.com/aisalamdag23/clean-architecture-template/pkg/infrastructure/protocol/jwtparser"

	"github.com/jmoiron/sqlx"

	"github.com/aisalamdag23/clean-architecture-template/internal/handler"
	userhttp "github.com/aisalamdag23/clean-architecture-template/internal/handler/user/v1"
	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/config"
	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/logger"
	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/sql"
	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/sql/mysql"
	userdb "github.com/aisalamdag23/clean-architecture-template/internal/storage/db/user"
	usersvc "github.com/aisalamdag23/clean-architecture-template/internal/usecase/user"
)

// Registry is the factory that creates all the "feature servers"
type Registry struct {
	cfg  *config.Config
	db   *sqlx.DB
	mail *email.Service
}

// Init instantiates the registry for API
// - creates database connection pool
func Init(ctx context.Context, cfg *config.Config) *Registry {
	registry := &Registry{cfg: cfg}

	// create a connection to db
	db, err := registry.createDB()
	if err != nil {
		logger.Extract(ctx).Fatal(err.Error())
	}

	registry.db = db

	registry.mail = email.NewEmailService(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.Username, cfg.SMTP.Password, cfg.SMTP.From)

	return registry
}

// CreateUserServer ...
func (r *Registry) CreateUserServer(jwt jwtparser.JwtParser) handler.Handler {
	repository := userdb.NewRepository(r.db)
	frontEndURL := r.cfg.General.FrontendURL
	loginExp := r.cfg.General.LoginExpiry
	rememberExp := r.cfg.General.RememberMeExpiry
	svc := usersvc.NewService(repository, jwt, frontEndURL, loginExp, rememberExp)
	return userhttp.NewServer(svc, r.mail)
}

func (r *Registry) CreateJwtParser() (jwt *jwtparser.JwtParser, err error) {
	publicKeys := map[string][]byte{}
	for _, verifyKey := range r.cfg.Security.VerifyKeys {
		var publicKey []byte
		if verifyKey.VerifyKeyPath != "" {
			publicKey, err = ioutil.ReadFile(verifyKey.VerifyKeyPath)
			if err != nil {
				return nil, err
			}
		} else {
			publicKey = []byte(verifyKey.VerifyKey)
		}
		publicKeys[verifyKey.IssuerName] = publicKey
	}

	var privateKey []byte
	if r.cfg.Security.SigningKeyPath != "" {
		privateKey, err = ioutil.ReadFile(r.cfg.Security.SigningKeyPath)
		if err != nil {
			return nil, err
		}
	} else {
		privateKey = []byte(r.cfg.Security.SigningKey)
	}

	jwt, err = jwtparser.NewJWTParser(r.cfg.Security.SignName, publicKeys, privateKey)
	if err != nil {
		return nil, err
	}
	return jwt, nil
}

func (r *Registry) CreateHealthCheckServer() handler.Handler {
	hc := healthcheck.NewHealthCheck(r.cfg.General.AppName, r.cfg.CommitHash, r.cfg.Tag)
	hc.RegisterService("db", dbstorage.HealthCheck(r.db))
	return hc
}

func (r *Registry) createDB() (*sqlx.DB, error) {
	dsnFactory := mysql.NewDSNFactory()
	dsn := dsnFactory.Create(
		r.cfg.DB.Protocol,
		r.cfg.DB.Credentials.Host,
		r.cfg.DB.Credentials.DBName,
		r.cfg.DB.Credentials.User,
		r.cfg.DB.Credentials.Pass,
		r.cfg.DB.ReadTimeoutSec,
		r.cfg.DB.WriteTimeoutSec,
	)

	connMaxLifetime, err := time.ParseDuration(fmt.Sprintf("%ds", r.cfg.DB.ConnLifetimeSec))
	if err != nil {
		return nil, err
	}

	dbFactory := sql.NewDBFactory()
	return dbFactory.Create(
		r.cfg.DB.Driver,
		dsn,
		r.cfg.DB.MaxOpenConn,
		connMaxLifetime,
	)
}
