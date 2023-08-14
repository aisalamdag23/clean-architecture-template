package config

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"
	"gopkg.in/yaml.v3"
)

const configPathEnvName = "SPEC_FILE"

type (
	specWithMetaConfig struct {
		Spec Config `yaml:"spec"`
	}

	// Config ...
	Config struct {
		// CommitHash is a git commit hash of this app build
		CommitHash string
		// Tag is a git Tag of this app build
		Tag string

		// General ...
		General General `yaml:"general" validate:"required"`
		// DB ...
		DB Database `yaml:"database" validate:"required"`
		// SMTP ...
		SMTP SMTP `yaml:"smtp" validate:"required"`
		// Security ...
		Security Security `yaml:"security" validate:"required"`
	}

	// General config
	General struct {
		// AppName ...
		AppName string `yaml:"app_name" validate:"required"`
		// CORSOrigin
		CORSOrigin string `yaml:"cors_origin" validate:"required"`
		// Access Token Expiry
		LoginExpiry uint `yaml:"login_expiry" validate:"required"`
		// Refresh Token Expiry
		RememberMeExpiry uint `yaml:"remember_me_expiry" validate:"required"`
		// FrontendURL
		FrontendURL string `yaml:"frontend_url" validate:"required"`
		// HTTPAddr internal server http address
		HTTPAddr string `yaml:"http_addr" validate:"required"`
		// WriteTimeoutSec ...
		WriteTimeoutSec int `yaml:"http_write_timeout_sec" validate:"required"`
		// ReadTimeoutSec ...
		ReadTimeoutSec int `yaml:"http_read_timeout_sec" validate:"required"`
		// IdleTimeoutSec ...
		IdleTimeoutSec int `yaml:"http_idle_timeout_sec" validate:"required"`
		// ShutdownWaitSec is the number of secs the server will wait
		// before shutting down after it receives an exit signal
		ShutdownWaitSec int `yaml:"graceful_shutdown_wait_time_sec" validate:"required"`
		// LogLevel ...
		LogLevel string `yaml:"log_level" validate:"required"`
	}

	SMTP struct {
		Host     string `yaml:"host" validate:"required"`
		Port     int    `yaml:"port" validate:"required"`
		Username string `yaml:"username" validate:"required"`
		Password string `yaml:"password" validate:"required"`
		From     string `yaml:"from" validate:"required"`
	}

	// Database config
	Database struct {
		// Credentials ...
		Credentials DBCredentials `yaml:"credentials" validate:"required"`
		// Driver ...
		Driver string `yaml:"driver" validate:"required"`
		// Protocol ...
		Protocol string `yaml:"protocol" validate:"required"`
		// ReadTimeoutSec ...
		ReadTimeoutSec int `yaml:"read_timeout_sec" validate:"required"`
		// WriteTimeoutSec ...
		WriteTimeoutSec int `yaml:"write_timeout_sec" validate:"required"`
		// MaxOpenConn ...
		MaxOpenConn int `yaml:"max_open_conn" validate:"required"`
		// ConnLifetimeSec ...
		ConnLifetimeSec int `yaml:"conn_lifetime_sec" validate:"required"`
	}

	Security struct {
		WhitelistedEndpoints []string    `yaml:"whitelisted_endpoints"`
		VerifyKeys           []VerifyKey `yaml:"verify_keys" validate:"required"`
		SignName             string      `yaml:"sign_name"`
		SigningKeyPath       string      `yaml:"signing_key_path"`
		SigningKey           string      `yaml:"signing_key" validate:"required"`
	}

	// DBCredentials database credentials
	DBCredentials struct {
		// Host ...
		Host string `yaml:"host" validate:"required"`
		// DBName ...
		DBName string `yaml:"name" validate:"required"`
		// User ...
		User string `yaml:"user" validate:"required"`
		// Pass ...
		Pass string `yaml:"pass" validate:"required"`
	}

	VerifyKey struct {
		IssuerName    string `yaml:"issuer_name" validate:"required"`
		VerifyKeyPath string `yaml:"verify_key_path"`
		VerifyKey     string `yaml:"verify_key"`
	}
)

// Load loads all configurations in to a new Config struct
// commitHash is a git commit hash of this app build
// tag is a git tag of this app build
func Load(commitHash string, tag string) (*Config, error) {
	configFilePath := os.Getenv(configPathEnvName)
	if configFilePath == "" {
		return nil, fmt.Errorf("env variable %s is not defined", configPathEnvName)
	}
	// reading app file config
	configFile, err := os.Open(configFilePath) // nolint:gosec
	if err != nil {
		return nil, errors.Wrap(err, "can not open config file")
	}

	var spec specWithMetaConfig
	err = yaml.NewDecoder(configFile).Decode(&spec)
	if err != nil {
		return nil, errors.Wrap(err, "can not unmarshal config data")
	}

	config := &spec.Spec
	config.CommitHash = commitHash
	config.Tag = tag

	// validating app file configs
	v := validator.New()
	err = v.Struct(config)
	if err != nil {
		return nil, errors.Wrap(err, "config file is not valid")
	}
	return config, nil
}
