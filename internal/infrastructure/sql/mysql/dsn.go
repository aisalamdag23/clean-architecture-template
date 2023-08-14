package mysql

import (
	"fmt"
)

// DSNFactory dsn factory
type DSNFactory struct{}

// NewDSNFactory ...
func NewDSNFactory() *DSNFactory {
	return &DSNFactory{}
}

// Create creates dsn (Data Source Name) string
func (f DSNFactory) Create(protocol, address, dbname, user, pass string, readTimeoutSec, writeTimeoutSec int) string {
	return fmt.Sprintf(
		"%s:%s@%s(%s)/%s?parseTime=%s&readTimeout=%ds&writeTimeout=%ds",
		user,
		pass,
		protocol,
		address,
		dbname,
		"true",
		readTimeoutSec,
		writeTimeoutSec)
}
