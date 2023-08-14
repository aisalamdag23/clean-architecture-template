package logger

import (
	"fmt"
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

// TimestampFormat common timestamp format for the package
const TimestampFormat = "2006-01-02T15:04:05.000"

// NewLogger creates a new logrus entry
func NewLogger(logLevel string) *logrus.Entry {
	logger := newLogger()
	level, err := logrus.ParseLevel(logLevel)
	if err == nil {
		logger.Level = level
	}
	return logrus.NewEntry(logger)
}

func newLogger() *logrus.Logger {
	// Initiate logging configurations
	logger := logrus.New()
	logger.Out = getLogOutput()
	logger.Level = logrus.InfoLevel
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: TimestampFormat,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})
	return logger
}

func getLogOutput() (f io.Writer) {
	logFile := "/var/log/application.log"
	if os.Getenv("LOG_FILE") != "" {
		logFile = os.Getenv("LOG_FILE")
	}
	f, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		fmt.Printf("error creating %s file, falling back to STDOUT\n", logFile)
		f = os.Stdout
	}
	return
}
