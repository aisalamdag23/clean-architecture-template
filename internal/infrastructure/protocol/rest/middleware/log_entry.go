package middleware

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/logger"
)

// LogEntry is a middleware that logs a single log entry per business request depending on status code
func LogEntry(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lrw := NewLoggingResponseWriter(w)
		next.ServeHTTP(lrw, r)
		statusCode := lrw.statusCode
		lgr := withRequestMetadata(logger.Extract(r.Context()), r, statusCode)
		if statusCode >= 500 {
			lgr.Error("http response: server error")
		} else if statusCode >= 400 {
			lgr.Warn("http response: client error")
		} else if statusCode >= 300 {
			lgr.Info("http response: redirection")
		} else if statusCode >= 200 {
			lgr.Info("http response: success")
		} else {
			lgr.Info("http response: informational")
		}
	})
}

func withRequestMetadata(lgr *logrus.Entry, r *http.Request, statusCode int) *logrus.Entry {
	return lgr.WithFields(logrus.Fields{
		"request_method": r.Method,
		"request_path":   r.URL.Path,
		"status_code":    statusCode,
	})
}
