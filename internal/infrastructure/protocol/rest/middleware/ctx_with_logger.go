package middleware

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/logger"
)

// CtxWithLogger is a middleware that puts a logger instance to context
func CtxWithLogger(loggerEntry *logrus.Entry) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := logger.ToContext(r.Context(), loggerEntry)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
