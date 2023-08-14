package logger

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
)

type ctxLoggerMarker struct{}

type ctxLogger struct {
	logger *logrus.Entry
	fields logrus.Fields
}

var (
	ctxLoggerKey = &ctxLoggerMarker{}
)

func newCtxLogger(entry *logrus.Entry) *ctxLogger {
	return &ctxLogger{
		logger: entry,
		fields: logrus.Fields{},
	}
}

// ToContext adds the logrus.Entry to the context for extraction later.
// Returning the new context that has been created.
func ToContext(ctx context.Context, entry *logrus.Entry) context.Context {
	return context.WithValue(ctx, ctxLoggerKey, newCtxLogger(entry))
}

// Extract takes the call-scoped logrus.Entry from context.
func Extract(ctx context.Context) *logrus.Entry {
	if ctx == nil {
		return logrus.
			NewEntry(newLogger())
	}
	l := extract(ctx)
	if l == nil {
		return logrus.
			NewEntry(newLogger())
	}
	return l.logger.
		WithContext(ctx).
		WithFields(l.fields)
}

// WithFields adds logrus fields to the logger inside context.
func WithFields(ctx context.Context, fields logrus.Fields) {
	l := extract(ctx)
	if l == nil {
		return
	}
	for k, v := range fields {
		l.fields[k] = v
	}
}

// WithField adds logrus field to the logger inside context.
func WithField(ctx context.Context, key string, value interface{}) {
	WithFields(ctx, logrus.Fields{key: value})
}

// WithExtReqFields injects external request data to context's log data
func WithExtReqFields(ctx context.Context, name string, fields map[string]interface{}) {
	WithField(
		ctx,
		fmt.Sprintf("external_request.%s", name),
		fields)
}

func extract(ctx context.Context) *ctxLogger {
	if ctx == nil {
		return nil
	}
	l, ok := ctx.Value(ctxLoggerKey).(*ctxLogger)
	if !ok || l == nil || l.logger == nil {
		return nil
	}
	return l
}
