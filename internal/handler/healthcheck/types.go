package healthcheck

import (
	"context"

	"github.com/aisalamdag23/clean-architecture-template/internal/handler"
)

type (
	HealthChecker interface {
		HealthCheck(context.Context) (interface{}, error)
	}

	Handler interface {
		handler.Handler
		RegisterService(name string, s HealthChecker)
	}
)
