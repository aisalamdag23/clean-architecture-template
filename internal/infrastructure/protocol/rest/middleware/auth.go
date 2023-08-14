package middleware

import (
	"net/http"

	"github.com/aisalamdag23/clean-architecture-template/pkg/infrastructure/protocol/jwtparser"
	"github.com/aisalamdag23/clean-architecture-template/pkg/infrastructure/protocol/rest/middleware"
)

func AuthMiddleware(jwtParser *jwtparser.JwtParser, protectedEndpoints []string) func(next http.Handler) http.Handler {
	return middleware.AuthMiddleware(jwtParser, protectedEndpoints)
}
