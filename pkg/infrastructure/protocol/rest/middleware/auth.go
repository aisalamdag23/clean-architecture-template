package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/logger"
	intctx "github.com/aisalamdag23/clean-architecture-template/pkg/infrastructure/context"
	"github.com/aisalamdag23/clean-architecture-template/pkg/infrastructure/protocol/jwtparser"
)

type Result struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func AuthMiddleware(jwt *jwtparser.JwtParser, whitelistedURLs []string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isWhitelisted(whitelistedURLs, r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			auth, err := jwt.ParseAccessToken(r)
			if err != nil || auth == nil {
				logger.WithField(r.Context(), "bir.auth.err", err)
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(Result{
					Detail: "authorization error",
					Title:  http.StatusText(http.StatusUnauthorized),
					Status: http.StatusUnauthorized,
				})
				return
			}
			ctxKey := intctx.GetCtxKeyByIss(auth.Issuer)
			ctx := context.WithValue(r.Context(), ctxKey, auth)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func isWhitelisted(whitelist []string, method, url string) bool {
	for _, str := range whitelist {
		endpoint := strings.Split(str, " ")
		whitelistedURL := endpoint[1]
		if endpoint[0] != method {
			continue
		}
		if strings.HasSuffix(whitelistedURL, "*") {
			whitelistedURL = whitelistedURL[:len(whitelistedURL)-2]
			if strings.HasPrefix(url, whitelistedURL) {
				return true
			}
		}
		if whitelistedURL == url {
			return true
		}
	}
	return false
}
