package rest

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"

	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/config"
	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/protocol/rest/middleware"
	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/registry"
)

// RunServer runs HTTP/REST server
func RunServer(ctx context.Context, cfg *config.Config, logger *logrus.Entry) error {
	wait, err := time.ParseDuration(fmt.Sprintf("%ds", cfg.General.ShutdownWaitSec))
	if err != nil {
		return err
	}

	reg := registry.Init(ctx, cfg)

	// Add your routes as needed
	r := mux.NewRouter()
	r.Use(middleware.NoCacheHeader)
	r.Use(middleware.CtxWithLogger(logger))
	r.Use(middleware.LogEntry)

	healthCheckServer := reg.CreateHealthCheckServer()
	healthCheckServer.RegisterRoutes(r)

	v1 := r.PathPrefix("/api/v1").Subrouter()

	jwtParser, err := reg.CreateJwtParser()
	if err != nil {
		return err
	}
	v1.Use(middleware.AuthMiddleware(jwtParser, cfg.Security.WhitelistedEndpoints))

	userServer := reg.CreateUserServer(*jwtParser)
	userServer.RegisterRoutes(v1)

	accountSerer := reg.CreateAccountServer(*jwtParser)
	accountSerer.RegisterRoutes(v1)

	// CORS control
	cor := cors.New(cors.Options{
		AllowedOrigins:   []string{cfg.General.CORSOrigin},
		AllowCredentials: true,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodHead, http.MethodPut},
	})
	// This inserts the middleware
	handler := cor.Handler(r)

	srv := &http.Server{
		Addr:         cfg.General.HTTPAddr,
		WriteTimeout: time.Second * time.Duration(cfg.General.WriteTimeoutSec),
		ReadTimeout:  time.Second * time.Duration(cfg.General.ReadTimeoutSec),
		IdleTimeout:  time.Second * time.Duration(cfg.General.IdleTimeoutSec),
		Handler:      handler,
	}

	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		logger.Info("starting HTTP/REST server...")
		if err := srv.ListenAndServe(); err != nil {
			logger.Error(err)
		}
	}()

	// Block until we receive our signal.
	<-c
	logger.Info("shutting down server...")
	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	_ = srv.Shutdown(ctx)

	logger.Info("shutdown complete")
	os.Exit(0)

	return nil
}
