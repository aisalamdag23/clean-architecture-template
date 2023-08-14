package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/config"
	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/logger"
	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/protocol/rest"
)

var (
	// CommitHash will be set at compile time with current git commit
	CommitHash string
	// Tag will be set at compile time with current branch or tag
	Tag string
)

func main() {
	if err := run(CommitHash, Tag); err != nil {
		log.Fatalln(err)
	}
}

func run(commitHash string, tag string) error {
	ctx := context.Background()

	cfg, err := config.Load(commitHash, tag)
	if err != nil {
		return fmt.Errorf("unable to load configurations: '%v'", err)
	}

	lgr := logger.NewLogger(cfg.General.LogLevel)

	return rest.RunServer(ctx, cfg, lgr)
}
