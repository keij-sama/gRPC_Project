package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/keij-sama/gRPC_Project/sso/iternal/app"
	"github.com/keij-sama/gRPC_Project/sso/iternal/config"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {

	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)

	log.Info("starting application",
		slog.String("env", cfg.Env),
		slog.Any("cfg", cfg),
		slog.Int("prot", cfg.GRPC.Port),
	)

	log.Debug("debug message")
	log.Error("error message")
	log.Warn("warn message")

	fmt.Println(cfg)

	application := app.New(log, cfg.GRPC.Port, cfg.StoragePath, cfg.TokenTTL)

	application.GRPCSrv.MustRun()

	// TODO: инициализировать приложение (app)

	// TODO: запустить gRPC-сервер приложения
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}
	return log
}
