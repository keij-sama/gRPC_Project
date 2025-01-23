package app

import (
	"log/slog"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.Server
}

func New(
	log *slog.Logger,
	grpcPort int,
	storagePath string,
	tokenTTL time.Duration,
) *App {
	grpcApp := grpcapp.New(log, grpcPort)

	return &App{
		GRPCSrv: grpcApp,
	}
}
