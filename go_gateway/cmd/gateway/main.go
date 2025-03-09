// cmd/gateway/main.go

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/your-org/api-gateway/internal/config"
	"github.com/your-org/api-gateway/internal/handlers"
	"github.com/your-org/api-gateway/pkg/cache"
	"github.com/your-org/api-gateway/pkg/logging"
	"github.com/your-org/api-gateway/pkg/tracing"
	"honnef.co/go/tools/config"
)

func main(){
	//Initialize logger
	logger := logging.NewLogger()
	logger.info("Starting API Gateway")

	//Load Configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("Failed to load configuration", logging.Error(err))
	}

	//Initialized distributed caching
	tracer, err := tracing.NewTracer("api-gateway", cfg.Tracing.JaegerEndpoint)
	if err != nil {
		logger.Fatal("Failed to initialize tracer", logging.Error(err))
	}
	defer tracer.Close()

	//Initialize redic cache
	redisClient, err := cache.NewRedisClient(cfg.Redis)
	if err != nil {
		logger.Fatal("Failed to connect to Redis", logging.Error(err))
	}
	defer redisClient.Close()

	//Setup HTTP server with all routes and middleware
	router := handlers.NewRouter(cfg, logger, redisClient, tracer)

	//Configure server
	server := &http.Server{
		Addr: ":" + cfg.Server.Port,
		Handler : router,
		ReadTimeout: time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second,
		IdleTimeout: time.Duration(cfg.Server.IdleTimeoutSeconds) * time.Second,	
	}

	//Start server in a goroutine
	go func(){
		logger.Info("Server listening", logging.String("port", cfg.Server.Port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server Failed", logging.Error(err))
		}
	}
}

