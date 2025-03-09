// cmd/gateway/main.go
package main

import (
	"context"
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
)

func main() {
	// Initialize logger
	logger := logging.NewLogger()
	logger.Info("Starting API Gateway")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("Failed to load configuration", logging.Error(err))
	}

	// Initialize distributed tracing
	tracer, err := tracing.NewTracer("api-gateway", cfg.Tracing.JaegerEndpoint)
	if err != nil {
		logger.Fatal("Failed to initialize tracer", logging.Error(err))
	}
	defer tracer.Close()

	// Initialize Redis cache
	redisClient, err := cache.NewRedisClient(cfg.Redis)
	if err != nil {
		logger.Fatal("Failed to connect to Redis", logging.Error(err))
	}
	defer redisClient.Close()

	// Setup HTTP server with all routes and middleware
	router := handlers.NewRouter(cfg, logger, redisClient, tracer)

	// Configure server
	server := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeoutSeconds) * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Server listening", logging.String("port", cfg.Server.Port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed", logging.Error(err))
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", logging.Error(err))
	}

	logger.Info("Server exited properly")
}
