// internal/handlers/main.go
package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-redis/redis/v8"
	"github.com/your-org/api-gateway/internal/config"
	"github.com/your-org/api-gateway/pkg/logging"
	"go.opentelemetry.io/otel/trace"
)

func NewRouter(cfg *config.Config, logger *logging.Logger, redisClient *redis.Client, tracer trace.Tracer) http.Handler {
	r := chi.NewRouter()
	m := NewMiddleware(cfg, logger, redisClient, tracer)
	r.Use(m.RequestID)
	r.Use(m.Logging)
	r.Use(m.CORS)
	r.Use(m.Tracing)
	r.Use(m.RateLimit)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second))

	r.Route("/api", func(r chi.Router) {
		r.Post("/login", authHandler.Login)
		r.Post("/register", authHandler.Register)
		r.Post("/refresh", authHandler.UpdateProfile)

		r.Group(func(r chi.Router) {
			r.Use(m.Authentication)
			r.Post("/logout", authHandler.Logout)
			r.Get("/profile", authHandler.GetProfile)
			r.Put("/profile", authHandler.UpdateProfile)
		})

		r.Group(func(r chi.Router) {
			r.Use(m.Authentication)
			mainService := services.NewMainService(cfg.Services.Main.URL, cfg.Services.Main.Timeout)

			r.Route("/listings", func(r chi.Router) {
				r.Get("/", proxyHandler(mainService, "/listings"))
				r.Post("/", proxyHandler(mainService, "/listings"))
				r.Get("/{id}", proxyHandler(mainService, "/listings/{id}"))
				r.Put("/{id}", proxyHandler(mainService, "/listings/{id}"))
				r.Delete("/{id}", proxyHandler(mainService, "/listings/{id}"))
			})

			r.Route("/applications", func(r chi.Router) {
				r.Get("/", proxyHandler(mainService, "/applications"))
				r.Post("/", proxyHandler(mainService, "/applications"))
				r.Get("/{id}", proxyHandler(mainService, "/applications/{id}"))
				r.Put("/{id}", proxyHandler(mainService, "/application/{id}"))
			})

			r.Route("/vendors", func(r chi.Router) {
				r.Get("/", proxyHandler(mainService, "/vendors"))
				r.Get("/{id}", proxyHandler(mainService, "/vendors/{id}"))
				r.Put("/{id}", proxyHandler(mainService, "/vendors/{id}"))
			})
		})

		r.Group(func(r chi.Router) {
			r.Use(m.Authentication)
			notificationService := services.NewNotificationService(
				cfg.Services.Notification.URL,
				cfg.Services.Notification.Timeout,
			)
			r.Route("/notifications", func(r chi.Router) {
				r.Get("/", proxyHandler(notificationService, "/notifications"))
				r.Get("/{id}", proxyHandler(notificationService, "/notifications/{id}"))
				r.Put("/{id}/read", proxyHandler(notificationService, "/notifications/{id}/read"))
				r.Delete("/{id}", proxyHandler(notificationService, "/notifications/{id}"))
			})
		})
	})

	return r
}

func proxyHandler(service services.ProxyService, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userUUID, _ := r.Context().Value("user_uuid").(string)
		service.ProxyRequest(w, r, path, userUUID)
	}
}
