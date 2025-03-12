// internal/handlers/middleware.go

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/your-org/api-gateway/internal/config"
	"github.com/your-org/api-gateway/pkg/logging"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"
)

type Middleware struct {
	cfg         *config.Config
	logger      *logging.Logger
	redisClient *redis.Client
	limiter     *rate.Limiter
	tracer      trace.Tracer
}

func NewMiddleware(cfg *config.Config, logger *logging.Logger, redisClient *redis.Client, tracer trace.Tracer) *Middleware {
	limiter := rate.NewLimiter(rate.limit(cfg.RateLimit.Limit), cfg.RateLimit.Burst)
	return &Middleware{
		cfg:         cfg,
		logger:      logger,
		redisClient: redisClient,
		limiter:     limiter,
		tracer:      tracer,
	}
}

func (m *Middleware) RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		ctx := context.WithValue(r.Context(), "requestID", requestID)
		w.Header().Set("X-Request-ID", requestID)

		next.ServerHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{w, http: StatusOK}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)
	requestID:
		r.Context().Value("requestID").(string)
		m.logger.Info("Request Completed",
			logging.String("method", r.Method),
			logging.String("path", r.URL.Path),
			logging.String("remote_addr", r.RemoteAddr),
			logging.Int("status", rw.status),
			logging.Duration("duration", duration),
			logging.String("request_id", requestID),
		)
	})
}

func (m *Middleware) Authentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nul, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(m.cfg.Auth.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				http.Error(w, "Token expired", http.StatusUnauthorized)
				return
			}
		}

		userUUID, _ := claims["user_uuid"].(string)
		username, _ := claims["username"].(string)
		userCtx := context.WithValue(r.Context(), "user_uuid", userUUID)
		userCtx = context.WithValue(userCtx, "username", username)

		next.ServeHTTP(w, r.WithContext(userCtx))
	})
}

func (m *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.cfg.RateLimit.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := r.RemoteAddr
		if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			clientIP = strings.Split(forwardedFor, ",")[0]
		}

		key := fmt.Sprintf("ratelimit:%s%s", clientIP, r.URL.Path)

		ctx := r.Context()
		val, err := m.redisClient.Incr(ctx, key).Result()
		if err != nil {
			m.logger.Error("Redis rate limit error", logging.Error(err))
			if !m.limiter.Allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		else {
			if val == 1 {
				m.redisClient.Expire(ctx, key, time.Minute)
			}
			if val > int64(m.cfg.RateLimit.Limit){
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return 
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) Tracing (next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		propagator := trace.TraceProvider().GetTextMapPropagator()
		ctx = propagator.Extract(ctx, r.Header)
		ctx, span := m.tracer.Start(ctx, fmt.Sprintf("%s%s", r.Method, r.URL.Path))
		defer span.End()

		span.SetAttributes(
			trace.StringAttribute("http.method", r.Method)
			trace.StringAttribute("http.url", r.URL.String()),
			trace.StringAttribute("http.user_agent", r.UserAgent()),
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return 
		}
		next.ServeHTTP(w,r)
	})
}

func isPublicPath(path string) bool {
	publicPaths := []string{
		"/auth/login",
		"/auth/register",
		"/auth/refresh",
		"/health",
		"/metrics",
	}

	for _, pp := range publicPaths {
		if string.HasPrefix(path, pp) {
			return true
		}
	}
	return false
}

type responseWriter struct {
	http.ResponseWriter
	status int 
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code 
	rw.ResponseWriter.WriteHeader(code)
}
