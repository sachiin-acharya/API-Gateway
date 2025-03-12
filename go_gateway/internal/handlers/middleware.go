// internal/handlers/middleware.go

// Level 0: This file implements HTTP middleware components for an API gateway.
// Middleware functions intercept HTTP requests and responses to add functionality
// like authentication, logging, rate limiting, etc. They work together in a chain
// where each middleware passes control to the next one after performing its task.

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/your-org/api-gateway/internal/config"
	"github.com/your-org/api-gateway/pkg/logging"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"
)

// Level 0: Middleware struct holds all dependencies needed by middleware functions.
// This enables middleware to access configuration, logging, Redis, rate limiting,
// and tracing capabilities.
type Middleware struct {
	cfg         *config.Config  // Application configuration
	logger      *logging.Logger // Logger for recording events
	redisClient *redis.Client   // Redis connection for distributed operations
	limiter     *rate.Limiter   // Local rate limiter as fallback
	tracer      trace.Tracer    // OpenTelemetry tracer for request tracing
}

// Level 0: NewMiddleware is a constructor that creates a new Middleware instance
// with all its dependencies properly initialized.
// Level 1: It takes configuration, logger, Redis client, and tracer as inputs,
// sets up the rate limiter based on config values, and returns a ready-to-use Middleware.
func NewMiddleware(cfg *config.Config, logger *logging.Logger, redisClient *redis.Client, tracer trace.Tracer) *Middleware {
	// Level 2: rate.Limit is a type conversion - converts the config value to the specific rate.Limit type
	limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit.Limit), cfg.RateLimit.Burst)
	return &Middleware{
		cfg:         cfg,
		logger:      logger,
		redisClient: redisClient,
		limiter:     limiter,
		tracer:      tracer,
	}
}

// Level 0: RequestID middleware adds a unique request ID to each incoming request.
// This helps with request tracking and debugging across distributed systems.
func (m *Middleware) RequestID(next http.Handler) http.Handler {
	// Level 1: Returns a function that processes each request by adding or using an existing request ID
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Level 1: Check if request already has an ID, otherwise generate a new UUID
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		// Level 2: context.WithValue adds the requestID to the request context for later retrieval
		ctx := context.WithValue(r.Context(), "requestID", requestID)
		w.Header().Set("X-Request-ID", requestID)

		// Level 1: Pass control to the next handler with the updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Level 0: Logging middleware logs information about each request including method,
// path, status code, and duration. This is crucial for monitoring and debugging.
func (m *Middleware) Logging(next http.Handler) http.Handler {
	// Level 1: Returns a function that wraps the actual request handling with timing and logging
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Level 1: Record start time and create a response writer wrapper to capture status code
		start := time.Now()
		// Level 2: Custom responseWriter embeds the standard ResponseWriter but adds status tracking
		rw := &responseWriter{w, status: http.StatusOK}

		// Level 1: Process the request with the wrapped response writer
		next.ServeHTTP(rw, r)

		// Level 1: Calculate duration and retrieve the request ID for the log entry
		duration := time.Since(start)
		// Level 2: Type assertion with comma-ok syntax to safely extract requestID from context
		requestID, _ := r.Context().Value("requestID").(string)

		// Level 1: Log the completed request with all relevant information
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

// Level 0: Authentication middleware verifies JWT tokens in requests to protected endpoints.
// It allows public paths through but requires valid authentication for all other routes.
func (m *Middleware) Authentication(next http.Handler) http.Handler {
	// Level 1: Returns a function that checks for authentication before proceeding
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Level 1: Skip authentication for public paths (login, register, health checks, etc.)
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Level 1: Check for the Authorization header and proper Bearer format
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		// Level 1: Extract and parse the JWT token
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		// Level 2: jwt.Parse decodes and validates the token using the provided key function
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			// Level 2: Verify the signing method is what we expect (HMAC)
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// Level 2: Return the secret key used to verify the token signature
			return []byte(m.cfg.Auth.JWTSecret), nil
		})

		// Level 1: Handle invalid tokens
		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Level 1: Extract claims (payload) from the token
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		// Level 1: Double-check token expiration (redundant with token.Valid, but explicit)
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				http.Error(w, "Token expired", http.StatusUnauthorized)
				return
			}
		}

		// Level 1: Add user information from token to request context for downstream handlers
		userUUID, _ := claims["user_uuid"].(string)
		username, _ := claims["username"].(string)
		// Level 2: Multiple context.WithValue calls chain together to add multiple values
		userCtx := context.WithValue(r.Context(), "user_uuid", userUUID)
		userCtx = context.WithValue(userCtx, "username", username)

		// Level 1: Pass control to next handler with the authenticated user context
		next.ServeHTTP(w, r.WithContext(userCtx))
	})
}

// Level 0: RateLimit middleware prevents abuse by limiting how many requests can be made
// from a single client IP address within a time period. It uses Redis for distributed rate
// limiting across multiple API gateway instances.
func (m *Middleware) RateLimit(next http.Handler) http.Handler {
	// Level 1: Returns a function that enforces rate limits on requests
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Level 1: Skip if rate limiting is disabled in configuration
		if !m.cfg.RateLimit.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Level 1: Determine client IP from headers or remote address
		clientIP := r.RemoteAddr
		// Level 2: Short variable declaration with conditional assignment for X-Forwarded-For
		if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			clientIP = strings.Split(forwardedFor, ",")[0]
		}

		// Level 1: Create a Redis key based on client IP and request path
		key := fmt.Sprintf("ratelimit:%s%s", clientIP, r.URL.Path)

		// Level 1: Use Redis to track and increment request count
		ctx := r.Context()
		val, err := m.redisClient.Incr(ctx, key).Result()
		if err != nil {
			// Level 1: If Redis fails, fall back to local in-memory rate limiter
			m.logger.Error("Redis rate limit error", logging.Error(err))
			if !m.limiter.Allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		} else {
			// Level 1: For new keys, set expiration time
			if val == 1 {
				m.redisClient.Expire(ctx, key, time.Minute)
			}
			// Level 1: Check if rate limit is exceeded
			if val > int64(m.cfg.RateLimit.Limit) {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		// Level 1: If not rate limited, proceed to next handler
		next.ServeHTTP(w, r)
	})
}

// Level 0: Tracing middleware adds distributed tracing to requests using OpenTelemetry.
// This allows for tracking requests across services and analyzing performance.
func (m *Middleware) Tracing(next http.Handler) http.Handler {
	// Level 1: Returns a function that adds tracing information to requests
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Level 1: Extract the context from the request
		ctx := r.Context()

		// Level 1: Start a new span for this request
		ctx, span := m.tracer.Start(ctx, fmt.Sprintf("%s %s", r.Method, r.URL.Path))
		// Level 2: defer ensures span.End() is called when the function returns
		defer span.End()

		// Level 1: Add relevant HTTP information to the span as attributes
		// Level 2: attribute.String creates typed attributes for the span
		span.SetAttributes(
			attribute.String("http.method", r.Method),
			attribute.String("http.url", r.URL.String()),
			attribute.String("http.user_agent", r.UserAgent()),
		)

		// Level 1: Pass control to the next handler with the traced context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Level 0: CORS middleware handles Cross-Origin Resource Sharing headers to allow
// frontend applications from different domains to access the API.
func (m *Middleware) CORS(next http.Handler) http.Handler {
	// Level 1: Returns a function that adds CORS headers to responses
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Level 1: Set standard CORS headers for all responses
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")

		// Level 1: Handle OPTIONS preflight requests specially
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Level 1: For non-OPTIONS requests, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

// Level 0: isPublicPath is a helper function that determines if a path is public
// (doesn't require authentication). This centralizes the list of public endpoints.
// Level 1: Checks if the given path starts with any of the defined public paths
func isPublicPath(path string) bool {
	// Level 1: Define the list of public paths that don't require authentication
	publicPaths := []string{
		"/auth/login",
		"/auth/register",
		"/auth/refresh",
		"/health",
		"/metrics",
	}

	// Level 1: Check each public path pattern against the request path
	for _, pp := range publicPaths {
		// Level 2: strings.HasPrefix checks if path begins with the public path pattern
		if strings.HasPrefix(path, pp) {
			return true
		}
	}
	return false
}

// Level 0: responseWriter is a custom wrapper around the standard http.ResponseWriter
// that tracks the status code for logging purposes.
type responseWriter struct {
	http.ResponseWriter     // Level 2: Embedded http.ResponseWriter provides all original methods
	status              int // Additional field to track status code
}

// Level 0: WriteHeader overrides the standard WriteHeader method to capture the status code
// before passing it to the underlying ResponseWriter.
// Level 1: Saves the status code and calls the original method
func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}
