// pkg/logging/logger.go

package logging

import (
	"go.uber.org/zap"
)

// Logger wraps zap logger
type Logger struct {
	*zap.Logger
}

// Error returns a zap.Field for structured logging of errors
func Error(err error) zap.Field {
	return zap.Error(err)
}

// String returns a zap.Field for structured logging of strings
func String(key, value string) zap.Field {
	return zap.String(key, value)
}

// Int returns a zap.Field for structure logging of integers
func Int(key string, value int) zap.Field {
	return zap.Int(key, value)
}
