// pkg/logging/logger.go
package logging

import (
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

// Int returns a zap.Field for structured logging of integers
func Int(key string, value int) zap.Field {
	return zap.Int(key, value)
}

// Duration returns a zap.Field for structured logging of time.Duration
func Duration(key string, value time.Duration) zap.Field {
	return zap.Duration(key, value)
}

// NewLogger creates a new Logger
func NewLogger() *Logger {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.MillisDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Determine output: JSON or console
	var encoder zapcore.Encoder
	// For production, use JSON output
	encoder = zapcore.NewJSONEncoder(encoderConfig)

	// Use stdout for both info and higher levels
	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(os.Stdout),
		zap.NewAtomicLevelAt(zapcore.InfoLevel),
	)

	// Create logger with development mode for caller info
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return &Logger{
		Logger: zapLogger,
	}
}
