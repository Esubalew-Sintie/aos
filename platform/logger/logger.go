// Package logger is the engine's logging interface, backed by the
// standard library's structured logger.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
)

type Logger interface {
	// Structured logging. args are alternating keys and values.
	Debug(ctx context.Context, msg string, args ...any)
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)

	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)

	// Named returns a logger that labels its lines with a component name.
	Named(name string) Logger
}

type slogLogger struct {
	logger *slog.Logger
}

// NewLogger writes JSON lines to standard error. In development it
// writes plain text and includes debug lines.
func NewLogger(development bool) Logger {
	if development {
		return &slogLogger{logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	}
	return &slogLogger{logger: slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))}
}

// NewDiscard returns a logger that writes nothing. For tests.
func NewDiscard() Logger {
	return &slogLogger{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func (l *slogLogger) Debug(ctx context.Context, msg string, args ...any) {
	l.logger.DebugContext(ctx, msg, args...)
}
func (l *slogLogger) Info(ctx context.Context, msg string, args ...any) {
	l.logger.InfoContext(ctx, msg, args...)
}
func (l *slogLogger) Warn(ctx context.Context, msg string, args ...any) {
	l.logger.WarnContext(ctx, msg, args...)
}
func (l *slogLogger) Error(ctx context.Context, msg string, args ...any) {
	l.logger.ErrorContext(ctx, msg, args...)
}

func (l *slogLogger) Debugf(format string, args ...any) { l.logger.Debug(fmt.Sprintf(format, args...)) }
func (l *slogLogger) Infof(format string, args ...any)  { l.logger.Info(fmt.Sprintf(format, args...)) }
func (l *slogLogger) Warnf(format string, args ...any)  { l.logger.Warn(fmt.Sprintf(format, args...)) }
func (l *slogLogger) Errorf(format string, args ...any) { l.logger.Error(fmt.Sprintf(format, args...)) }

func (l *slogLogger) Named(name string) Logger {
	return &slogLogger{logger: l.logger.With("component", name)}
}
