package middleware

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/flash-software-technology/aos/internal/constant"
	"github.com/flash-software-technology/aos/internal/constant/dto/response"
	"github.com/flash-software-technology/aos/internal/constant/errors"
	"github.com/flash-software-technology/aos/internal/constant/model"
	"github.com/flash-software-technology/aos/internal/module/auth"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/utils"
)

// RequestContext gives every request an id, records where it came from,
// and caps the size of its body.
func RequestContext(trustedProxies []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			meta := model.RequestMeta{
				IP:        utils.ClientIP(r, trustedProxies),
				UserAgent: truncate(r.UserAgent(), 400),
				RequestID: utils.NewRequestID(),
			}
			// The browser's long-lived id, when it has one (SIGN-11).
			if c, err := r.Cookie(constant.DeviceCookie); err == nil && len(c.Value) <= 100 {
				meta.DeviceToken = c.Value
			}
			w.Header().Set(constant.HeaderRequestID, meta.RequestID)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			r.Body = http.MaxBytesReader(w, r.Body, constant.MaxBodyBytes)
			next.ServeHTTP(w, r.WithContext(auth.WithClientIP(withMeta(r.Context(), meta), meta.IP)))
		})
	}
}

// Recovery turns a panic into a plain 500. The caller never sees the cause.
func Recovery(log logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if rec == http.ErrAbortHandler {
						panic(rec)
					}
					log.Error(r.Context(), "panic in handler",
						"panic", rec, "path", r.URL.Path, "request_id", MetaFrom(r.Context()).RequestID)
					response.SendErrorResponse(w, errors.ErrUnexpected)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// AccessLog writes one line per request. It never logs a body, a header
// or a query string, any of which can hold a secret.
func AccessLog(log logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			log.Info(r.Context(), "request",
				"method", r.Method, "path", r.URL.Path, "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", MetaFrom(r.Context()).RequestID)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
