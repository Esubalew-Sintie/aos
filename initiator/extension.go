package initiator

import (
	"context"
	"io"

	"github.com/go-chi/chi/v5"

	"github.com/flash-software-technology/aos/internal/handler/middleware"
	"github.com/flash-software-technology/aos/internal/module"
	"github.com/flash-software-technology/aos/platform/logger"
)

// Extension adds to the engine when it is built with more source files
// laid over it. The hosted service is one: it registers itself from a
// file of package initiator that the public engine does not contain. With
// no extension, the engine has no usage limits and no extra routes.
type Extension struct {
	Name string
	// Meter counts what tenants do and knows their limits. Nil: none.
	Meter func(log logger.Logger) module.UsageMeter
	// Build makes the extension's parts once the engine's are made, and
	// returns how to add its routes. It may keep what it made in
	// App.Extras for its commands and tests.
	Build func(app *App) (func(r chi.Router, tenant *middleware.TenantMiddleware), error)
	// Commands are extra subcommands of the aos program.
	Commands []Command
}

// Command is a subcommand an extension adds to the aos program.
type Command struct {
	Name  string
	Usage string
	Run   func(ctx context.Context, args []string, out io.Writer) error
}

var extensions []Extension

// RegisterExtension adds an extension. Call it from an init function.
func RegisterExtension(e Extension) { extensions = append(extensions, e) }

// Extended reports whether any extension is built in.
func Extended() bool { return len(extensions) > 0 }

func extensionMeter(log logger.Logger) module.UsageMeter {
	var meter module.UsageMeter
	for _, e := range extensions {
		if e.Meter != nil {
			meter = e.Meter(log)
		}
	}
	return meter
}
