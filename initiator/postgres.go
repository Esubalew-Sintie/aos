package initiator

import (
	"context"

	"github.com/flash-software-technology/aos/platform/config"
	"github.com/flash-software-technology/aos/platform/logger"
	"github.com/flash-software-technology/aos/platform/postgres"
)

// InitDatabase connects and applies any migration that has not been
// applied yet. Two copies of the engine starting at once are safe: the
// migrations run under a lock.
func InitDatabase(ctx context.Context, cfg config.Config, log logger.Logger) (*postgres.DB, error) {
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	applied, err := db.Migrate(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}
	for _, name := range applied {
		log.Infof("migration applied: %s", name)
	}
	return db, nil
}
