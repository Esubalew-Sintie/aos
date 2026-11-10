package initiator

import (
	"github.com/flash-software-technology/aos/platform/config"
	"github.com/flash-software-technology/aos/platform/logger"
)

func InitLogger(cfg config.Config) logger.Logger {
	return logger.NewLogger(cfg.Development())
}
