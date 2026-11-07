package initiator

import (
	"github.com/flash-softeware/aos/platform/config"
	"github.com/flash-softeware/aos/platform/logger"
)

func InitLogger(cfg config.Config) logger.Logger {
	return logger.NewLogger(cfg.Development())
}
