package initiator

import (
	"github.com/flash-software-technology/aos/platform/config"
	"github.com/flash-software-technology/aos/platform/secret"
)

// InitConfig reads the settings from the environment. needMasterKey is
// false for commands that only touch the schema.
func InitConfig(needMasterKey bool) (config.Config, error) {
	return config.FromEnv(needMasterKey)
}

// InitMasterKey reads the key that wraps every tenant's data key.
func InitMasterKey(cfg config.Config) (*secret.MasterKey, error) {
	return secret.ParseMasterKey(cfg.MasterKey)
}
