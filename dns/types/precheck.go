package types

import "time"

const (
	DefaultPrecheckInterval = time.Minute
	DefaultPrecheckTimeout  = 2 * time.Second
)

type PrecheckConfig struct {
	CheckNameservers []string      `yaml:"checkNameservers"`
	Enabled          bool          `yaml:"enabled"`
	PrecheckInterval time.Duration `yaml:"precheckInterval"`
	PrecheckTimeout  time.Duration `yaml:"precheckTimeout"`
}

func (conf *PrecheckConfig) SetDefaults() {
	if conf.PrecheckInterval == 0 {
		conf.PrecheckInterval = DefaultPrecheckInterval
	}
	if conf.PrecheckTimeout == 0 {
		conf.PrecheckTimeout = 2 * DefaultPrecheckTimeout
	}
}
