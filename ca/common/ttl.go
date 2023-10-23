package common

import (
	"fmt"
	"time"

	"github.com/dns3l/dns3l-core/ca/types"
	"github.com/dns3l/dns3l-core/common"
	"github.com/dns3l/dns3l-core/util"
)

type TTLConfig struct {
	Min           uint16 `yaml:"min"`
	Max           uint16 `yaml:"max"`
	Default       uint16 `yaml:"default"`
	IgnoreUserTTL bool   `yaml:"ignoreUserTTL"`
}

func GetTTL(cinfo *types.CertificateClaimInfo, config TTLConfig) (time.Duration, error) {
	var ttl time.Duration = 0
	if !config.IgnoreUserTTL && cinfo.TTLSelected > 0 {
		minTTL := util.DaysToDuration(config.Min)
		maxTTL := util.DaysToDuration(config.Max)
		if cinfo.TTLSelected < minTTL {
			return 0, &common.InvalidInputError{
				SubErr: fmt.Errorf("TTL %dd is smaller than minimum TTL (%dd)", util.DurationToDays(cinfo.TTLSelected), util.DurationToDays(minTTL)),
			}
		}
		if maxTTL > 0 && cinfo.TTLSelected > maxTTL {
			return 0, &common.InvalidInputError{
				SubErr: fmt.Errorf("TTL %dd is larger than maximum TTL (%dd)", util.DurationToDays(cinfo.TTLSelected), util.DurationToDays(maxTTL)),
			}
		}
		ttl = cinfo.TTLSelected
	} else if config.Default > 0 {
		ttl = util.DaysToDuration(config.Default)
	}
	return ttl, nil
}
