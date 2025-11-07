package renew

import "time"

type ServerInfoRenewal struct {
	LastRun    *time.Time `json:"lastRun"`
	Successful uint       `json:"successful"`
	Failed     uint       `json:"failed"`
}
