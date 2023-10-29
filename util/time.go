package util

import "time"

// RFC3339
func FormatTimeDNS3L(t time.Time) string {
	return t.Format("2006-01-02T15:04:05Z07:00")
}

func DaysToDuration(days uint16) time.Duration {
	return time.Duration(days) * time.Hour * 24
}

func DurationToDays(d time.Duration) uint16 {
	return uint16(d.Hours() / 24)
}
