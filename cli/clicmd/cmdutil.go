package clicmd

import (
	"os"
)

func checkEnv(env string) bool {
	if valStr, ok := os.LookupEnv(env); valStr != "" && ok {
		return true
	}
	return false
}
