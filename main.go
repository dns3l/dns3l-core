package main

import (
	"os"

	cmd "github.com/dta4/dns3l-go/cmd/dns3ld"
	log "github.com/sirupsen/logrus"
)

func main() {

	log.SetLevel(log.DebugLevel)

	err := cmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
