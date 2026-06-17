package main

import (
	"fmt"
	"os"

	"github.com/dns3l/dns3l-core/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
