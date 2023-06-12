package main

import (
	"errors"
	"fmt"
	"os"

	cli "github.com/dns3l/dns3l-core/cli/clicmd"
	clitypes "github.com/dns3l/dns3l-core/cli/clitypes"
)

func main() {
	err := cli.Execute()
	var valueErr *clitypes.ExitValueError
	var exitCode int
	if errors.As(err, &valueErr) {
		fmt.Printf("ERROR: Exitcode is '%d'\n", valueErr.Value)
		exitCode = valueErr.Value
	} else if err != nil {
		fmt.Printf("ERROR: Without an dedicated ExitCode 1 %s", err.Error())
		exitCode = 1
	} else {
		exitCode = 0
	}
	os.Exit(exitCode)
}
