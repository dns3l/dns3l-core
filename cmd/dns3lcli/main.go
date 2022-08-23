package main

import (
	"fmt"

	"github.com/dta4/dns3l-go/cli"
	"github.com/spf13/viper"
)

func main() {
	cli.Execute()
	if cli.Verbose {
		fmt.Printf("Finished writing the effective Config from File and Shell Variables to current directiory into 'dns3l_config_plus_shell.yaml' \n")
		// if shell varibale modify the configuration you will see it here
		// command line at the moment not because i write them not back to viper
		viper.GetViper().WriteConfigAs("dns3l_config_plus_shell.yaml")
	}
}
