package cli

import (
	"fmt"
	"os"
)

func argsPrinter(args []string) {
	for i, v := range args {
		fmt.Printf("Argument(%d) := '%s' \n", i, v)
	}
}

func checkEnv(env string) bool {
	if valStr, ok := os.LookupEnv(env); valStr != "" && ok {
		return true
	}
	return false
}

func checkEnvDefaultStr(env string, defaultVal string) string {

	if configName, ok := os.LookupEnv(env); configName != "" && ok {
		return configName
	}
	return defaultVal
}

func checkEnvDefaultBool(env string, defaultVal bool) bool {

	if configString, ok := os.LookupEnv(env); configString != "" && ok {
		var configVal bool
		if configString == "true" {
			configVal = true
		} else {
			configVal = false
		}
		return configVal
	}
	return defaultVal
}
