package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	// fmt.Println("VersionCmd.init() called")
	rootCmd.AddCommand(versionCmd)
}

// here we ignore all the globals flags like
// 		-v, --debug
// 		-c, --config
//		-j, --json
// 		-h, --help

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of dns3l CLI",
	Long:  `All software has versions. This is dns3l CLIs`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("dns3l version := 0.1.7")
	},
}
