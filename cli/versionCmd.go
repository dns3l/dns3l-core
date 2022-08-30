package cli

import (
	"fmt"

	"github.com/dns3l/dns3l-core/context"
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
		fmt.Printf("dns3l version := %v", context.CLIVersion)
	},
}
