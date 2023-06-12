package clicmd

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
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Version:=%s\n", context.CLIVersion)
		return nil
	},
}
