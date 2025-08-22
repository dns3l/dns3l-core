package main

import (
	"os"

	"github.com/dns3l/dns3l-core/context"
	"github.com/dns3l/dns3l-core/service"
	"github.com/dns3l/dns3l-core/state"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {

	log.SetLevel(log.DebugLevel)

	err := Execute()
	if err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "dns3ld",
	Short: "dns3l backend daemon",
	Long:  `DNS3LD backend daemon, version ` + context.ServiceVersion,
	Run: func(cmd *cobra.Command, args []string) {

		confPath, err := cmd.PersistentFlags().GetString("config")
		if err != nil {
			panic(err)
		}
		conf := service.Config{}
		err = conf.FromFile(confPath)
		if err != nil {
			panic(err)
		}
		err = conf.Initialize()
		if err != nil {
			panic(err)
		}
		socket, err := cmd.PersistentFlags().GetString("socket")
		if err != nil {
			panic(err)
		}
		renew, err := cmd.PersistentFlags().GetBool("renew")
		if err != nil {
			panic(err)
		}
		bootstrapcert, err := cmd.PersistentFlags().GetBool("bootstrapcert")
		if err != nil {
			panic(err)
		}
		svc := service.Service{Config: &conf, Socket: socket, NoRenew: !renew, NoBootstrapCert: !bootstrapcert}
		err = svc.Run()
		if err != nil {
			panic(err)
		}
	},
}

var dbCreateCmd = &cobra.Command{
	Use:   "dbcreate",
	Short: "Create database structure",
	Long: `Creates the database and the table structure given the database driver and DB
	connection information in the config file`,
	Run: func(cmd *cobra.Command, args []string) {

		confPath, err := cmd.Parent().PersistentFlags().GetString("config")
		if err != nil {
			panic(err)
		}

		tablesonly, err := cmd.PersistentFlags().GetBool("tablesonly")
		if err != nil {
			panic(err)
		}

		conf := service.Config{}
		err = conf.FromFile(confPath)
		if err != nil {
			panic(err)
		}

		err = conf.DB.Init()
		if err != nil {
			panic(err)
		}

		err = state.CreateSQLTables(conf.DB, !tablesonly)
		if err != nil {
			panic(err)
		}
	},
}

func Execute() error {
	rootCmd.PersistentFlags().StringP("config", "c", "config.yaml",
		`YAML-formatted configuration for dns3ld.`)
	rootCmd.PersistentFlags().StringP("socket", "s", ":80",
		`L4 socket on which the service should listen.`)
	rootCmd.PersistentFlags().BoolP("renew", "r", true,
		`Whether automatic cert renewal jobs should run. Useful if multiple instances run on the
		same DB and you want to disable renewal for the replicas, which is not yet thread-safe.`)
	rootCmd.PersistentFlags().BoolP("bootstrapcert", "b", true,
		`Whether initial bootstrapping of certs should run on this instance. Useful if multiple
		instances run on the same DB and you want to disable bootstrapping for the replicas.`)
	dbCreateCmd.PersistentFlags().BoolP("tablesonly", "t", false,
		`Do not try to attempt creating the DB, only create the tables`)

	rootCmd.AddCommand(dbCreateCmd)
	return rootCmd.Execute()
}
