package clicmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/*
the cli implements this pattern
	APPNAME COMMAND ARG --FLAG
	cli     command 	arg     flag
	git 	clone 		URL 	--bare
*/
/* global flags of the cli
	-v, --debug     | Enable more output [$DNS3L_DEBUG]
	-j, --json      | Results as JSON
	-h, -?, --help  | Show help
IMPLEMENTATION
 	global flags are implemented as persistent flags on the rootCmd
*/

// Verbose ===========================
// -h, -?, --help  | Show help
// Remark cobra has a buildin / automatic help !!!
// --help is already done
// ===========================
// -v, --debug     | Enable more output [$DNS3L_DEBUG]
var Verbose bool

// JSONOutput ===========================
//-j, --json      | Results as JSON
var JSONOutput bool

/*Force flag
// -f, --force     | Change existing DATA
*/
var Force bool

// Config ===========================
// -c, --config
// NoOptDefault -c
// --> [$DNS3L_CONFIG] or or default value ~/.dns3l.json, if shell variable is not set or empty
// -c="file"	--> only a name of file
// we search in several places in this order
// -- current directory
// -- shell varibale
// -- home directory

var Config string = ""

// ConfigDummy necessary for viper & cobra hack
var ConfigDummy string

// this is the value if only -c is written in the command line without an parameter
// var configDefaultFileNameNoOpt = "dns3l"
var viperShellPrefix = "DNS3L"

// singel letters used
/*
    -f, --force
	-v, --debug
	-j, --json
	-h, -?, --help
	-c, --config
	-s, --secret
	-i, --id
	-b, --backend
	-w, --wildcard
  	-d, --autodns
	-m, --mode
	  , --ca        <<<=== c of cert conflicts the the c of config
*/

/* You can provide your own Help command or your own template for the default command to use with following functions
cmd.SetHelpCommand(cmd *Command)
cmd.SetHelpFunc(f func(*Command, []string))
cmd.SetHelpTemplate(s string)
*/

var rootCmd = &cobra.Command{
	Use:   "dns3cli",
	Short: "CLI for dns3ld and DNS",
	Long:  "Deal with \n1) DNS3L X.509 certificates\n2) DNS3L DNS backends\n for help about a command use ./dns3cli <command> --help ",
	Run: func(cmd *cobra.Command, args []string) {
		// One can use this function of commands to modify or inspect strings straight from the terminal`,

	},
}

//Execute this function will be called from main()
// and at the this will call the final command e.g dns_add_Command
func Execute() {
	// start with the root element of our commands tree
	err := rootCmd.Execute()
	if err != nil && err.Error() != "" {
		fmt.Fprintf(os.Stderr, "ERROR: Where was an fatal error while executing your dns3l CLI '%s'", err)
		os.Exit(1)
	}
	// fmt.Printf("Exit of commands.Execute()\n")
}

// this function is called from golang before main
// for c++ people something like a constructor of this file
func init() {
	// we must parse the command line by manually
	// to get viper working and put its values as default into cobra
	value, OK := parseCommandLineForConfig()
	if OK {
		Config = value
	}
	// first init Viper,
	//that we have the values from config-file or shell Variable
	initViperConfig()
	vip := viper.GetViper()
	// this is a dummy flag
	// does not work because we need viper to read its config File
	// becasue that we can set the default values for the cobra flags during intitalisation
	// but we need this otherwise we get an ERROR from cobra
	rootCmd.PersistentFlags().StringVarP(&ConfigDummy, "config", "c", "", "Configuration  yaml file ")
	rootCmd.PersistentFlags().Lookup("config").NoOptDefVal = "dns3lcli.yaml"
	// global flags are implemented as persistent flags on the rootCmd
	// the settings behind the command has a higher priority than the shell variable
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "debug", "v", vip.GetBool("debug"), "Enable more output")
	rootCmd.PersistentFlags().Lookup("debug").NoOptDefVal = "true"
	// json output
	rootCmd.PersistentFlags().BoolVarP(&JSONOutput, "json", "j", vip.GetBool("json"), "Results as JSON formatted file")
	rootCmd.PersistentFlags().Lookup("json").NoOptDefVal = "true"
	// force
	rootCmd.PersistentFlags().BoolVarP(&Force, "force", "f", vip.GetBool("force"), "Change existing DATA")
	rootCmd.PersistentFlags().Lookup("force").NoOptDefVal = "true"
	// add the sub commands
	initDNS()
	initCert()
	initLogin()
}

func initViperConfig() {
	vip := viper.GetViper()
	vip.AddConfigPath(".") // optionally look for config in the working directory
	if checkEnv(viperShellPrefix + "_CONFIG") {
		vip.AddConfigPath("$" + viperShellPrefix + "_CONFIG") // == "$DNS3L_CONFIG"
	}
	// Find home directory.
	home, errOS := os.UserHomeDir()
	cobra.CheckErr(errOS)
	vip.AddConfigPath(home)   // path to look for the config file in
	vip.SetConfigType("yaml") // REQUIRED if the config file does not have the extension in the name
	vip.AutomaticEnv()
	// has to be called behind AutomaticEnv()
	// it is not necessary to set this
	// because we expliitly set the names of the shell variable
	vip.SetEnvPrefix(viperShellPrefix)
	// Defaultvalues
	vip.SetDefault("config", "dns3lcli.yaml")
	vip.SetDefault("debug", "false")
	vip.SetDefault("json", "false")
	// the error of BindEnv means you did not provide any key (can be looked at sourcecode of viper)
	vip.BindEnv("config", viperShellPrefix+"_CONFIG") //nolint:errcheck
	vip.BindEnv("debug", viperShellPrefix+"_DEBUG")   //nolint:errcheck
	vip.BindEnv("json", viperShellPrefix+"_JSON")     //nolint:errcheck
	// DNS and cert
	vip.SetDefault("force", "false")
	vip.BindEnv("force", viperShellPrefix+"_FORCE") //nolint:errcheck
	// printViperConfigRoot()
	// DNS part
	vip.SetDefault("dns.backend", "NOT_SET")
	vip.SetDefault("dns.id", "NOT_SET")
	vip.SetDefault("dns.secret", "NOT_SET")
	vip.BindEnv("dns.backend", viperShellPrefix+"_DNS_BACKEND") //nolint:errcheck
	vip.BindEnv("dns.id", viperShellPrefix+"_DNS_ID")           //nolint:errcheck
	vip.BindEnv("dns.secret", viperShellPrefix+"_DNS_SECRET")   //nolint:errcheck
	// CERT part
	// not done
	vip.SetDefault("cert.ca", "NOT_SET")
	vip.SetDefault("cert.wildcard", "NOT_SET")
	vip.SetDefault("cert.autodns", "false")
	vip.SetDefault("cert.modeFull", "false")
	vip.SetDefault("cert.api", "NOT_SET")
	vip.BindEnv("cert.ca", viperShellPrefix+"_CERT_CA")             //nolint:errcheck
	vip.BindEnv("cert.wildcard", viperShellPrefix+"_CERT_WILDCARD") //nolint:errcheck
	vip.BindEnv("cert.autodns", viperShellPrefix+"_CERT_AUTODNS")   //nolint:errcheck
	vip.BindEnv("cert.modeFull", viperShellPrefix+"_CERT_MODE")     //nolint:errcheck
	vip.BindEnv("cert.api", viperShellPrefix+"_CERT__API")          //nolint:errcheck

	// if in the commandline was no --config
	if Config == "" {
		Config = vip.GetString("config")
	}
	if Verbose {
		fmt.Fprintf(os.Stderr, "INFO: Using config file: '%s' \n", Config)
	}
	if !(parseCommandLineForHelp() || parseCommandLineForVersionCommand()) {
		vip.SetConfigName(Config) // name of config file (without extension)
		err := vip.ReadInConfig() // Find and read the config file
		if err != nil {           // Handle errors reading the config file
			fmt.Fprintf(os.Stderr, "ERROR: Init fatal error config file:%v \n Using config file: %s\n", err, vip.ConfigFileUsed())
			// os.Exit(1)
		} else if Verbose {
			fmt.Fprintf(os.Stderr, "SUCCESS: Init Configuration sucessfully read: %s\n", vip.ConfigFileUsed())
			// printViperConfigRoot()
		}
	}
}

// implementation of -c --config
// because both viper and cobra depend on each other
// during the initialisation
// we have a chicken egg problem about
func parseCommandLineForConfig() (string, bool) {
	regExWithValue := regexp.MustCompile(`^((-c=\w+)|(--config=\w+))`)
	var cliVal string
	var count int = 0
	for _, v := range os.Args {
		// fmt.Printf("Value := %s \n", v)
		if strings.EqualFold(v, "-c") || strings.EqualFold(v, "--config") {
			cliVal = "dns3lcli.yaml"
			count++
		}
		if regExWithValue.MatchString(v) {
			// alles nach dem 1sten = übernehmen
			cliVal = v[strings.Index(v, "=")+1:]
			count++
		}
	}
	if count == 1 {
		return cliVal, true
	}
	if count > 1 {
		fmt.Fprintf(os.Stderr, "ERROR: Init found  more than one config flag!\n")
		return string(""), false
	}
	return string(""), false
}

//  -h, --help
func parseCommandLineForHelp() bool {
	for _, v := range os.Args {
		if strings.EqualFold(v, "-h") || strings.EqualFold(v, "--help") {
			return true
		}
	}
	return false
}

// parse version
func parseCommandLineForVersionCommand() bool {
	for _, v := range os.Args {
		if strings.EqualFold(v, "version") || strings.EqualFold(v, "Version") {
			return true
		}
	}
	return false
}
