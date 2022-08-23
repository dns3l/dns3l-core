package cli

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
// the following logic is not implemented !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// -c, --config    | Configuration (~/.dns3l.json) [$DNS3L_CONFIG]
// -c			--> [$DNS3L_CONFIG] or ~/.dns3l.json id shell variable is not set or empty
// nothing 	--> "" empty String
// -c "file"	--> only the name of file, not a path
// This is implemented
// we search in several places in this order
// current directory
// shell varibale#
// home directory
// home
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
var rootCmd = &cobra.Command{
	Use:   "dns3cli",
	Short: "CLI for dns3ld and DNS",
	Long:  "Deal with \n1) DNS3L X.509 certificates\n2) DNS3L DNS backends",
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
		fmt.Fprintf(os.Stderr, "Where was an error while executing your dns3l CLI '%s'", err)
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
	// fmt.Printf("Behind cobra.OnInitialize(initViperConfig)\n")
	// this is a dummy flag
	// does not work because we need viper to read its config File
	// becasue that we can set the default values for the cobra flags during intitalisation
	// but we need this otherwise we get an ERROR from cobra
	rootCmd.PersistentFlags().StringVarP(&ConfigDummy, "config", "c", "", "Configuration  yaml file ")
	rootCmd.PersistentFlags().Lookup("config").NoOptDefVal = "Value_is_never_used"
	// global flags are implemented as persistent flags on the rootCmd
	// the settings behind the command has a higher priority than the shell variable
	// fmt.Printf("Debug in CommandsGoInit()         	'%t' \n", vip.GetBool("debug"))
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "debug", "v", vip.GetBool("debug"), "Enable more output")
	rootCmd.PersistentFlags().Lookup("debug").NoOptDefVal = "true"
	// json output
	// fmt.Printf("json in CommandsGoInit()         	'%t' \n", vip.GetBool("json"))
	rootCmd.PersistentFlags().BoolVarP(&JSONOutput, "json", "j", vip.GetBool("json"), "Results as JSON formatted file")
	rootCmd.PersistentFlags().Lookup("json").NoOptDefVal = "true"
	// force
	rootCmd.PersistentFlags().BoolVarP(&Force, "force", "f", vip.GetBool("force"), "Change existing DATA")
	rootCmd.PersistentFlags().Lookup("force").NoOptDefVal = "true"
	// add the sub commands
	// fmt.Printf("Command::Init() before initDNS()\n ")
	initDNS()
	// fmt.Printf("Command::Init() After initDNS()\n ")
	initCert()
}

func initViperConfig() {

	viper.AddConfigPath(".") // optionally look for config in the working directory
	if checkEnv(viperShellPrefix + "_CONFIG") {
		viper.AddConfigPath("$" + viperShellPrefix + "_CONFIG") // == "$DNS3L_CONFIG"
	}
	// Find home directory.
	home, errOS := os.UserHomeDir()
	cobra.CheckErr(errOS)
	viper.AddConfigPath(home)   // path to look for the config file in
	viper.SetConfigType("yaml") // REQUIRED if the config file does not have the extension in the name
	viper.AutomaticEnv()
	// has to be called behind aAtomaticEnv()
	// it is not necessary to set this
	// because we expliitly set the names of the shell variable
	viper.SetEnvPrefix(viperShellPrefix)
	// Defaultvalues
	viper.SetDefault("config", "dns3l")
	viper.SetDefault("debug", "false")
	viper.SetDefault("json", "false")
	// the error of BindEnv means you did not provide any key (looked at sourcecode)
	viper.BindEnv("config", viperShellPrefix+"_CONFIG") //nolint:errcheck
	viper.BindEnv("debug", viperShellPrefix+"_DEBUG")   //nolint:errcheck
	viper.BindEnv("json", viperShellPrefix+"_JSON")     //nolint:errcheck
	// DNS and cert
	viper.SetDefault("force", "false")
	viper.BindEnv("force", viperShellPrefix+"_FORCE") //nolint:errcheck
	// printViperConfigRoot()
	// DNS part
	viper.SetDefault("dns.backend", "InfoblxNIC")
	viper.SetDefault("dns.id", "user")
	viper.SetDefault("dns.secret", "pass")
	viper.BindEnv("dns.backend", viperShellPrefix+"_DNS_BACKEND") //nolint:errcheck
	viper.BindEnv("dns.id", viperShellPrefix+"_DNS_ID")           //nolint:errcheck
	viper.BindEnv("dns.secret", viperShellPrefix+"_DNS_SECRET")   //nolint:errcheck
	// CERT part
	// not done
	viper.SetDefault("cert.ca", "ViDef_CA")
	viper.SetDefault("cert.wildcard", "ViDef_wildcard")
	viper.SetDefault("cert.autodns", "false")
	viper.SetDefault("cert.modeFull", "false")
	viper.SetDefault("cert.api", "ViDef_cert_api")
	viper.BindEnv("cert.ca", viperShellPrefix+"_CERT_CA")             //nolint:errcheck
	viper.BindEnv("cert.wildcard", viperShellPrefix+"_CERT_WILDCARD") //nolint:errcheck
	viper.BindEnv("cert.autodns", viperShellPrefix+"_CERT_AUTODNS")   //nolint:errcheck
	viper.BindEnv("cert.modeFull", viperShellPrefix+"_CERT_MODE")     //nolint:errcheck
	viper.BindEnv("cert.api", viperShellPrefix+"_CERT__API")          //nolint:errcheck

	// if in the commandline was no --config
	if Config == "" {
		Config = viper.GetString("config")
	}
	// fmt.Printf("InitViper: Using config file: '%s' \n", Config)
	viper.SetConfigName(Config) // name of config file (without extension)
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		fmt.Printf("fatal error config file:%v \n Using config file: %s\n", err, viper.ConfigFileUsed())
		// os.Exit(1)
	} else if Verbose {
		fmt.Printf("Viper Configuration sucessfully read: %s\n", viper.ConfigFileUsed())
		// printViperConfigRoot()
	}
}

// implementation of -c --config
// because both viper and cobra depend on each other
// during the initialisation
// we have a chicken egg problem about
func parseCommandLineForConfig() (string, bool) {
	regExWithValue := regexp.MustCompile(`^((-c=\w+)|(--config=\w+))`)
	var cliVal string
	for _, v := range os.Args {
		// fmt.Printf("Value := %s \n", v)
		if strings.EqualFold(v, "-c") || strings.EqualFold(v, "--config") {
			cliVal = "dns3l.json"
			// fmt.Printf("Config + without file found -> assign NoOptDefault '%s' \n", cliVal)
			return cliVal, true
		}
		if regExWithValue.MatchString(v) {
			// alles nach dem 1sten = übernehmen
			cliVal = v[strings.Index(v, "=")+1:]
			// fmt.Printf("Assign '%s' to Config file  \n", cliVal)
			return cliVal, true
		}
	}
	return string(""), false
}
