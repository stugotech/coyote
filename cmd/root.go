package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stugotech/coyote/coyote"
	"github.com/stugotech/coyote/store"
)

// Flag names
const (
	AcceptTOSFlag          = "accept-tos"
	AcmeDirectoryFlag      = "acme-directory"
	ConfigFlag             = "config"
	DomainFlag             = "domain"
	EmailFlag              = "email"
	LetsEncryptStagingFlag = "le-staging"
	LogFlag                = "log"
	PathPrefixFlag         = "path-prefix"
	SANFlag                = "san"
	SealKeyFlag            = "seal-key"
	StoreFlag              = "store"
	StoreNodesFlag         = "store-nodes"
	StorePrefixFlag        = "store-prefix"
)

// Default flag values
var (
	AcmeDirectoryProduction = "https://acme-v01.api.letsencrypt.org/directory"
	AcmeDirectoryDefault    = "https://acme-staging.api.letsencrypt.org/directory"
	LogDefault              = "info"
	StoreDefault            = "etcd"
	StoreNodesDefault       = []string{"127.0.0.1:2379"}
	StorePrefixDefault      = "coyote"
)

var configFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "coyote",
	Short: "A utility to automate creation of TLS certificates using the ACME protocol",
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	pf := RootCmd.PersistentFlags()

	pf.StringVar(&configFile, ConfigFlag, "", "config file")

	// ACME settings
	pf.String(AcmeDirectoryFlag, AcmeDirectoryDefault, "ACME directory")
	pf.Bool(AcceptTOSFlag, false, "accept the terms of the ACME service")
	pf.String(EmailFlag, "", "the contact email address of the registrant")

	// KV store settings
	pf.String(StoreFlag, StoreDefault, "Name of the KV store to use [etcd|consul|boltdb|zookeeper]")
	pf.StringSlice(StoreNodesFlag, StoreNodesDefault, "Comma-seperated list of KV store nodes")
	pf.String(StorePrefixFlag, StorePrefixDefault, "Base path for values in KV store")

	// other settings
	pf.String(SealKeyFlag, "", "Key used to encrypt secret values")

	// bind all persistent flags to config
	viper.BindPFlags(pf)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if configFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(configFile)
	}

	viper.SetConfigName(".coyote") // name of config file (without extension)
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME")
	viper.AddConfigPath("/etc/coyote")
	viper.SetEnvPrefix("coyote")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file: ", viper.ConfigFileUsed())
	}
}

func createCoyoteFromConfig() (coyote.Coyote, error) {
	store, err := store.NewStore(
		viper.GetString(StoreFlag),
		viper.GetStringSlice(StoreNodesFlag),
		viper.GetString(StorePrefixFlag),
	)
	if err != nil {
		return nil, err
	}
	return coyote.NewCoyote(
		&coyote.Config{
			AcceptTOS:    viper.GetBool(AcceptTOSFlag),
			ContactEmail: viper.GetString(EmailFlag),
			DirectoyURI:  viper.GetString(AcmeDirectoryFlag),
			SecretKey:    viper.GetString(SealKeyFlag),
			Store:        store,
		},
	)
}
