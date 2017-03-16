package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stugotech/coyote/server"
	"github.com/stugotech/goconfig"
)

// listenCmd represents the listen command
var listenCmd = &cobra.Command{
	Use:   "listen [interface]",
	Short: "Listen for and solve ACME challenges",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return NewCommandError(2, "must specify interface to listen on")
		}
		viper.Set(server.ListenKey, args[0])
		srv, err := server.NewServerFromConfig(goconfig.Viper())
		if err != nil {
			return NewCommandErrorF(255, "can't create server: %v", err)
		}
		err = srv.Listen()
		if err != nil {
			return NewCommandErrorF(255, "error while waiting for challenges: %v", err)
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(listenCmd)
	fl := listenCmd.Flags()
	fl.String(server.PathPrefixKey, server.PathPrefixDefault, "the prefix for the URI path to ACME challenges")
	viper.BindPFlags(fl)
}
