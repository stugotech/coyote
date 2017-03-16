package cmd

import (
	"github.com/spf13/cobra"
)

// certsCmd represents the certs command
var certsCmd = &cobra.Command{
	Aliases: []string{"certs"},
	Use:     "certificates [command]",
	Short:   "Manage ACME certificates",
}

func init() {
	RootCmd.AddCommand(certsCmd)
}
