package cmd

import (
	"github.com/spf13/cobra"
)

// authorizeCmd represents the authorize command
var authorizeCmd = &cobra.Command{
	Use:     "authorize",
	Short:   "Authorize a domain under your control",
	Aliases: []string{"auth"},
}

func init() {
	RootCmd.AddCommand(authorizeCmd)
}
