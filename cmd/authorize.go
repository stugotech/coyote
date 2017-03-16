package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// authorizeCmd represents the authorize command
var authorizeCmd = &cobra.Command{
	Use:     "authorize",
	Short:   "Authorize a domain under your control",
	Aliases: []string{"auth"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return NewCommandError(2, "must specify domain")
		}
		// init
		coy, err := createCoyoteFromConfig()
		if err != nil {
			return NewCommandErrorF(255, "unable to create coyote: %v", err)
		}
		// get challenge
		err = coy.Authorize(args[0])
		if err != nil {
			return NewCommandErrorF(255, "unable to authorize domain: %v", err)
		}
		fmt.Printf("authorization of domain %q successfull\n", args[0])
		return nil
	},
}

func init() {
	RootCmd.AddCommand(authorizeCmd)
}
