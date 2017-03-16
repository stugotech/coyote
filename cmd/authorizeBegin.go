package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// authorizeBeginCmd represents the authorizeBegin command
var authorizeBeginCmd = &cobra.Command{
	Use:   "begin [domain]",
	Short: "Begin authorization on the given domain by requesting a challenge",

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
		challenge, err := coy.BeginAuthorize(args[0])
		if err != nil {
			return NewCommandErrorF(255, "unable to get challenge: %v", err)
		}
		fmt.Printf("Challenge for domain %s\n\tURI = %q\n\tPath = %q\n\tResponse = %q\n", args[0], challenge.AuthChallenge.URI, challenge.Path, challenge.Response)
		return nil
	},
}

func init() {
	authorizeCmd.AddCommand(authorizeBeginCmd)
}
