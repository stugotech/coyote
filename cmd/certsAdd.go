package cmd

import (
	"github.com/spf13/cobra"
)

// certsAddCmd represents the certsAdd command
var certsAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return NewCommandError(2, "must specify one or more domains")
		}
		// init
		coy, err := createCoyoteFromConfig()
		if err != nil {
			return NewCommandErrorF(255, "unable to create coyote: %v", err)
		}
		// get certificate
		err = coy.NewCertificate(args)
		if err != nil {
			return NewCommandErrorF(255, "unable to get certificates (%v): %v", args, err)
		}
		return nil
	},
}

func init() {
	certsCmd.AddCommand(certsAddCmd)
}
