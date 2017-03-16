package cmd

import (
	"time"

	"github.com/spf13/cobra"
)

// certsRenewCmd represents the certsRenew command
var certsRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renews any certificates which need renewing",
	RunE: func(cmd *cobra.Command, args []string) error {
		// init
		coy, err := createCoyoteFromConfig()
		if err != nil {
			return NewCommandErrorF(255, "unable to create coyote: %v", err)
		}
		// renew certificates that will expire in less than a week
		err = coy.RenewExpiringCertificates(time.Duration(7) * time.Hour * 24)
		if err != nil {
			return NewCommandErrorF(255, "unable to renew certificates (%v): %v", args, err)
		}
		return nil
	},
}

func init() {
	certsCmd.AddCommand(certsRenewCmd)
}
