package cmd

import (
	"time"

	"github.com/spf13/cobra"
)

// certsWatchCmd represents the certsWatch command
var certsWatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Run every day and renew the certificates that will expire soon",
	RunE: func(cmd *cobra.Command, args []string) error {
		// init
		coy, err := createCoyoteFromConfig()
		if err != nil {
			return NewCommandErrorF(255, "unable to create coyote: %v", err)
		}
		// renew certificates that will expire in less than a week
		coy.RenewLoop(time.Duration(1)*time.Hour, time.Duration(7)*time.Hour*24)
		return nil
	},
}

func init() {
	certsCmd.AddCommand(certsWatchCmd)
}
