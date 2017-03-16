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

		day := time.Duration(7) * time.Hour * 24
		for {
			// renew certificates that will expire in less than a week
			certs, err := coy.RenewExpiringCertificates(day * 7)
			if err == nil {
				err = certificateSync(certs)
			}
			if err != nil {
				logger.Errore(err)
			}
			time.Sleep(day)
		}
	},
}

func init() {
	certsCmd.AddCommand(certsWatchCmd)
}
