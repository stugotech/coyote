package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stugotech/coyote/secret"
)

// newkeyCmd represents the newkey command
var newkeyCmd = &cobra.Command{
	Use:   "newkey",
	Short: "Creates a new value suitable for passing as --seal-key",
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := secret.NewKeyString()
		if err != nil {
			return NewCommandErrorF(255, "can't create seal key: %v", err)
		}
		fmt.Printf("New seal key: %s\n", key)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(newkeyCmd)
}
