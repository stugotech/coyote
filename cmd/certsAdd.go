package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// certsAddCmd represents the certsAdd command
var certsAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new certificate",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("certificates add called")
	},
}

func init() {
	certsCmd.AddCommand(certsAddCmd)
}
