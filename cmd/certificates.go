package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stugotech/coyote/store"
	"github.com/stugotech/coyote/sync"
	"github.com/stugotech/coyote/sync/vulcand"
)

// Flags
const (
	VulcandKey = "vulcand"
)

// certsCmd represents the certs command
var certsCmd = &cobra.Command{
	Aliases: []string{"certs"},
	Use:     "certificates [command]",
	Short:   "Manage ACME certificates",
}

func init() {
	RootCmd.AddCommand(certsCmd)
	pf := certsCmd.PersistentFlags()
	pf.String(VulcandKey, "", "A vulcand API endpoint to sync with")
	viper.BindPFlags(pf)
}

func certificateSync(certs []*store.Certificate) error {
	vulcandEndpoint := viper.GetString(VulcandKey)
	if vulcandEndpoint == "" {
		return nil
	}

	vulcandClient := vulcand.NewClient(vulcandEndpoint)
	return sync.Certificates(certs, vulcandClient)
}
