package cmd

import (
	"fmt"
	"os"

	"github.com/mosajjal/potash/pkg/rest"
	"github.com/spf13/cobra"
)

var (
	// Used for flags.
	listen   string
	basePath string
	tlsCert  string
	tlsKey   string

	restCmd = &cobra.Command{
		Use:   "rest",
		Short: "run rest API",
		Long:  `run rest API`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := rest.RunRest(gobPath, listen, basePath, tlsCert, tlsKey); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	restCmd.Flags().StringVarP(&listen, "listen", "l", "0.0.0.0:5555", "listen address")
	restCmd.Flags().StringVarP(&basePath, "basepath", "b", "/", "base path")
	restCmd.Flags().StringVarP(&tlsCert, "tlscert", "c", "", "TLS certificate")
	restCmd.Flags().StringVarP(&tlsKey, "tlskey", "k", "", "TLS key")
	rootCmd.AddCommand(restCmd)
}
