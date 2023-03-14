package cmd

import (
	"fmt"
	"os"

	potash "github.com/mosajjal/potash/pkg"
	"github.com/rs/zerolog"

	"github.com/spf13/cobra"
)

var (
	// Used for flags.
	csvPath       string
	gobPath       string
	forceGenerate bool
	hash          string
	outputFormat  string // format of the output. options: JSON, CSV, Table, YAML
	radius        uint16

	rootCmd = &cobra.Command{
		Use:   "potash",
		Short: "potash is awesome",
		Long: `potash consumes the abuse.ch malware export CSV file, generates a trie based on
		the TLSH hashes and then provides a CLI to query the trie for similar hashes`,
		// Run: func(cmd *cobra.Command, args []string) {
		// 	if err := potash.RunOnce(gobPath, hash, radius); err != nil {
		// 		fmt.Println(err)
		// 		os.Exit(1)
		// 	}
		// },
	}

	generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "generate a new tree",
		Long:  `generate a new tree`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := potash.Generate(csvPath, gobPath, forceGenerate); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	runOnceCmd = &cobra.Command{
		Use:   "runonce",
		Short: "run once",
		Long:  `compare a hash with the tree and exit`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := potash.RunOnce(gobPath, hash, radius, outputFormat); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	runInteractiveCmd = &cobra.Command{
		Use:   "runinteractive",
		Short: "run interactive",
		Long:  `compare hashes from input/stdin with the tree and exit`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := potash.RunInteractive(gobPath, radius, outputFormat); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {

	runOnceCmd.Flags().StringVarP(&gobPath, "treegob", "t", "./tree.gob", "path to the tree gob file")
	runOnceCmd.Flags().StringVarP(&hash, "tlsh", "s", "T1A6144B2D62EA2CD4E97A817CC8868251D5B370362712B1EF02E0C57C9F17AE97A7DF41", "hash of the file")
	// make tlsh required
	runOnceCmd.MarkFlagRequired("tlsh")
	runOnceCmd.Flags().Uint16VarP(&radius, "count", "c", 10, "number of output neighbours")
	runOnceCmd.Flags().StringVarP(&outputFormat, "format", "f", "json", "output format. options: json, table, yaml")

	generateCmd.Flags().StringVarP(&csvPath, "csv", "c", "./malware.csv", "path to the abuse.ch CSV file")
	// make csv required
	generateCmd.MarkFlagRequired("csv")
	generateCmd.Flags().StringVarP(&gobPath, "treegob", "t", "./tree.gob", "path to the tree gob file")
	generateCmd.Flags().BoolVarP(&forceGenerate, "force", "f", false, "force overwrite of the existing tree")

	runInteractiveCmd.Flags().StringVarP(&gobPath, "treegob", "t", "./tree.gob", "path to the tree gob file")
	runInteractiveCmd.Flags().Uint16VarP(&radius, "count", "c", 10, "number of output neighbours")
	runInteractiveCmd.Flags().StringVarP(&outputFormat, "format", "f", "json", "output format. options: json, csv, table, yaml")

	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(runOnceCmd)
	rootCmd.AddCommand(runInteractiveCmd)

	// set up logging
	// set log level
	if l, err := zerolog.ParseLevel("debug"); err == nil {
		zerolog.SetGlobalLevel(l)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}
