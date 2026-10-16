package main

import (
	"fmt"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/spf13/cobra"
)

func init() {
	commandTools.AddCommand(&cobra.Command{
		Use: "tls-fingerprints", Short: "Print this core's uTLS profile and build capabilities as JSON", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			document, err := tls.FingerprintCapabilitiesJSON()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), document)
			return err
		},
	})
}
