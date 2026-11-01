//go:build with_naive_outbound

package main

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/sagernet/cronet-go"
	tun "github.com/sagernet/sing-tun"

	"github.com/spf13/cobra"
)

type cronetLibraryVerification struct {
	Path      string
	SHA256    string
	Bytes     int64
	Selection string
}

func init() {
	var library, digest, expectedVersion string
	command := &cobra.Command{
		Use: "cronet", Short: "Verify local Cronet linkage and version without starting networking", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if expectedVersion == "" {
				return fmt.Errorf("--expected-version is required")
			}
			verified, err := prepareCronetLibraryObservation(library, digest)
			if err != nil {
				return err
			}
			engine := cronet.NewEngine()
			defer engine.Destroy()
			version := engine.Version()
			if version != expectedVersion {
				return fmt.Errorf("Cronet version mismatch: got %q, want %q", version, expectedVersion)
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				OS               string `json:"os"`
				Arch             string `json:"arch"`
				Go               string `json:"go"`
				Linkage          string `json:"linkage"`
				Library          string `json:"library,omitempty"`
				SHA256           string `json:"sha256,omitempty"`
				LibraryBytes     int64  `json:"libraryBytes,omitempty"`
				LibrarySelection string `json:"librarySelection,omitempty"`
				Version          string `json:"version"`
				GVisor           bool   `json:"gvisorCompiled"`
			}{runtime.GOOS, runtime.GOARCH, runtime.Version(), cronetLinkage, verified.Path, verified.SHA256, verified.Bytes, verified.Selection, version, tun.WithGVisor})
		},
	}
	command.Flags().StringVar(&library, "library", "", "Explicit shared library path; omit for a captured sealed library FD (purego builds)")
	command.Flags().StringVar(&digest, "sha256", "", "Expected library SHA-256 (required for purego)")
	command.Flags().StringVar(&expectedVersion, "expected-version", "", "Exact expected Cronet engine version")
	commandTools.AddCommand(command)
}
