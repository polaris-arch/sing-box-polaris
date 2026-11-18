package main

import (
	"os"

	"github.com/sagernet/sing-box/common/srs"

	"github.com/spf13/cobra"
)

var commandRuleSet = &cobra.Command{
	Use:   "rule-set",
	Short: "Manage rule-sets",
}

func init() {
	mainCommand.AddCommand(commandRuleSet)
}

func openRuleSetInput(path string) (*os.File, error) {
	if path == "stdin" {
		return os.Stdin, nil
	}
	return os.Open(path)
}

func readRuleSetContent(path string, limit int64) ([]byte, error) {
	reader, err := openRuleSetInput(path)
	if err != nil {
		return nil, err
	}
	if path != "stdin" {
		defer reader.Close()
	}
	return srs.ReadContent(reader, limit)
}
