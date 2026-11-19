package main

import (
	"context"
	"os"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"

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

func decodeRuleSetSource(content []byte) (option.PlainRuleSetCompat, error) {
	ctx := globalCtx
	if ctx == nil {
		ctx = context.Background()
	}
	// The file/stdin byte limit was applied before acquisition. The normalized
	// merge output is an internal value; the rule tree still has the same cap.
	return srs.ReadSourceContextWithLimits(ctx, content, srs.ReadLimits{InputBytes: int64(len(content))})
}
