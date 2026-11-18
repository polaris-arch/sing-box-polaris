package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/rw"

	"github.com/spf13/cobra"
)

var (
	ruleSetPaths       []string
	ruleSetDirectories []string
)

var commandRuleSetMerge = &cobra.Command{
	Use:   "merge <output-path>",
	Short: "Merge rule-set source files",
	Run: func(cmd *cobra.Command, args []string) {
		err := mergeRuleSet(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
	Args: cobra.ExactArgs(1),
}

func init() {
	commandRuleSetMerge.Flags().StringArrayVarP(&ruleSetPaths, "config", "c", nil, "set input rule-set file path")
	commandRuleSetMerge.Flags().StringArrayVarP(&ruleSetDirectories, "config-directory", "C", nil, "set input rule-set directory path")
	commandRuleSet.AddCommand(commandRuleSetMerge)
}

type RuleSetEntry struct {
	path    string
	options option.PlainRuleSetCompat
}

func readRuleSet() ([]*RuleSetEntry, error) {
	var optionsList []*RuleSetEntry
	remaining := srs.DefaultInputBytes
	readEntry := func(path string) error {
		if remaining == 0 {
			return E.Cause(srs.ErrResourceLimit, "read config at ", path)
		}
		content, err := readRuleSetContent(path, remaining)
		if err != nil {
			return E.Cause(err, "read config at ", path)
		}
		remaining -= int64(len(content))
		options, err := json.UnmarshalExtendedContext[option.PlainRuleSetCompat](globalCtx, content)
		if err != nil {
			return E.Cause(err, "decode config at ", path)
		}
		optionsList = append(optionsList, &RuleSetEntry{path: path, options: options})
		return nil
	}
	for _, path := range ruleSetPaths {
		if err := readEntry(path); err != nil {
			return nil, err
		}
	}
	for _, directory := range ruleSetDirectories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, E.Cause(err, "read rule-set directory at ", directory)
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") || entry.IsDir() {
				continue
			}
			if err := readEntry(filepath.Join(directory, entry.Name())); err != nil {
				return nil, err
			}
		}
	}
	sort.Slice(optionsList, func(i, j int) bool {
		return optionsList[i].path < optionsList[j].path
	})
	return optionsList, nil
}

func readRuleSetAndMerge() (option.PlainRuleSetCompat, error) {
	optionsList, err := readRuleSet()
	if err != nil {
		return option.PlainRuleSetCompat{}, err
	}
	if len(optionsList) == 1 {
		return optionsList[0].options, nil
	}
	var optionVersion uint8
	for _, options := range optionsList {
		if optionVersion < options.options.Version {
			optionVersion = options.options.Version
		}
	}
	var mergedMessage json.RawMessage
	for _, options := range optionsList {
		mergedMessage, err = badjson.MergeJSON(globalCtx, options.options.RawMessage, mergedMessage, false)
		if err != nil {
			return option.PlainRuleSetCompat{}, E.Cause(err, "merge config at ", options.path)
		}
	}
	mergedOptions, err := json.UnmarshalExtendedContext[option.PlainRuleSetCompat](globalCtx, mergedMessage)
	if err != nil {
		return option.PlainRuleSetCompat{}, E.Cause(err, "unmarshal merged config")
	}
	mergedOptions.Version = optionVersion
	return mergedOptions, nil
}

func mergeRuleSet(outputPath string) error {
	mergedOptions, err := readRuleSetAndMerge()
	if err != nil {
		return err
	}
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(mergedOptions)
	if err != nil {
		return E.Cause(err, "encode config")
	}
	err = rw.MkdirParent(outputPath)
	if err != nil {
		return err
	}
	err = os.WriteFile(outputPath, buffer.Bytes(), 0o644)
	if err != nil {
		return err
	}
	outputPath, _ = filepath.Abs(outputPath)
	os.Stderr.WriteString(outputPath + "\n")
	return nil
}
