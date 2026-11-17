package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("expected a CI command")
	}
	switch args[0] {
	case "patch-packages":
		return patchPackages(args[1:])
	case "g4-candidate":
		return g4Candidate(args[1:])
	case "check-sdk-selection":
		return checkSDKSelection(args[1:])
	case "check-format":
		return checkFormat(args[1:])
	case "runtime-proto":
		return runtimeProto(args[1:])
	default:
		return fmt.Errorf("unknown CI command: %s", args[0])
	}
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writeJSONFile(filename string, value any) error {
	output, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	err = writeJSON(output, value)
	closeErr := output.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func git(directory string, args ...string) ([]byte, error) {
	command := exec.Command("git", args...)
	command.Dir = directory
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return output, nil
}
