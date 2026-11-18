package main

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const (
	repository   = "polaris-arch/sing-box-polaris"
	repositoryID = "1421657509"
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
	case "record-candidate":
		return recordCandidate(args[1:])
	case "publisher-receipt":
		return publisherReceipt(args[1:])
	case "peer-metadata":
		return peerMetadata(args[1:])
	case "tls-gate":
		return tlsGate(args[1:])
	case "tls-cost":
		return tlsCost(args[1:])
	default:
		return fmt.Errorf("unknown CI command: %s", args[0])
	}
}

func nativeEnvironment(names ...string) (map[string]string, error) {
	values := make(map[string]string, len(names))
	for _, name := range names {
		value, present := os.LookupEnv(name)
		if !present {
			return nil, fmt.Errorf("missing native environment: %s", name)
		}
		values[name] = value
	}
	return values, nil
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// Native needs must not resolve duplicate object keys by last-writer wins.
// Keep JSON numbers exact while checking the whole value.
func uniqueJSON(input io.Reader, target any) error {
	strict := jsontext.NewDecoder(input, jsontext.AllowDuplicateNames(false))
	raw, err := strict.ReadValue()
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	// ReadValue's buffer belongs to strict: consume it before checking for EOF.
	if _, err := strict.ReadToken(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("multiple JSON values")
	}
	return nil
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
