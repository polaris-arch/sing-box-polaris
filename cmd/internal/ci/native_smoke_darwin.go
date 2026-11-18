package main

import (
	"bytes"
	"context"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

func prepareNativeSmoke(ctx context.Context, core string, row map[string]any, _ map[string][]byte, execution *nativeSmokeExecution) (err error) {
	if row["variant"].(map[string]any)["legacy"] == true {
		return nil
	}
	archive := row["archive"].(map[string]any)
	if err := validateMacNativeRow(row, archive); err != nil {
		return err
	}
	translated, err := unix.SysctlUint32("sysctl.proc_translated")
	if err != nil && !errors.Is(err, unix.ENOENT) || translated > 1 {
		return fmt.Errorf("Mac native translation state is unknown")
	}
	if translated != 0 {
		return fmt.Errorf("Mac translated execution cannot provide native proof")
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "DYLD_") || strings.HasPrefix(entry, "LD_") {
			return fmt.Errorf("Mac ambient loader overrides are unsupported")
		}
	}
	fd, err := unix.Open(core, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), core)
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()

	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return err
	}
	pin := row["core"].(map[string]any)
	size, _ := nativePositiveInteger(pin["bytes"])
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size != size {
		return fmt.Errorf("Mac final Core object differs")
	}
	// Holding the file detects archive-to-observation and namespace drift.
	// The root private factory is the separate runtime execution boundary.
	same := func(current unix.Stat_t) bool {
		return current.Dev == before.Dev && current.Ino == before.Ino && current.Mode == before.Mode &&
			current.Nlink == before.Nlink && current.Size == before.Size && current.Mtim == before.Mtim && current.Ctim == before.Ctim
	}
	current := func() error {
		var held, named unix.Stat_t
		if err := unix.Fstat(fd, &held); err != nil {
			return err
		}
		if err := unix.Lstat(core, &named); err != nil {
			return err
		}
		if !same(held) || !same(named) {
			return fmt.Errorf("Mac post-sign object/namespace changed")
		}
		return nil
	}
	data, err := readNativeBytes(file, size)
	if err != nil {
		return err
	}
	if int64(len(data)) != size || sha256Hex(data) != pin["sha256"] {
		return fmt.Errorf("Mac final post-sign digest differs")
	}
	arch := strings.TrimPrefix(row["target"].(string), "darwin/")
	loader, err := macNativeLoader(data, arch)
	if err != nil {
		return err
	}
	observe := func() (map[string]any, error) {
		if err := current(); err != nil {
			return nil, err
		}
		version, _, graph, err := nativeBuildInfo(core)
		if err != nil {
			return nil, err
		}
		rawGraph, err := json.Marshal(graph)
		if err != nil {
			return nil, err
		}
		var actual map[string]any
		if err := decodeNativeJSON(bytes.NewReader(rawGraph), &actual); err != nil {
			return nil, err
		}
		buildCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		buildID, _, code, err := sourceCommandOutput(buildCtx, "", nil, 1<<20, "go", "tool", "buildid", core)
		cancel()
		if err != nil {
			return nil, err
		}
		if code == nil || *code != 0 || strings.TrimSpace(buildID) != row["buildID"] ||
			version != row["goVersion"] || !reflect.DeepEqual(actual, row["buildGraph"]) {
			return nil, fmt.Errorf("Mac actual post-sign Go metadata differs")
		}
		if err := current(); err != nil {
			return nil, err
		}
		var diagnostic string
		for _, args := range [][]string{
			{"/usr/bin/codesign", "--verify", "--strict", core},
			{"/usr/bin/codesign", "--display", "--verbose=4", core},
		} {
			signCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			_, diagnostic, code, err = sourceCommandOutput(signCtx, "", nil, 1<<20, args...)
			cancel()
			if err != nil {
				return nil, err
			}
			if code == nil || *code != 0 {
				return nil, fmt.Errorf("Mac actual strict signature verification failed")
			}
		}
		hashes := nativeCDHash.FindAllStringSubmatch(diagnostic, -1)
		if len(hashes) != 1 {
			return nil, fmt.Errorf("Mac exactly one actual signature CDHash required")
		}
		hash := hashes[0][1]
		if !reflect.DeepEqual(row["signatureObservation"], map[string]any{"state": "signed", "cdHash": hash, "trustValidated": false}) {
			return nil, fmt.Errorf("Mac collected signature differs from final bytes")
		}
		if err := current(); err != nil {
			return nil, err
		}
		if _, err := file.Seek(0, 0); err != nil {
			return nil, err
		}
		after, err := readNativeBytes(file, size)
		if err != nil {
			return nil, err
		}
		if err := current(); err != nil {
			return nil, err
		}
		if !bytes.Equal(after, data) {
			return nil, fmt.Errorf("Mac post-sign bytes changed during observation")
		}
		return map[string]any{
			"coreSHA256": pin["sha256"], "coreBytes": size, "cdHash": hash, "signatureVerified": true, "nativeLoader": loader,
		}, nil
	}
	initial, err := observe()
	if err != nil {
		return err
	}
	execution.close = file.Close
	execution.proofKey = "macosExecution"
	execution.observe = func() (map[string]any, error) {
		after, err := observe()
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(after, initial) {
			return nil, fmt.Errorf("Mac post-sign observation changed during native smoke")
		}
		return map[string]any{"schema": "polaris-macos-native-execution-proof-v1", "postSign": after}, nil
	}
	return nil
}

func macNativeLoader(data []byte, arch string) (map[string]any, error) {
	const headerSize = 32
	cpu, knownCPU := map[string]macho.Cpu{"amd64": macho.CpuAmd64, "arm64": macho.CpuArm64}[arch]
	read := binary.LittleEndian.Uint32
	if len(data) < headerSize || !knownCPU || read(data) != macho.Magic64 ||
		macho.Cpu(read(data[4:])) != cpu || macho.Type(read(data[12:])) != macho.TypeExec {
		return nil, fmt.Errorf("Mac thin native executable header differs")
	}
	count, size := int(read(data[16:])), int(read(data[20:]))
	end := headerSize + size
	if count <= 0 || count > 4096 || size > 1<<20 || end > len(data) {
		return nil, fmt.Errorf("Mac thin native execution graph differs")
	}
	commands := data[headerSize:end]
	libraries := map[string]bool{}
	var dyld string
	var signature map[string]any
	for range count {
		if len(commands) < 8 {
			return nil, fmt.Errorf("Mac truncated load command")
		}
		kind, length := read(commands), int(read(commands[4:]))
		if length < 8 || length%8 != 0 || length > len(commands) {
			return nil, fmt.Errorf("Mac invalid load command size")
		}
		command := commands[:length]
		commands = commands[length:]
		switch kind {
		case 0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20: // dylib load commands
			library, err := macNativeLoaderPath(command, 24)
			if err != nil {
				return nil, err
			}
			if !nativeMacSystemLibrary(library) {
				return nil, fmt.Errorf("Mac non-system dependency requires its own proof")
			}
			libraries[library] = true
		case 0xe: // LC_LOAD_DYLINKER
			path, err := macNativeLoaderPath(command, 12)
			if err != nil {
				return nil, err
			}
			if dyld != "" || path != "/usr/lib/dyld" {
				return nil, fmt.Errorf("Mac ambiguous or unsupported dyld")
			}
			dyld = path
		case 0x1d: // LC_CODE_SIGNATURE
			if len(command) != 16 || signature != nil {
				return nil, fmt.Errorf("Mac ambiguous signature command")
			}
			start, length := int(read(command[8:])), int(read(command[12:]))
			if length <= 0 || start < end || start > len(data) || length > len(data)-start {
				return nil, fmt.Errorf("Mac invalid post-sign range")
			}
			signature = map[string]any{"signatureOffset": start, "signatureBytes": length, "signatureSHA256": sha256Hex(data[start : start+length])}
		case 0x19, 0x2, 0xb, 0x1b, 0x32, 0x2a, 0x80000028, 0x26, 0x29, 0x80000022, 0x80000033, 0x80000034, 0x24, 0x4, 0x5:
			// Commands in the closed native profile without external dependencies.
		default:
			return nil, fmt.Errorf("Mac unknown/search/environment/encrypted loader command")
		}
	}
	if len(commands) != 0 || signature == nil || dyld == "" {
		return nil, fmt.Errorf("Mac incomplete signed loader graph")
	}
	maps.Copy(signature, map[string]any{
		"arch": arch, "dyld": dyld, "libraries": slices.Sorted(maps.Keys(libraries)), "commandsSHA256": sha256Hex(data[:end]),
	})
	if len(libraries) == 0 {
		signature["libraries"] = []string{}
	}
	return signature, nil
}

func macNativeLoaderPath(command []byte, minimum int) (string, error) {
	if len(command) < minimum {
		return "", fmt.Errorf("Mac truncated loader command")
	}
	offset := int(binary.LittleEndian.Uint32(command[8:]))
	if offset < minimum || offset >= len(command) {
		return "", fmt.Errorf("Mac loader name offset differs")
	}
	path, _, terminated := bytes.Cut(command[offset:], []byte{0})
	if !terminated || !utf8.Valid(path) {
		return "", fmt.Errorf("Mac malformed or unterminated loader name")
	}
	return string(path), nil
}
