package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type cronetPatchChange struct {
	before, after *cronetOverlayFile
}

type cronetPatchHunk struct {
	oldLine, newLine int
	removed, added   [][]byte
}

var cronetHunkHeader = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@\n$`)

const cronetNoNewline = "\\ No newline at end of file\n"

func nextCronetPatchLine(raw []byte) (line, rest []byte) {
	end := bytes.IndexAny(raw, "\r\n")
	if end < 0 {
		return raw, nil
	}
	end++
	if raw[end-1] == '\r' && end < len(raw) && raw[end] == '\n' {
		end++
	}
	return raw[:end], raw[end:]
}

func parseCronetHunk(raw []byte) (cronetPatchHunk, []byte, error) {
	var hunk cronetPatchHunk
	header, raw := nextCronetPatchLine(raw)
	fields := cronetHunkHeader.FindSubmatch(header)
	if fields == nil {
		return hunk, nil, fmt.Errorf("patch hunk header differs")
	}
	var values [4]int
	for i, field := range fields[1:] {
		values[i] = 1
		if len(field) != 0 {
			value, err := strconv.Atoi(string(field))
			if err != nil {
				return hunk, nil, fmt.Errorf("patch coordinate exceeds bounds")
			}
			values[i] = value
		}
	}
	oldLine, oldCount, newLine, newCount := values[0], values[1], values[2], values[3]
	hunk.oldLine, hunk.newLine = oldLine, newLine
	if oldCount == 0 && newCount == 0 {
		return hunk, nil, fmt.Errorf("empty zero-context hunk")
	}
	for len(hunk.removed) < oldCount || len(hunk.added) < newCount {
		line, rest := nextCronetPatchLine(raw)
		raw = rest
		if len(line) == 0 {
			return hunk, nil, fmt.Errorf("truncated patch hunk")
		}
		target, count := &hunk.removed, oldCount
		switch line[0] {
		case '+':
			target, count = &hunk.added, newCount
		case '-':
		default:
			return hunk, nil, fmt.Errorf("nonzero-context patch hunk")
		}
		if len(*target) >= count {
			return hunk, nil, fmt.Errorf("zero-context patch quantity differs")
		}
		body := line[1:]
		if bytes.HasPrefix(raw, []byte(cronetNoNewline)) {
			if !bytes.HasSuffix(body, []byte{'\n'}) {
				return hunk, nil, fmt.Errorf("invalid no-newline marker")
			}
			body, raw = body[:len(body)-1], raw[len(cronetNoNewline):]
		}
		*target = append(*target, body)
	}
	return hunk, raw, nil
}

func applyCronetPatch(raw []byte, hunks []cronetPatchHunk, reverse bool) ([]byte, error) {
	var result []byte
	sourceLine, outputLine := 0, 0
	for _, hunk := range hunks {
		oldLine, newLine, removed, added := hunk.oldLine, hunk.newLine, hunk.removed, hunk.added
		if reverse {
			oldLine, newLine, removed, added = newLine, oldLine, added, removed
		}
		if len(removed) != 0 {
			oldLine--
		}
		if len(added) != 0 {
			newLine--
		}
		if oldLine < sourceLine {
			return nil, fmt.Errorf("cold patch exact source coordinates differ")
		}
		for sourceLine < oldLine {
			line, rest := nextCronetPatchLine(raw)
			if len(line) == 0 {
				return nil, fmt.Errorf("cold patch exact source coordinates differ")
			}
			result = append(result, line...)
			raw = rest
			sourceLine++
			outputLine++
		}
		if outputLine != newLine {
			return nil, fmt.Errorf("cold patch exact output coordinates differ")
		}
		for _, wanted := range removed {
			line, rest := nextCronetPatchLine(raw)
			if len(line) == 0 || !bytes.Equal(line, wanted) {
				return nil, fmt.Errorf("cold patch exact source mismatch")
			}
			raw = rest
			sourceLine++
		}
		for _, line := range added {
			result = append(result, line...)
		}
		outputLine += len(added)
	}
	return append(result, raw...), nil
}

func replayCronetPatch(raw []byte, changes map[string]cronetPatchChange, current map[string][]byte) error {
	seen := make(map[string]bool)
	for len(raw) != 0 {
		oldLine, rest := nextCronetPatchLine(raw)
		newLine, rest := nextCronetPatchLine(rest)
		raw = rest
		old, oldOK := strings.CutPrefix(string(oldLine), "--- ")
		new, newOK := strings.CutPrefix(string(newLine), "+++ ")
		if !oldOK || !newOK || !strings.HasSuffix(old, "\n") || !strings.HasSuffix(new, "\n") {
			return fmt.Errorf("patch header differs")
		}
		old, new = strings.TrimSuffix(old, "\n"), strings.TrimSuffix(new, "\n")
		name, found := strings.CutPrefix(new, "b/")
		if !found {
			name = strings.TrimPrefix(old, "a/")
		}
		change, found := changes[name]
		if !found || seen[name] {
			return fmt.Errorf("extra or duplicate patch path: %s", name)
		}
		oldPath, newPath := "/dev/null", "/dev/null"
		if change.before != nil {
			oldPath = "a/" + name
		}
		if change.after != nil {
			newPath = "b/" + name
		}
		if old != oldPath || new != newPath {
			return fmt.Errorf("patch path/operation mismatch: %s", name)
		}
		seen[name] = true

		var hunks []cronetPatchHunk
		for len(raw) != 0 && !bytes.HasPrefix(raw, []byte("--- ")) {
			hunk, rest, err := parseCronetHunk(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			hunks, raw = append(hunks, hunk), rest
		}
		if len(hunks) == 0 {
			return fmt.Errorf("empty patch section: %s", name)
		}
		after := current[name]
		before, err := applyCronetPatch(after, hunks, true)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if change.before == nil {
			if len(before) != 0 {
				return fmt.Errorf("added path has nonempty base: %s", name)
			}
		} else if err := change.before.verify(before, sha256Hex(before)); err != nil {
			return err
		}
		reconstructed, err := applyCronetPatch(before, hunks, false)
		if err != nil || !bytes.Equal(reconstructed, after) {
			return fmt.Errorf("cold forward reconstruction differs: %s", name)
		}
	}
	if len(seen) != len(changes) {
		return fmt.Errorf("missing patch path")
	}
	return nil
}
