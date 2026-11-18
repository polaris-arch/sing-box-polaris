package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path"
	"slices"
	"strings"
)

type artifactZIP struct {
	file    *os.File
	members []*zip.File
	offsets map[*zip.File]int64
}

// Inspect the bounded directory before archive/zip allocates entries. The
// offsets also retain the local-name/overlap checks not exposed by Go's API.
func openArtifactZIP(file *os.File) (*artifactZIP, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	tail := make([]byte, min(size, 65557))
	if _, err := file.ReadAt(tail, size-int64(len(tail))); err != nil {
		return nil, err
	}
	end := bytes.LastIndex(tail, []byte("PK\x05\x06"))
	order := binary.LittleEndian
	if end < 0 || len(tail)-end < 22 {
		return nil, fmt.Errorf("ZIP end record missing")
	}
	header := tail[end:]
	if len(header) != 22+int(order.Uint16(header[20:])) || order.Uint32(header[4:]) != 0 ||
		order.Uint16(header[8:]) != order.Uint16(header[10:]) {
		return nil, fmt.Errorf("invalid/multidisk ZIP")
	}
	count, directorySize, directoryOffset := uint64(order.Uint16(header[10:])), uint64(order.Uint32(header[12:])), uint64(order.Uint32(header[16:]))
	endOffset := size - int64(len(tail)) + int64(end)
	if endOffset >= 20 {
		var locator [20]byte
		if _, err := file.ReadAt(locator[:], endOffset-20); err != nil {
			return nil, err
		}
		if bytes.Equal(locator[:4], []byte("PK\x06\x07")) {
			position := order.Uint64(locator[8:])
			if endOffset < 76 || order.Uint32(locator[4:]) != 0 || order.Uint32(locator[16:]) != 1 || position > uint64(endOffset-76) {
				return nil, fmt.Errorf("invalid ZIP64 locator")
			}
			var record [56]byte
			if _, err := file.ReadAt(record[:], int64(position)); err != nil {
				return nil, err
			}
			if !bytes.Equal(record[:4], []byte("PK\x06\x06")) || order.Uint64(record[4:]) < 44 ||
				order.Uint64(record[16:]) != 0 || order.Uint64(record[24:]) != order.Uint64(record[32:]) {
				return nil, fmt.Errorf("invalid/multidisk ZIP64")
			}
			count, directorySize, directoryOffset = order.Uint64(record[32:]), order.Uint64(record[40:]), order.Uint64(record[48:])
			endOffset = int64(position)
		}
	}
	if count == 0 || count > 16384 || directorySize > 32<<20 || directorySize > uint64(endOffset) || directoryOffset > uint64(endOffset)-directorySize {
		return nil, fmt.Errorf("ZIP directory exceeds evidence budget")
	}
	base := endOffset - int64(directorySize) - int64(directoryOffset)
	if base > 0 {
		var signature [4]byte
		if _, err := file.ReadAt(signature[:], int64(directoryOffset)); err == nil && bytes.Equal(signature[:], []byte("PK\x01\x02")) {
			base = 0
		}
	}
	directoryStart := base + int64(directoryOffset)
	section := io.NewSectionReader(file, directoryStart, int64(directorySize))
	var offsets []int64
	for consumed := int64(0); consumed < int64(directorySize); {
		var record [46]byte
		if _, err := io.ReadFull(section, record[:]); err != nil {
			return nil, err
		}
		if !bytes.Equal(record[:4], []byte("PK\x01\x02")) || len(offsets) >= int(count) {
			return nil, fmt.Errorf("ZIP directory record count differs")
		}
		nameSize, extraSize, commentSize := int64(order.Uint16(record[28:])), int64(order.Uint16(record[30:])), int64(order.Uint16(record[32:]))
		if nameSize+extraSize+commentSize > int64(directorySize)-consumed-46 {
			return nil, fmt.Errorf("truncated ZIP directory entry")
		}
		if _, err := section.Seek(nameSize, io.SeekCurrent); err != nil {
			return nil, err
		}
		extra := make([]byte, extraSize)
		if _, err := io.ReadFull(section, extra); err != nil {
			return nil, err
		}
		local := uint64(order.Uint32(record[42:]))
		if local == math.MaxUint32 {
			found := false
			for len(extra) >= 4 {
				id, length := order.Uint16(extra), int(order.Uint16(extra[2:]))
				extra = extra[4:]
				if length > len(extra) {
					return nil, fmt.Errorf("invalid ZIP64 extra field")
				}
				value := extra[:length]
				extra = extra[length:]
				if id != 1 {
					continue
				}
				for _, field := range []int{24, 20} {
					if order.Uint32(record[field:]) == math.MaxUint32 {
						if len(value) < 8 {
							return nil, fmt.Errorf("truncated ZIP64 size")
						}
						value = value[8:]
					}
				}
				if len(value) < 8 {
					return nil, fmt.Errorf("missing ZIP64 local offset")
				}
				local, found = order.Uint64(value), true
				break
			}
			if !found {
				return nil, fmt.Errorf("missing ZIP64 extra field")
			}
		}
		if local > uint64(directoryStart-base) || base+int64(local) > directoryStart-30 {
			return nil, fmt.Errorf("invalid local ZIP offset")
		}
		offsets = append(offsets, base+int64(local))
		if _, err := section.Seek(commentSize, io.SeekCurrent); err != nil {
			return nil, err
		}
		consumed += 46 + nameSize + extraSize + commentSize
	}
	if uint64(len(offsets)) != count {
		return nil, fmt.Errorf("ZIP directory record count differs")
	}
	archive, err := zip.NewReader(file, size)
	if err != nil {
		return nil, err
	}
	if len(archive.File) != len(offsets) {
		return nil, fmt.Errorf("ZIP directory interpretation differs")
	}
	ordered := slices.Clone(offsets)
	slices.Sort(ordered)
	ends := map[int64]int64{}
	for i, offset := range ordered {
		if _, exists := ends[offset]; exists {
			return nil, fmt.Errorf("overlapping ZIP local headers")
		}
		ends[offset] = directoryStart
		if i+1 < len(ordered) {
			ends[offset] = ordered[i+1]
		}
	}
	result := &artifactZIP{file, archive.File, map[*zip.File]int64{}}
	names, files := map[string]bool{}, map[string]bool{}
	for i, member := range archive.File {
		name, err := portableArtifactPath(member.Name)
		if err != nil || name != strings.TrimSuffix(member.Name, "/") {
			return nil, fmt.Errorf("noncanonical ZIP path: %s", member.Name)
		}
		folded := strings.ToLower(name)
		if names[folded] {
			return nil, fmt.Errorf("duplicate ZIP path: %s", name)
		}
		names[folded] = true
		mode := member.Mode()
		directory := strings.HasSuffix(member.Name, "/")
		if directory && !mode.IsDir() || !directory && !mode.IsRegular() || member.Flags&1 != 0 ||
			member.Method != zip.Store && member.Method != zip.Deflate || directory && member.UncompressedSize64 != 0 ||
			member.CompressedSize64 > math.MaxInt64 || member.UncompressedSize64 > math.MaxInt64 {
			return nil, fmt.Errorf("non-regular, encrypted or unsupported ZIP entry: %s", name)
		}
		if !directory {
			files[folded] = true
		}
		var local [30]byte
		if _, err := file.ReadAt(local[:], offsets[i]); err != nil {
			return nil, err
		}
		if !bytes.Equal(local[:4], []byte("PK\x03\x04")) || order.Uint16(local[6:]) != member.Flags || order.Uint16(local[8:]) != member.Method {
			return nil, fmt.Errorf("local ZIP header differs: %s", name)
		}
		localName := make([]byte, order.Uint16(local[26:]))
		if _, err := file.ReadAt(localName, offsets[i]+30); err != nil {
			return nil, err
		}
		dataOffset := offsets[i] + 30 + int64(len(localName)) + int64(order.Uint16(local[28:]))
		libraryOffset, err := member.DataOffset()
		if err != nil || string(localName) != member.Name || libraryOffset != dataOffset || dataOffset > ends[offsets[i]] ||
			member.CompressedSize64 > uint64(ends[offsets[i]]-dataOffset) {
			return nil, fmt.Errorf("mismatched or overlapping ZIP member: %s", name)
		}
		result.offsets[member] = dataOffset
	}
	for name := range names {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if files[parent] {
				return nil, fmt.Errorf("ZIP file/directory prefix collision")
			}
		}
	}
	return result, nil
}

func portableArtifactPath(name string) (string, error) {
	if path.IsAbs(name) || strings.ContainsAny(name, "\\:") {
		return "", fmt.Errorf("unsafe artifact path")
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("artifact traversal")
		}
	}
	clean := path.Clean(name)
	if clean == "." {
		return "", fmt.Errorf("empty artifact path")
	}
	for _, part := range strings.Split(clean, "/") {
		if strings.IndexFunc(part, func(c rune) bool {
			return !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_.+ -", c))
		}) >= 0 {
			return "", fmt.Errorf("unsafe artifact filename")
		}
	}
	return clean, nil
}

func (archive *artifactZIP) copyMember(member *zip.File, destination io.Writer) (readResult, error) {
	result := readResult{}
	offset, found := archive.offsets[member]
	if !found {
		return result, fmt.Errorf("ZIP member was not admitted")
	}
	raw := io.NewSectionReader(archive.file, offset, int64(member.CompressedSize64))
	buffered := bufio.NewReader(raw)
	var source io.Reader = raw
	if member.Method == zip.Deflate {
		decoder := flate.NewReader(buffered)
		defer decoder.Close()
		source = decoder
	}
	digest, crc := sha256.New(), crc32.NewIEEE()
	buffer := make([]byte, 65536)
	for {
		n, err := source.Read(buffer)
		if uint64(n) > member.UncompressedSize64-uint64(result.Bytes) {
			return result, fmt.Errorf("actual ZIP member exceeds declared size")
		}
		if n != 0 {
			written, writeErr := destination.Write(buffer[:n])
			if writeErr != nil {
				return result, writeErr
			}
			if written != n {
				return result, io.ErrShortWrite
			}
			digest.Write(buffer[:n])
			crc.Write(buffer[:n])
			result.Bytes += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, err
		}
	}
	position, err := raw.Seek(0, io.SeekCurrent)
	if err != nil {
		return result, err
	}
	if member.Method == zip.Deflate {
		position -= int64(buffered.Buffered())
	}
	if position != int64(member.CompressedSize64) || uint64(result.Bytes) != member.UncompressedSize64 || crc.Sum32() != member.CRC32 {
		return result, fmt.Errorf("ZIP member size, trailing data or CRC differs")
	}
	result.SHA256 = fmt.Sprintf("%x", digest.Sum(nil))
	return result, nil
}
