package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
)

const (
	publisherScratchLimit = 4 << 30
	publisherSpaceReserve = 128 << 20
)

type publisherStorage struct {
	root, audit                string
	limit, reserve, live, peak int64
	state                      map[string]any
}

type publisherCleanupError struct {
	cause error
	note  string
}

func (err *publisherCleanupError) Error() string { return err.cause.Error() }

func (err *publisherCleanupError) Unwrap() error { return err.cause }

func publisherCleanup(primary, cleanup error, context string) error {
	if cleanup == nil {
		return primary
	}
	if primary == nil {
		return fmt.Errorf("%s: %w", context, cleanup)
	}
	return &publisherCleanupError{primary, fmt.Sprintf("%s: %v", context, cleanup)}
}

func withPublisherStorage(audit string, use func(*publisherStorage) error) (err error) {
	root, err := os.MkdirTemp(os.Getenv("RUNNER_TEMP"), "polaris-publisher-")
	if err != nil {
		return err
	}
	storage := &publisherStorage{root: root, audit: audit, limit: publisherScratchLimit, reserve: publisherSpaceReserve,
		state: map[string]any{"phase": "preflight", "remoteWriteState": "none"}}
	err = use(storage)
	cleanup := os.RemoveAll(root)
	if cleanup == nil && err == nil {
		return nil
	}
	err = publisherCleanup(err, cleanup, "scratch directory cleanup also failed")
	var notes []string
	cause := err
	for annotated, ok := cause.(*publisherCleanupError); ok; annotated, ok = cause.(*publisherCleanupError) {
		notes = append(notes, annotated.note)
		cause = annotated.Unwrap()
	}
	if notes == nil {
		notes = []string{}
	}
	message := cause.Error()
	fields := map[string]any{"result": "failed", "errorType": reflect.TypeOf(cause).String(),
		"error": message[:min(600, len(message))], "cleanupNotes": notes}
	if cleanup != nil {
		fields["scratchCleanupFailed"] = true
	}
	storage.record(fields)
	return err
}

func (storage *publisherStorage) admit(size int64, context string) error {
	if size < 0 {
		return fmt.Errorf("invalid scratch allocation")
	}
	free, err := sourceDiskFree(storage.root)
	if err != nil {
		return err
	}
	maps.Copy(storage.state, map[string]any{"context": context[:min(400, len(context))], "requestedBytes": size,
		"liveBytes": storage.live, "peakBytes": storage.peak, "freeBytes": free,
		"limitBytes": storage.limit, "reserveBytes": storage.reserve})
	if size > storage.limit-storage.live {
		return fmt.Errorf("scratch budget exceeded: %s", context)
	}
	if free < uint64(storage.reserve) || uint64(size) > free-uint64(storage.reserve) {
		return fmt.Errorf("insufficient free scratch space: %s", context)
	}
	storage.live += size
	storage.peak = max(storage.peak, storage.live)
	return nil
}

func (storage *publisherStorage) record(fields map[string]any) {
	maps.Copy(storage.state, fields)
	storage.state["liveBytes"], storage.state["peakBytes"] = storage.live, storage.peak
	var data bytes.Buffer
	if err := writeJSON(&data, storage.state); err != nil {
		fmt.Println("Unable to serialize storage diagnostic:", err)
		return
	}
	fmt.Print("Publisher storage: ", data.String())
	if err := os.WriteFile(filepath.Join(storage.audit, "storage-status.json"), data.Bytes(), 0o644); err != nil {
		fmt.Println("Unable to retain storage diagnostic:", err)
	}
}

func (storage *publisherStorage) temporary(size int64, context string, use func(*os.File) error) (err error) {
	if err := storage.admit(size, context); err != nil {
		return err
	}
	defer func() { storage.live -= size }()
	file, err := os.CreateTemp(storage.root, "publisher-")
	if err != nil {
		return err
	}
	defer func() {
		err = publisherCleanup(err, errors.Join(file.Close(), os.Remove(file.Name())), "temporary file cleanup also failed")
	}()
	return use(file)
}

func (storage *publisherStorage) retained(filename string, size int64, context string, write func(io.Writer) error) (err error) {
	if err := storage.admit(size, context); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			storage.live -= size
		}
	}()
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	err = publisherCleanup(write(file), file.Close(), "retained file close also failed")
	if err != nil {
		err = publisherCleanup(err, os.Remove(filename), "partial retained file cleanup also failed")
	}
	return err
}

func (storage *publisherStorage) copy(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	return storage.retained(destination, info.Size(), "audit copy "+filepath.Base(destination), func(output io.Writer) error {
		_, err := io.Copy(output, input)
		return err
	})
}

func (storage *publisherStorage) writeJSON(filename string, record any) error {
	var data bytes.Buffer
	if err := writeJSON(&data, record); err != nil {
		return err
	}
	if data.Len() > publisherProposalLimit {
		return fmt.Errorf("serialized evidence exceeds budget")
	}
	return storage.retained(filename, int64(data.Len()), "evidence "+filepath.Base(filename), func(output io.Writer) error {
		_, err := data.WriteTo(output)
		return err
	})
}

func (p *publisher) withArchive(metadata publisherArtifactMetadata, use func(*artifactZIP) error) error {
	if metadata.Size <= 0 {
		return fmt.Errorf("Actions artifact ZIP size required")
	}
	if !peerDigest.MatchString(metadata.Digest) {
		return fmt.Errorf("Actions artifact digest missing")
	}
	p.storage.state["artifactId"], p.storage.state["artifact"] = metadata.ID, metadata.Name
	for _, key := range []string{"member", "readAttempt", "readStatus", "readHeaders", "readBytes", "readError"} {
		delete(p.storage.state, key)
	}
	id := strconv.FormatInt(metadata.ID, 10)
	return p.storage.temporary(metadata.Size, "ZIP "+id+" "+metadata.Name, func(file *os.File) error {
		measured, err := readGitHubFile(p.ctx, publisherRepositoryPath+"/actions/artifacts/"+id+"/zip", file, metadata.Size,
			&p.reads, defaultReadLimits, func(fields map[string]any) {
				if fields["readError"] != "transport error" {
					p.storage.record(fields)
				}
			})
		if err != nil {
			return err
		}
		if measured.Bytes != metadata.Size {
			return fmt.Errorf("Actions artifact ZIP size differs")
		}
		if "sha256:"+measured.SHA256 != metadata.Digest {
			return fmt.Errorf("Actions artifact digest missing or mismatched")
		}
		archive, err := openArtifactZIP(file)
		if err != nil {
			return err
		}
		return use(archive)
	})
}

func publisherMember(archive *artifactZIP, member *zip.File, destination io.Writer, limit uint64, evidence any) (readResult, error) {
	if destination == nil {
		destination = io.Discard
	}
	var data bytes.Buffer
	if evidence != nil {
		if member.UncompressedSize64 > limit {
			return readResult{}, fmt.Errorf("JSON evidence exceeds serialized budget")
		}
		destination = io.MultiWriter(destination, &data)
	}
	measured, err := archive.copyMember(member, destination)
	if err != nil {
		return readResult{}, err
	}
	if evidence != nil {
		if err := uniqueJSON(&data, evidence); err != nil {
			return readResult{}, err
		}
	}
	return measured, nil
}
