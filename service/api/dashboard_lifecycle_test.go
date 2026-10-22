package api

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func dashboardOwnedFixture(t *testing.T) (*dashboard, *dashboardTestFiles) {
	t.Helper()
	ctx, files := dashboardFileContext(t)
	path := filepath.Join(t.TempDir(), "dashboard")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"index.html": "previous", ".etag": "previous-tag"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return newDashboard(ctx, log.NewNOPFactory().Logger(), "0", option.APIDashboardOptions{Path: path}), files
}

func dashboardRequireOldAndClean(t *testing.T, d *dashboard, files *dashboardTestFiles) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(d.path, "index.html"))
	if err != nil || string(content) != "previous" {
		t.Fatalf("previous dashboard lost: %q %v", content, err)
	}
	workspaces, err := filepath.Glob(d.path + ".update-*")
	if err != nil || len(workspaces) != 0 {
		t.Fatalf("unclosed update workspace: %v %v", workspaces, err)
	}
	archives, err := os.ReadDir(files.TempPath())
	if err != nil || len(archives) != 0 {
		t.Fatalf("unclosed temporary archive: %v %v", archives, err)
	}
}

func TestDashboardArchiveFailurePreservesOwnedFiles(t *testing.T) {
	// Use a stored member to make corruption deterministic, independent of deflate.
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.CreateHeader(&zip.FileHeader{Name: "index.html", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(entry, "crc-content")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	badCRC := append([]byte(nil), buffer.Bytes()...)
	index := bytes.Index(badCRC, []byte("crc-content"))
	if index < 0 {
		t.Fatal("CRC fixture missing")
	}
	badCRC[index] ^= 1
	var symlink bytes.Buffer
	zw := zip.NewWriter(&symlink)
	header := &zip.FileHeader{Name: "index.html", Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0o777)
	link, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(link, "/outside")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"invalid_zip": []byte("not zip"), "parent": dashboardTestZip(t, map[string]string{"../outside": "bad"}),
		"wrapped_parent": dashboardTestZip(t, map[string]string{"root/../../outside": "bad"}),
		"absolute":       dashboardTestZip(t, map[string]string{"/outside": "bad"}),
		"backslash":      dashboardTestZip(t, map[string]string{`root\..\outside`: "bad"}),
		"symlink":        symlink.Bytes(), "crc": badCRC,
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			d, files := dashboardOwnedFixture(t)
			if err := d.extract(context.Background(), bytes.NewReader(archive), "new"); err == nil {
				t.Fatal("invalid archive accepted")
			}
			dashboardRequireOldAndClean(t, d, files)
		})
	}
}

func TestDashboardRenameFailureAndCancellationRestore(t *testing.T) {
	archive := dashboardTestZip(t, map[string]string{"index.html": "new"})
	for _, mode := range []string{"old_move_failure", "new_move_failure", "cancel_after_backup", "restore_failure"} {
		t.Run(mode, func(t *testing.T) {
			d, files := dashboardOwnedFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			files.rename = func(before, after string) error {
				if mode == "old_move_failure" && before == d.path {
					return errors.New("synthetic old-move failure")
				}
				if (mode == "new_move_failure" || mode == "restore_failure") && filepath.Base(before) == "new" {
					return errors.New("synthetic publication failure")
				}
				if mode == "restore_failure" && filepath.Base(before) == "previous" {
					return errors.New("synthetic restore failure")
				}
				err := files.Manager.Rename(before, after)
				if mode == "cancel_after_backup" && filepath.Base(after) == "previous" && err == nil {
					cancel()
				}
				return err
			}
			err := d.extract(ctx, bytes.NewReader(archive), "new")
			if err == nil {
				t.Fatal("expected interrupted publication")
			}
			if mode != "restore_failure" {
				dashboardRequireOldAndClean(t, d, files)
				return
			}
			if !strings.Contains(err.Error(), "previous files preserved at") {
				t.Fatalf("lost recovery evidence: %v", err)
			}
			backups, _ := filepath.Glob(filepath.Join(d.path+".update-*", "previous", "index.html"))
			if len(backups) != 1 {
				t.Fatalf("backup deleted after failed restore: %v", backups)
			}
			content, readErr := os.ReadFile(backups[0])
			if readErr != nil || string(content) != "previous" {
				t.Fatalf("recovery bytes: %q %v", content, readErr)
			}
			archives, readErr := os.ReadDir(files.TempPath())
			if readErr != nil || len(archives) != 0 {
				t.Fatal("temporary archive not removed")
			}
		})
	}
}

type dashboardFailCreate struct{ filemanager.Manager }

func (m dashboardFailCreate) Create(string) (*os.File, error) {
	return nil, errors.New("synthetic disk write failure")
}

func TestDashboardWriteFailureAndUserFilesRemainUntouched(t *testing.T) {
	archive := dashboardTestZip(t, map[string]string{"index.html": "new"})
	t.Run("write_failure", func(t *testing.T) {
		d, files := dashboardOwnedFixture(t)
		d.ctx = service.ContextWith[filemanager.Manager](d.ctx, dashboardFailCreate{files})
		if err := d.extract(context.Background(), bytes.NewReader(archive), "new"); err == nil {
			t.Fatal("write failure swallowed")
		}
		dashboardRequireOldAndClean(t, d, files)
	})
	t.Run("user_directory", func(t *testing.T) {
		d, files := dashboardOwnedFixture(t)
		if err := os.Remove(filepath.Join(d.path, ".etag")); err != nil {
			t.Fatal(err)
		}
		if err := d.extract(context.Background(), bytes.NewReader(archive), "new"); err == nil {
			t.Fatal("static user files overwritten")
		}
		dashboardRequireOldAndClean(t, d, files)
		if err := d.start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if d.done != nil || d.legacyTransport != nil {
			t.Fatal("static user files acquired HTTP resources")
		}
		if err := d.close(); err != nil {
			t.Fatal(err)
		}
	})
}

type dashboardCancellationBody struct {
	ctx                        context.Context
	entered, cancelled, resume chan struct{}
	once                       sync.Once
}

func (b *dashboardCancellationBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.ctx.Done()
	close(b.cancelled)
	<-b.resume
	return 0, b.ctx.Err()
}

func TestDashboardCloseCancelsAndJoinsBeforeLeaseRelease(t *testing.T) {
	ctx, _ := dashboardFileContext(t)
	events := &dashboardEventLog{}
	entered, cancelled, resume := make(chan struct{}), make(chan struct{}), make(chan struct{})
	transport := &dashboardTestTransport{id: "active", events: events}
	transport.roundTrip = func(request *http.Request) (*http.Response, error) {
		body := &dashboardCancellationBody{ctx: request.Context(), entered: entered, cancelled: cancelled, resume: resume}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &dashboardTestBody{Reader: body, close: func() error { events.add("body:active"); return nil }}}, nil
	}
	provider := &dashboardTestProvider{current: transport}
	ctx = service.ContextWith[adapter.RuntimeDashboardHTTPProvider](ctx, provider)
	d := newDashboard(ctx, log.NewNOPFactory().Logger(), "0", option.APIDashboardOptions{Path: filepath.Join(t.TempDir(), "dashboard"), DownloadURL: "http://fixture.test/archive"})
	if err := d.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	dashboardWait(t, entered, "download reader")
	closed := make(chan struct{})
	go func() { _ = d.close(); close(closed) }()
	dashboardWait(t, cancelled, "worker cancellation")
	select {
	case <-closed:
		t.Fatal("close reported success before worker joined")
	default:
	}
	if active, _ := provider.counts(); active != 1 {
		t.Fatal("graph released while body still running")
	}
	close(resume)
	dashboardWait(t, closed, "joined worker")
	if active, _ := provider.counts(); active != 0 {
		t.Fatal("graph lease leaked")
	}
	seen := events.snapshot()
	if len(seen) < 3 || seen[len(seen)-3] != "body:active" || seen[len(seen)-2] != "idle:active" || seen[len(seen)-1] != "release:active" {
		t.Fatalf("ownership order: %v", seen)
	}
	if err := d.close(); err != nil {
		t.Fatal(err)
	}
	if err := d.start(context.Background()); err == nil {
		t.Fatal("closed worker restarted")
	}
}

func TestDashboardStartCloseRace(t *testing.T) {
	for range 20 {
		ctx, _ := dashboardFileContext(t)
		events := &dashboardEventLog{}
		transport := &dashboardTestTransport{id: "race", events: events, roundTrip: func(*http.Request) (*http.Response, error) { return nil, errors.New("synthetic HTTP error") }}
		provider := &dashboardTestProvider{current: transport}
		ctx = service.ContextWith[adapter.RuntimeDashboardHTTPProvider](ctx, provider)
		d := newDashboard(ctx, log.NewNOPFactory().Logger(), "0", option.APIDashboardOptions{Path: filepath.Join(t.TempDir(), "dashboard"), DownloadURL: "http://fixture.test/archive"})
		var workers sync.WaitGroup
		workers.Go(func() { _ = d.start(context.Background()) })
		workers.Go(func() { _ = d.close() })
		workers.Wait()
		if active, _ := provider.counts(); active != 0 {
			t.Fatal("start/close escaped graph reservation")
		}
		if d.done != nil {
			select {
			case <-d.done:
			default:
				t.Fatal("worker survived close")
			}
		}
	}
}

func TestDashboardFetchErrorAndNotModifiedCleanup(t *testing.T) {
	for _, mode := range []string{"http_error", "bad_zip", "body_close_error", "not_modified", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			d, files := dashboardOwnedFixture(t)
			d.loadState()
			d.url = "http://fixture.test/archive"
			events := &dashboardEventLog{}
			transport := &dashboardTestTransport{id: mode, events: events}
			transport.roundTrip = func(*http.Request) (*http.Response, error) {
				status := http.StatusOK
				body := []byte("not zip")
				if mode == "http_error" {
					status = http.StatusBadGateway
				}
				if mode == "not_modified" {
					status = http.StatusNotModified
					body = nil
				}
				if mode == "body_close_error" {
					body = dashboardTestZip(t, map[string]string{"index.html": "new"})
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: &dashboardTestBody{Reader: bytes.NewReader(body), close: func() error {
					events.add("body:" + mode)
					if mode == "body_close_error" {
						return errors.New("synthetic close error")
					}
					return nil
				}}}, nil
			}
			provider := &dashboardTestProvider{current: transport}
			d.provider = provider
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			err := d.fetch(ctx)
			if (err == nil) != (mode == "not_modified") {
				t.Fatalf("fetch result: %v", err)
			}
			active, acquired := provider.counts()
			if active != 0 {
				t.Fatal("error path leaked graph lease")
			}
			if mode == "canceled" {
				if acquired != 0 {
					t.Fatal("canceled fetch acquired graph")
				}
			} else if acquired != 1 {
				t.Fatal("fetch admission count changed")
			}
			if mode != "body_close_error" {
				dashboardRequireOldAndClean(t, d, files)
			}
		})
	}
}
