package api

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

const (
	dashboardRoutePrefix  = "/dashboard/"
	dashboardEtagFileName = ".etag"
	defaultDashboardURL   = "https://github.com/SagerNet/sing-box-dashboard/archive/refs/heads/gh-pages.zip"
)

type dashboardStatus int

const (
	dashboardEmpty dashboardStatus = iota
	dashboardManaged
	dashboardUserProvided
)

type dashboard struct {
	ctx             context.Context
	logger          log.ContextLogger
	options         option.APIDashboardOptions
	path            string
	url             string
	updateInterval  time.Duration
	fileServer      http.Handler
	provider        adapter.RuntimeDashboardHTTPProvider
	serviceTag      string
	legacyTransport adapter.HTTPTransport
	lifecycle       sync.Mutex
	started         bool
	closed          bool
	cancel          context.CancelFunc
	done            chan struct{}
	lastEtag        string
	lastUpdated     time.Time
}

func newDashboard(ctx context.Context, logger log.ContextLogger, serviceTag string, options option.APIDashboardOptions) *dashboard {
	path := options.Path
	if path == "" {
		path = "dashboard"
	}
	path = filemanager.BasePath(ctx, os.ExpandEnv(path))
	url := options.DownloadURL
	if url == "" {
		url = defaultDashboardURL
	}
	updateInterval := 24 * time.Hour
	if options.UpdateInterval > 0 {
		updateInterval = time.Duration(options.UpdateInterval)
	}
	return &dashboard{
		ctx:            ctx,
		serviceTag:     serviceTag,
		provider:       service.FromContext[adapter.RuntimeDashboardHTTPProvider](ctx),
		logger:         logger,
		options:        options,
		path:           path,
		url:            url,
		updateInterval: updateInterval,
		fileServer:     http.StripPrefix(dashboardRoutePrefix, http.FileServer(dashboardDir(path))),
	}
}

func (d *dashboard) start(ctx context.Context) error {
	d.lifecycle.Lock()
	defer d.lifecycle.Unlock()
	if d.closed || d.started {
		return E.New("dashboard already started or closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := filemanager.ReadDir(d.ctx, d.path)
	if err != nil && !os.IsNotExist(err) {
		return E.Cause(err, "read dashboard directory")
	}
	status := d.loadState()
	if status == dashboardUserProvided {
		d.started = true
		d.logger.Info("dashboard: serving user-provided files at ", d.path, ", auto-update disabled")
		return nil
	}
	if _, err := d.managedDirectory(d.path); err != nil {
		return err
	}
	if d.provider == nil {
		manager := service.FromContext[adapter.HTTPClientManager](d.ctx)
		if manager == nil {
			return E.New("dashboard HTTP manager unavailable")
		}
		transport, err := manager.ResolveTransport(d.ctx, d.logger, common.PtrValueOrDefault(d.options.HTTPClient))
		if err != nil {
			return E.Cause(err, "create dashboard http client")
		}
		d.legacyTransport = transport
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	worker, cancel := context.WithCancel(ctx)
	d.cancel, d.done, d.started = cancel, make(chan struct{}), true
	go func() {
		defer close(d.done)
		d.loopUpdate(worker, status)
	}()
	return nil
}

func (d *dashboard) close() error {
	d.lifecycle.Lock()
	d.closed = true
	cancel, done := d.cancel, d.done
	d.lifecycle.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	// No worker can create or use a transport after this point. The manager,
	// not this stable service, owns physical graph-transport destruction.
	return nil
}

func (d *dashboard) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	if strings.HasPrefix(request.URL.Path, dashboardRoutePrefix) {
		d.fileServer.ServeHTTP(writer, request)
		return
	}
	http.Redirect(writer, request, dashboardRoutePrefix, http.StatusFound)
}

func (d *dashboard) loopUpdate(ctx context.Context, status dashboardStatus) {
	var nextUpdate time.Time
	if status == dashboardManaged {
		nextUpdate = d.lastUpdated.Add(d.updateInterval)
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		now := time.Now()
		if !now.Before(nextUpdate) {
			err := d.fetch(ctx)
			if err != nil {
				d.logger.Error(E.Cause(err, "update dashboard"))
				nextUpdate = now.Add(d.updateInterval)
			} else {
				nextUpdate = d.lastUpdated.Add(d.updateInterval)
			}
		}
		timer.Reset(max(time.Until(nextUpdate), 0))
	}
}

func (d *dashboard) loadState() dashboardStatus {
	entries, err := filemanager.ReadDir(d.ctx, d.path)
	if err != nil {
		return dashboardEmpty
	}
	if len(entries) == 0 {
		return dashboardEmpty
	}
	etagPath := filepath.Join(d.path, dashboardEtagFileName)
	etagBytes, err := filemanager.ReadFile(d.ctx, etagPath)
	if err != nil {
		return dashboardUserProvided
	}
	d.lastEtag = strings.TrimSpace(string(etagBytes))
	info, err := filemanager.Stat(d.ctx, etagPath)
	if err == nil {
		d.lastUpdated = info.ModTime()
	}
	return dashboardManaged
}

func (d *dashboard) fetch(ctx context.Context) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	transport := d.legacyTransport
	if d.provider != nil {
		lease, err := d.provider.AcquireDashboardHTTP(ctx, d.serviceTag)
		if err != nil {
			return err
		}
		if lease == nil {
			return E.New("dashboard HTTP admission returned no lease")
		}
		defer lease.Release()
		ctx, transport = lease.Context(), lease.Transport()
	}
	if transport == nil {
		return E.New("dashboard HTTP transport unavailable")
	}
	client := &http.Client{Transport: transport}
	defer client.CloseIdleConnections()
	d.logger.Info("updating dashboard from URL: ", d.url)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.url, nil)
	if err != nil {
		return err
	}
	if d.lastEtag != "" {
		request.Header.Set("If-None-Match", d.lastEtag)
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, response.Body.Close()) }()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		if err := ctx.Err(); err != nil {
			return err
		}
		exists, err := d.managedDirectory(d.path)
		if err != nil || !exists || d.lastEtag == "" {
			return errors.Join(err, E.New("dashboard not-modified response without owned cached content"))
		}
		if err := filemanager.WriteFile(d.ctx, filepath.Join(d.path, dashboardEtagFileName), []byte(d.lastEtag), 0o644); err != nil {
			return E.Cause(err, "save dashboard update time")
		}
		d.lastUpdated = time.Now()
		d.logger.Info("dashboard: not modified")
		return nil
	default:
		return E.New("unexpected status: ", response.Status)
	}
	etag := response.Header.Get("Etag")
	if err := d.extract(ctx, response.Body, etag); err != nil {
		return err
	}
	d.lastEtag, d.lastUpdated = etag, time.Now()
	d.logger.Info("dashboard: updated")
	return nil
}

// Only an absent/empty directory or a directory bearing our regular .etag
// marker is update-owned. User-provided files and symlink roots are never
// removed, including if they appear while a download is in flight.
func (d *dashboard) managedDirectory(path string) (bool, error) {
	info, err := os.Lstat(filemanager.BasePath(d.ctx, path))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, E.New("dashboard update destination is not an owned directory")
	}
	entries, err := filemanager.ReadDir(d.ctx, path)
	if err != nil {
		return false, err
	}
	if len(entries) == 0 {
		return true, nil
	}
	marker, err := os.Lstat(filemanager.BasePath(d.ctx, filepath.Join(path, dashboardEtagFileName)))
	if err != nil || !marker.Mode().IsRegular() {
		return false, E.New("dashboard update destination contains user-provided files")
	}
	return true, nil
}

func (d *dashboard) extract(ctx context.Context, body io.Reader, etag string) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	tempFile, err := filemanager.CreateTemp(d.ctx, "sing-box-dashboard-*.zip")
	if err != nil {
		return err
	}
	tempZipPath := tempFile.Name()
	defer func() { result = errors.Join(result, filemanager.Remove(d.ctx, tempZipPath)) }()
	_, copyErr := io.Copy(tempFile, dashboardContextReader{ctx, body})
	if err := errors.Join(copyErr, tempFile.Close()); err != nil {
		return err
	}
	reader, err := zip.OpenReader(tempZipPath)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, reader.Close()) }()

	if err := filemanager.MkdirAll(d.ctx, filepath.Dir(d.path), 0o755); err != nil {
		return err
	}
	workspace := d.path + ".update-" + rand.Text()
	if err := filemanager.Mkdir(d.ctx, workspace, 0o700); err != nil {
		return err
	}
	preserveBackup := false
	defer func() {
		if !preserveBackup {
			result = errors.Join(result, filemanager.RemoveAll(d.ctx, workspace))
		}
	}()
	tempDir := filepath.Join(workspace, "new")
	if err := filemanager.Mkdir(d.ctx, tempDir, 0o755); err != nil {
		return err
	}
	trimDir := zipIsInSingleDirectory(reader.File)
	for _, file := range reader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !filepath.IsLocal(filepath.FromSlash(file.Name)) || strings.Contains(file.Name, `\`) {
			return E.New("invalid dashboard archive entry: ", file.Name)
		}
		if file.FileInfo().IsDir() {
			continue
		}
		if !file.Mode().IsRegular() {
			return E.New("unsupported dashboard archive entry: ", file.Name)
		}
		pathElements := strings.Split(file.Name, "/")
		if trimDir {
			pathElements = pathElements[1:]
		}
		if len(pathElements) == 0 {
			continue
		}
		relativePath := filepath.Join(pathElements...)
		if !filepath.IsLocal(relativePath) {
			return E.New("invalid dashboard archive entry: ", file.Name)
		}
		savePath := filepath.Join(tempDir, relativePath)
		if err := filemanager.MkdirAll(d.ctx, filepath.Dir(savePath), 0o755); err != nil {
			return err
		}
		if err := extractZipEntry(ctx, d.ctx, file, savePath); err != nil {
			return err
		}
	}
	if err := filemanager.WriteFile(d.ctx, filepath.Join(tempDir, dashboardEtagFileName), []byte(etag), 0o644); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	exists, err := d.managedDirectory(d.path)
	if err != nil {
		return err
	}
	backup := filepath.Join(workspace, "previous")
	if exists {
		if err := filemanager.Rename(d.ctx, d.path, backup); err != nil {
			return err
		}
		preserveBackup = true
	}
	restore := func(cause error) error {
		if exists {
			if err := filemanager.Rename(d.ctx, backup, d.path); err != nil {
				return errors.Join(cause, E.Cause(err, "restore dashboard; previous files preserved at ", backup))
			}
			preserveBackup = false
		}
		return cause
	}
	if exists {
		if _, err := d.managedDirectory(backup); err != nil {
			return restore(err)
		}
	}
	if err := ctx.Err(); err != nil {
		return restore(err)
	}
	if err := filemanager.Rename(d.ctx, tempDir, d.path); err != nil {
		return restore(err)
	}
	preserveBackup = false
	return nil
}

type dashboardContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r dashboardContextReader) Read(content []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(content)
}

func extractZipEntry(ctx context.Context, fileContext context.Context, file *zip.File, savePath string) (result error) {
	reader, err := file.Open()
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, reader.Close()) }()
	writer, err := filemanager.Create(fileContext, savePath)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, writer.Close()) }()
	_, err = io.Copy(writer, dashboardContextReader{ctx, reader})
	return err
}

// GitHub archives wrap every file under a single "<repo>-<branch>/" top-level directory.
func zipIsInSingleDirectory(files []*zip.File) bool {
	var dirName string
	for _, file := range files {
		if file.FileInfo().IsDir() {
			continue
		}
		pathElements := strings.Split(file.Name, "/")
		if len(pathElements) < 2 {
			return false
		}
		if dirName == "" {
			dirName = pathElements[0]
		} else if dirName != pathElements[0] {
			return false
		}
	}
	return dirName != ""
}
