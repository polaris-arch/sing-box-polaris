//go:build with_tailscale

package tailscale

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/locale"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service/filemanager"
	"github.com/sagernet/tailscale/ipn/ipnlocal"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/util/backoff"
	"github.com/sagernet/tailscale/util/httphdr"
)

const (
	taildropPartialSuffix      = ".partial"
	taildropDeletedSuffix      = ".deleted"
	taildropBlockSize          = 64 << 10
	taildropDeleteDelay        = time.Hour
	taildropDeleteRetryDelay   = 5 * time.Second
	taildropRejectDrainTimeout = 3 * time.Second
	taildropNotificationTypeID = 11
)

var (
	errTaildropFileExists = E.New("taildrop: file already exists")
	errTaildropCanceled   = E.New("taildrop: canceled by receiver")
)

var (
	taildropAccess    sync.RWMutex
	taildropEndpoints = make(map[*ipnlocal.LocalBackend]*Endpoint)
)

func init() {
	ipnlocal.RegisterPeerAPIHandler("/v0/put/", handleTaildropRequest)
}

func registerTaildropEndpoint(backend *ipnlocal.LocalBackend, endpoint *Endpoint) {
	taildropAccess.Lock()
	taildropEndpoints[backend] = endpoint
	taildropAccess.Unlock()
}

func unregisterTaildropEndpoint(backend *ipnlocal.LocalBackend) {
	taildropAccess.Lock()
	delete(taildropEndpoints, backend)
	taildropAccess.Unlock()
}

func handleTaildropRequest(handler ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	taildropAccess.RLock()
	endpoint := taildropEndpoints[handler.LocalBackend()]
	taildropAccess.RUnlock()
	if endpoint == nil {
		http.Error(w, "taildrop not available", http.StatusForbidden)
		return
	}
	endpoint.taildrop.handlePeerRequest(handler, w, r)
}

type taildropIncomingKey struct {
	senderID string
	name     string
}

type taildropIncomingFile struct {
	manager    *taildropManager
	writer     io.Writer
	interrupt  func()
	senderName string
	started    time.Time
	size       int64
	canceled   atomic.Bool

	access     sync.Mutex
	copied     int64
	lastNotify time.Time
}

func (f *taildropIncomingFile) Write(content []byte) (int, error) {
	if f.canceled.Load() {
		return 0, errTaildropCanceled
	}
	n, err := f.writer.Write(content)
	if n > 0 {
		var notify bool
		f.access.Lock()
		f.copied += int64(n)
		now := time.Now()
		if now.Sub(f.lastNotify) >= time.Second {
			f.lastNotify = now
			notify = true
		}
		f.access.Unlock()
		if notify {
			f.manager.notifyInboxUpdated()
		}
	}
	return n, err
}

type taildropManager struct {
	// Bound before publication; nil is reserved for standalone legacy tests.
	directoryReady    func() bool
	ctx               context.Context
	logger            logger.ContextLogger
	tag               string
	directory         string
	platformInterface adapter.PlatformInterface

	renameAccess sync.Mutex

	// Admission and ioWG.Add are serialized with sealing by access.
	ioWG      sync.WaitGroup
	closeOnce sync.Once
	drainDone chan struct{}
	drainErr  error
	cancelIO  context.CancelFunc
	openFiles map[*taildropReadCloser]struct{}

	totalReceived atomic.Int64
	emptySince    atomic.Int64

	access        sync.Mutex
	closed        bool
	incoming      map[taildropIncomingKey]*taildropIncomingFile
	senderNames   map[string]string
	unreadFiles   map[string]bool
	deleteTimers  map[string]*time.Timer
	inboxWatchers map[chan struct{}]bool
	fileWatchers  map[chan struct{}]bool
}

func newTaildropManager(ctx context.Context, logger logger.ContextLogger, tag string, directory string, platformInterface adapter.PlatformInterface) *taildropManager {
	ctx, cancelIO := context.WithCancel(ctx)
	manager := &taildropManager{
		drainDone:         make(chan struct{}),
		cancelIO:          cancelIO,
		openFiles:         make(map[*taildropReadCloser]struct{}),
		ctx:               ctx,
		logger:            logger,
		tag:               tag,
		directory:         directory,
		platformInterface: platformInterface,
		incoming:          make(map[taildropIncomingKey]*taildropIncomingFile),
		senderNames:       make(map[string]string),
		unreadFiles:       make(map[string]bool),
		deleteTimers:      make(map[string]*time.Timer),
		inboxWatchers:     make(map[chan struct{}]bool),
		fileWatchers:      make(map[chan struct{}]bool),
	}
	manager.emptySince.Store(-1)
	return manager
}

func (m *taildropManager) start() {
	if !m.beginIO() {
		return
	}
	defer m.endIO()

	entries, err := m.readDir(m.directory)
	if err != nil {
		return
	}
	now := time.Now()
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		name := entry.Name()
		switch {
		case strings.HasSuffix(name, taildropPartialSuffix):
			information, infoErr := entry.Info()
			if infoErr != nil {
				continue
			}
			m.scheduleDelete(name, taildropDeleteDelay-now.Sub(information.ModTime()))
		case strings.HasSuffix(name, taildropDeletedSuffix):
			baseName := strings.TrimSuffix(name, taildropDeletedSuffix)
			baseErr := os.Remove(filepath.Join(m.directory, baseName))
			if baseErr == nil || os.IsNotExist(baseErr) {
				markerErr := os.Remove(filepath.Join(m.directory, name))
				if markerErr == nil || os.IsNotExist(markerErr) {
					continue
				}
			}
			m.scheduleDelete(name, taildropDeleteDelay)
		}
	}
}

// close bounds the caller wait; a deadline is an explicit incomplete drain.
// It is never proof that the whole directory can be retired.
func (m *taildropManager) close() error {
	m.seal()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.waitContext(ctx)
}

func (m *taildropManager) scheduleDelete(name string, delay time.Duration) {
	if delay < 0 {
		delay = 0
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.closed {
		return
	}
	if _, exists := m.deleteTimers[name]; exists {
		return
	}
	// Count the callback before publishing the timer. Stop and the callback
	// divide ownership of Done according to Timer.Stop's result.
	m.ioWG.Add(1)
	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		defer m.endIO()
		m.access.Lock()
		if m.deleteTimers[name] != timer {
			m.access.Unlock()
			return
		}
		delete(m.deleteTimers, name)
		m.access.Unlock()
		m.deleteExpired(name)
	})
	m.deleteTimers[name] = timer
}

func (m *taildropManager) cancelDelete(name string) {
	m.access.Lock()
	defer m.access.Unlock()
	timer, exists := m.deleteTimers[name]
	if exists {
		if timer.Stop() {
			m.endIO()
		}
		delete(m.deleteTimers, name)
	}
}

func (m *taildropManager) deleteExpired(name string) {
	if !m.beginIO() {
		return
	}
	defer m.endIO()

	m.access.Lock()
	closed := m.closed
	var active bool
	if nameAndSender, isPartial := strings.CutSuffix(name, taildropPartialSuffix); isPartial {
		separatorIndex := strings.LastIndexByte(nameAndSender, '.')
		if separatorIndex > 0 {
			key := taildropIncomingKey{senderID: nameAndSender[separatorIndex+1:], name: nameAndSender[:separatorIndex]}
			active = m.incoming[key] != nil
		}
	}
	m.access.Unlock()
	if closed {
		return
	}
	if active {
		m.scheduleDelete(name, taildropDeleteDelay)
		return
	}
	if baseName, isMarker := strings.CutSuffix(name, taildropDeletedSuffix); isMarker {
		baseErr := os.Remove(filepath.Join(m.directory, baseName))
		if baseErr != nil && !os.IsNotExist(baseErr) {
			m.scheduleDelete(name, taildropDeleteDelay)
			return
		}
		m.access.Lock()
		delete(m.senderNames, baseName)
		delete(m.unreadFiles, baseName)
		m.access.Unlock()
	}
	err := os.Remove(filepath.Join(m.directory, name))
	if err != nil && !os.IsNotExist(err) {
		m.scheduleDelete(name, taildropDeleteDelay)
	}
}

func (m *taildropManager) watch(watchers map[chan struct{}]bool, signal chan struct{}) error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.closed {
		return os.ErrClosed
	}
	watchers[signal] = true
	return nil
}

func (m *taildropManager) isClosed() bool {
	m.access.Lock()
	defer m.access.Unlock()
	return m.closed
}

func (m *taildropManager) unwatch(watchers map[chan struct{}]bool, signal chan struct{}) {
	m.access.Lock()
	delete(watchers, signal)
	m.access.Unlock()
}

func (m *taildropManager) notifyInboxUpdated() {
	m.access.Lock()
	defer m.access.Unlock()
	for signal := range m.inboxWatchers {
		select {
		case signal <- struct{}{}:
		default:
		}
	}
}

func (m *taildropManager) notifyStatusChanged() {
	m.access.Lock()
	defer m.access.Unlock()
	for signal := range m.fileWatchers {
		select {
		case signal <- struct{}{}:
		default:
		}
	}
}

func (m *taildropManager) notifyFilesChanged() {
	m.notifyStatusChanged()
	m.notifyInboxUpdated()
}

func (m *taildropManager) markInboxRead() {
	m.access.Lock()
	if len(m.unreadFiles) == 0 {
		m.access.Unlock()
		return
	}
	clear(m.unreadFiles)
	m.access.Unlock()
	m.notifyStatusChanged()
}

var errTaildropInvalidFileName = E.New("taildrop: invalid filename")

func validateTaildropFileName(name string) error {
	if !utf8.ValidString(name) ||
		name == "." ||
		len(name) > 255 ||
		strings.ContainsRune(name, 0) ||
		filepath.Base(name) != name ||
		!filepath.IsLocal(name) ||
		strings.HasSuffix(name, taildropPartialSuffix) ||
		strings.HasSuffix(name, taildropDeletedSuffix) {
		return errTaildropInvalidFileName
	}
	return nil
}

var (
	taildropExtensionSuffix = regexp.MustCompile(`(\.[a-zA-Z0-9]{0,3}[a-zA-Z][a-zA-Z0-9]{0,3})*$`)
	taildropNumberSuffix    = regexp.MustCompile(` \([0-9]+\)$`)
)

func nextFileName(name string) string {
	extension := taildropExtensionSuffix.FindString(strings.TrimPrefix(name, "."))
	name = strings.TrimSuffix(name, extension)
	var sequence uint64
	if taildropNumberSuffix.MatchString(name) {
		separatorIndex := strings.LastIndex(name, " (")
		sequence, _ = strconv.ParseUint(name[separatorIndex+len(" ("):len(name)-len(")")], 10, 64)
		if sequence > 0 {
			name = name[:separatorIndex]
		}
	}
	return name + " (" + strconv.FormatUint(sequence+1, 10) + ")" + extension
}

func (m *taildropManager) putFile(senderID string, senderName string, baseName string, content io.Reader, offset int64, declaredLength int64, interrupt func()) error {
	if !m.beginIO() {
		return os.ErrClosed
	}
	defer m.endIO()

	err := validateTaildropFileName(baseName)
	if err != nil {
		return err
	}
	partialName := baseName + "." + senderID + taildropPartialSuffix
	m.cancelDelete(partialName)
	totalSize := int64(-1)
	if declaredLength >= 0 {
		totalSize = offset + declaredLength
	}
	key := taildropIncomingKey{senderID: senderID, name: baseName}
	incoming := &taildropIncomingFile{
		manager:    m,
		interrupt:  interrupt,
		senderName: senderName,
		started:    time.Now(),
		size:       totalSize,
		copied:     offset,
	}
	m.access.Lock()
	if m.closed {
		m.access.Unlock()
		return os.ErrClosed
	}
	if m.incoming[key] != nil {
		m.access.Unlock()
		return errTaildropFileExists
	}
	m.incoming[key] = incoming
	m.access.Unlock()
	m.notifyFilesChanged()
	receivingName := "receiving/" + senderID + "/" + baseName
	m.sendNotification(receivingName, fmt.Sprintf(locale.FromContext(m.ctx).TaildropReceiving, baseName, senderName))
	defer m.cancelNotification(receivingName)
	defer func() {
		m.access.Lock()
		delete(m.incoming, key)
		m.access.Unlock()
		m.notifyFilesChanged()
	}()
	partialPath := filepath.Join(m.directory, partialName)
	file, err := filemanager.OpenFile(m.ctx, partialPath, os.O_CREATE|os.O_RDWR, 0o666)
	if err != nil {
		m.scheduleDelete(partialName, taildropDeleteDelay)
		return E.Cause(err, "taildrop: create partial file")
	}
	if offset == 0 {
		err = file.Truncate(0)
		if err != nil {
			err = E.Cause(err, "taildrop: truncate partial file")
		}
	} else {
		var currentSize int64
		currentSize, err = file.Seek(0, io.SeekEnd)
		if err != nil {
			err = E.Cause(err, "taildrop: seek partial file")
		}
		if err == nil && (offset < 0 || offset > currentSize) {
			err = E.New("taildrop: offset ", offset, " out of range")
		}
		if err == nil {
			_, err = file.Seek(offset, io.SeekStart)
			if err != nil {
				err = E.Cause(err, "taildrop: seek partial file")
			}
		}
		if err == nil {
			err = file.Truncate(offset)
			if err != nil {
				err = E.Cause(err, "taildrop: truncate partial file")
			}
		}
	}
	if err != nil {
		m.closeFile(file)
		m.scheduleDelete(partialName, taildropDeleteDelay)
		return err
	}
	incoming.writer = file
	copied, err := io.Copy(incoming, content)
	if err != nil && incoming.canceled.Load() {
		err = errTaildropCanceled
	}
	if err == nil && declaredLength >= 0 && copied != declaredLength {
		err = E.New("taildrop: copied ", copied, " bytes, expected ", declaredLength)
	}
	if err != nil {
		m.closeFile(file)
		if errors.Is(err, errTaildropCanceled) {
			removeErr := os.Remove(partialPath)
			if removeErr != nil && !os.IsNotExist(removeErr) {
				m.scheduleDelete(partialName, taildropDeleteDelay)
			}
		} else {
			m.scheduleDelete(partialName, taildropDeleteDelay)
		}
		return err
	}
	err = m.closeFile(file)
	if err != nil {
		m.scheduleDelete(partialName, taildropDeleteDelay)
		return E.Cause(err, "taildrop: close partial file")
	}
	finalName, err := m.renamePartial(partialPath, baseName)
	if err != nil {
		m.scheduleDelete(partialName, taildropDeleteDelay)
		return err
	}
	m.access.Lock()
	m.senderNames[finalName] = senderName
	m.unreadFiles[finalName] = true
	m.access.Unlock()
	m.totalReceived.Add(1)
	m.logger.Info("taildrop: received ", finalName, " (", offset+copied, " bytes) from ", senderName)
	m.notifyFilesChanged()
	m.sendNotification(finalName, fmt.Sprintf(locale.FromContext(m.ctx).TaildropReceived, finalName, senderName))
	return nil
}

func (m *taildropManager) renamePartial(partialPath string, baseName string) (string, error) {
	partialInfo, err := os.Stat(partialPath)
	if err != nil {
		return "", E.Cause(err, "taildrop: stat partial file")
	}
	finalName := baseName
	for range 10 {
		finalPath := filepath.Join(m.directory, finalName)
		m.renameAccess.Lock()
		_, statErr := os.Stat(finalPath)
		if os.IsNotExist(statErr) {
			renameErr := filemanager.Rename(m.ctx, partialPath, finalPath)
			m.renameAccess.Unlock()
			if renameErr != nil {
				return "", E.Cause(renameErr, "taildrop: rename partial file")
			}
			return finalName, nil
		}
		m.renameAccess.Unlock()
		if statErr != nil {
			return "", E.Cause(statErr, "taildrop: stat received file")
		}
		identical, compareErr := filesIdentical(partialPath, finalPath, partialInfo.Size(), m.failIO)
		if compareErr != nil {
			return "", E.Cause(compareErr, "taildrop: compare received file")
		}
		if identical {
			removeErr := os.Remove(partialPath)
			if removeErr != nil {
				return "", E.Cause(removeErr, "taildrop: remove partial file")
			}
			return finalName, nil
		}
		finalName = nextFileName(finalName)
	}
	return "", E.New("taildrop: too many rename attempts for ", baseName)
}

func filesIdentical(leftPath string, rightPath string, leftSize int64, failures ...func(error)) (bool, error) {
	rightInfo, err := os.Stat(rightPath)
	if err != nil {
		return false, err
	}
	if rightInfo.Size() != leftSize {
		return false, nil
	}
	leftSum, err := fileChecksum(leftPath, failures...)
	if err != nil {
		return false, err
	}
	rightSum, err := fileChecksum(rightPath, failures...)
	if err != nil {
		return false, err
	}
	return leftSum == rightSum, nil
}

func fileChecksum(filePath string, failures ...func(error)) (sum [sha256.Size]byte, resultErr error) {
	file, err := os.Open(filePath)
	if err != nil {
		return sum, err
	}
	defer func() {
		closeErr := file.Close()
		for _, fail := range failures {
			fail(closeErr)
		}
		resultErr = errors.Join(resultErr, closeErr)
	}()
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return sum, err
	}
	copy(sum[:], hash.Sum(nil))
	return sum, nil
}

func (m *taildropManager) sendNotification(name string, body string) {
	if m.platformInterface == nil || !m.platformInterface.UsePlatformNotification() {
		return
	}
	err := m.platformInterface.SendNotification(&adapter.Notification{
		Identifier: "taildrop/" + m.tag + "/" + name,
		TypeName:   "Taildrop Notifications",
		TypeID:     taildropNotificationTypeID,
		Title:      "Taildrop",
		Body:       body,
		OpenURL:    "sing-box:taildrop?endpoint=" + percentEscape(m.tag),
	})
	if err != nil {
		m.logger.Error("taildrop: send notification: ", err)
	}
}

func (m *taildropManager) cancelNotification(name string) {
	if m.platformInterface == nil || !m.platformInterface.UsePlatformNotification() {
		return
	}
	err := m.platformInterface.CancelNotification("taildrop/"+m.tag+"/"+name, taildropNotificationTypeID)
	if err != nil {
		m.logger.Error("taildrop: cancel notification: ", err)
	}
}

func percentEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func (m *taildropManager) receivingFileCount() int32 {
	m.access.Lock()
	defer m.access.Unlock()
	return int32(len(m.incoming))
}

func (m *taildropManager) cancelReceiving(senderID string, baseName string) {
	key := taildropIncomingKey{senderID: senderID, name: baseName}
	m.access.Lock()
	incoming := m.incoming[key]
	m.access.Unlock()
	if incoming == nil {
		return
	}
	incoming.canceled.Store(true)
	if incoming.interrupt != nil {
		incoming.interrupt()
	}
}

func (m *taildropManager) inbox() *adapter.TaildropInbox {
	if !m.beginIO() {
		return &adapter.TaildropInbox{}
	}
	defer m.endIO()

	inbox := &adapter.TaildropInbox{}
	entries, err := m.readDir(m.directory)
	if err == nil {
		deletedNames := make(map[string]bool)
		fileNames := make(map[string]bool, len(entries))
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				continue
			}
			name := entry.Name()
			fileNames[name] = true
			baseName, isMarker := strings.CutSuffix(name, taildropDeletedSuffix)
			if isMarker {
				deletedNames[baseName] = true
			}
		}
		m.access.Lock()
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				continue
			}
			name := entry.Name()
			if strings.HasSuffix(name, taildropPartialSuffix) ||
				strings.HasSuffix(name, taildropDeletedSuffix) ||
				deletedNames[name] {
				continue
			}
			information, infoErr := entry.Info()
			if infoErr != nil {
				continue
			}
			inbox.Files = append(inbox.Files, &adapter.TaildropFile{
				Name:       name,
				Size:       information.Size(),
				SenderName: m.senderNames[name],
				ModifiedAt: information.ModTime().Unix(),
			})
		}
		for name := range m.senderNames {
			if !fileNames[name] {
				delete(m.senderNames, name)
				delete(m.unreadFiles, name)
			}
		}
		m.access.Unlock()
	}
	slices.SortFunc(inbox.Files, func(left, right *adapter.TaildropFile) int {
		if left.ModifiedAt != right.ModifiedAt {
			return cmp.Compare(right.ModifiedAt, left.ModifiedAt)
		}
		return strings.Compare(left.Name, right.Name)
	})
	m.access.Lock()
	receiving := make([]*taildropIncomingFile, 0, len(m.incoming))
	receivingKeys := make(map[*taildropIncomingFile]taildropIncomingKey, len(m.incoming))
	for key, incoming := range m.incoming {
		receiving = append(receiving, incoming)
		receivingKeys[incoming] = key
	}
	m.access.Unlock()
	slices.SortFunc(receiving, func(left, right *taildropIncomingFile) int {
		return left.started.Compare(right.started)
	})
	for _, incoming := range receiving {
		key := receivingKeys[incoming]
		incoming.access.Lock()
		inbox.Receiving = append(inbox.Receiving, &adapter.TaildropReceivingFile{
			Name:          key.name,
			Size:          incoming.size,
			ReceivedBytes: incoming.copied,
			SenderID:      key.senderID,
			SenderName:    incoming.senderName,
		})
		incoming.access.Unlock()
	}
	return inbox
}

func (m *taildropManager) waitingFileCount() int32 {
	if !m.beginIO() {
		return 0
	}
	defer m.endIO()

	totalReceived := m.totalReceived.Load()
	if totalReceived == m.emptySince.Load() {
		return 0
	}
	entries, err := m.readDir(m.directory)
	if err != nil {
		return 0
	}
	deletedNames := make(map[string]bool)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		name := entry.Name()
		baseName, isMarker := strings.CutSuffix(name, taildropDeletedSuffix)
		if isMarker {
			deletedNames[baseName] = true
			continue
		}
		if strings.HasSuffix(name, taildropPartialSuffix) {
			continue
		}
		names = append(names, name)
	}
	var count int32
	for _, name := range names {
		if deletedNames[name] {
			continue
		}
		count++
	}
	if count == 0 {
		m.emptySince.Store(totalReceived)
	}
	return count
}

func (m *taildropManager) unreadFileCount() int32 {
	m.access.Lock()
	defer m.access.Unlock()
	return int32(len(m.unreadFiles))
}

func (m *taildropManager) partialFileNames(senderID string) []string {
	if !m.beginIO() {
		return nil
	}
	defer m.endIO()

	fileNames := make([]string, 0)
	entries, err := m.readDir(m.directory)
	if err != nil {
		return fileNames
	}
	suffix := "." + senderID + taildropPartialSuffix
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), suffix) {
			fileNames = append(fileNames, entry.Name())
		}
	}
	return fileNames
}

func (m *taildropManager) openFile(baseName string) (io.ReadCloser, int64, error) {
	if !m.beginIO() {
		return nil, 0, os.ErrClosed
	}
	// Transfer this lease to the returned reader only on success.
	transferred := false
	defer func() {
		if !transferred {
			m.endIO()
		}
	}()

	err := validateTaildropFileName(baseName)
	if err != nil {
		return nil, 0, err
	}
	_, markerErr := os.Stat(filepath.Join(m.directory, baseName+taildropDeletedSuffix))
	if markerErr == nil {
		return nil, 0, E.Extend(os.ErrNotExist, baseName)
	}
	file, err := os.Open(filepath.Join(m.directory, baseName))
	if err != nil {
		return nil, 0, err
	}
	information, err := file.Stat()
	if err != nil {
		m.closeFile(file)
		return nil, 0, err
	}
	reader := &taildropReadCloser{file: file, manager: m}
	m.access.Lock()
	if m.closed {
		m.access.Unlock()
		m.closeFile(file)
		return nil, 0, os.ErrClosed
	}
	m.openFiles[reader] = struct{}{}
	transferred = true
	m.access.Unlock()
	return reader, information.Size(), nil
}

func (m *taildropManager) deleteFile(baseName string) error {
	if !m.beginIO() {
		return os.ErrClosed
	}
	defer m.endIO()

	err := validateTaildropFileName(baseName)
	if err != nil {
		return err
	}
	var (
		removeBackoff *backoff.Backoff
		startedAt     = time.Now()
	)
	for {
		err = os.Remove(filepath.Join(m.directory, baseName))
		if err == nil || os.IsNotExist(err) {
			break
		}
		if runtime.GOOS != "windows" {
			return E.Cause(err, "taildrop: delete received file")
		}
		if time.Since(startedAt) < taildropDeleteRetryDelay {
			if removeBackoff == nil {
				removeBackoff = backoff.NewBackoff("taildrop-delete", func(format string, args ...any) {
					m.logger.Debug(fmt.Sprintf(format, args...))
				}, time.Second)
			}
			removeBackoff.BackOff(m.ctx, err)
			if m.ctx.Err() != nil {
				return E.Cause(err, "taildrop: delete received file")
			}
			continue
		}
		marker, markerErr := filemanager.OpenFile(m.ctx, filepath.Join(m.directory, baseName+taildropDeletedSuffix), os.O_CREATE|os.O_WRONLY, 0o666)
		if markerErr != nil {
			return E.Cause(err, "taildrop: delete received file")
		}
		if closeErr := m.closeFile(marker); closeErr != nil {
			return closeErr
		}
		m.scheduleDelete(baseName+taildropDeletedSuffix, taildropDeleteDelay)
		break
	}
	m.access.Lock()
	delete(m.senderNames, baseName)
	delete(m.unreadFiles, baseName)
	m.access.Unlock()
	m.notifyFilesChanged()
	return nil
}

type taildropBlockChecksum struct {
	Checksum  string `json:"checksum"`
	Algorithm string `json:"algo"`
	Size      int64  `json:"size"`
}

func (m *taildropManager) handlePeerRequest(handler ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	if !m.beginIO() {
		http.Error(w, "taildrop closed", http.StatusServiceUnavailable)
		return
	}
	defer m.endIO()

	if handler.Peer().UnsignedPeerAPIOnly() ||
		!(handler.IsSelfUntagged() || handler.PeerCaps().HasCapability(tailcfg.PeerCapabilityFileSharingSend)) {
		http.Error(w, "Taildrop access denied", http.StatusForbidden)
		return
	}
	if !handler.Self().CapMap().Contains(tailcfg.CapabilityFileSharing) {
		http.Error(w, "file sharing not enabled by Tailscale admin", http.StatusForbidden)
		return
	}
	escapedName, found := strings.CutPrefix(r.URL.EscapedPath(), "/v0/put/")
	if !found {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	baseName, err := url.PathUnescape(escapedName)
	if err != nil {
		http.Error(w, errTaildropInvalidFileName.Error(), http.StatusBadRequest)
		return
	}
	senderID := string(handler.Peer().StableID())
	if senderID == "" || validateTaildropFileName(senderID) != nil {
		http.Error(w, "invalid peer identity", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if escapedName == "" {
			err = json.NewEncoder(w).Encode(m.partialFileNames(senderID))
			if err != nil {
				m.logger.Error("taildrop: write partial file list: ", err)
			}
		} else {
			m.writePartialChecksums(w, senderID, baseName)
		}
	case http.MethodPut:
		var offset int64
		rangeHeader := r.Header.Get("Range")
		if rangeHeader != "" {
			ranges, valid := httphdr.ParseRange(rangeHeader)
			if !valid || len(ranges) != 1 || ranges[0].Length != 0 {
				http.Error(w, "invalid Range header", http.StatusBadRequest)
				return
			}
			offset = ranges[0].Start
		}
		responseController := http.NewResponseController(w)
		err = m.putFile(senderID, handler.Peer().ComputedName(), baseName, r.Body, offset, r.ContentLength, func() {
			_ = responseController.SetReadDeadline(time.Now())
		})
		if err == nil {
			io.WriteString(w, "{}\n")
			return
		}
		var (
			statusCode int
			message    string
		)
		switch {
		case errors.Is(err, errTaildropInvalidFileName):
			statusCode = http.StatusBadRequest
			message = err.Error()
		case errors.Is(err, errTaildropFileExists):
			statusCode = http.StatusConflict
			message = err.Error()
		case errors.Is(err, errTaildropCanceled):
			m.logger.Debug("taildrop: receive ", baseName, ": ", err)
			statusCode = http.StatusForbidden
			message = err.Error()
		default:
			m.logger.Error("taildrop: receive ", baseName, ": ", err)
			statusCode = http.StatusInternalServerError
			message = "taildrop: receive failed"
		}
		// http.Error deletes Content-Length, so a response flushed before the
		// handler returns is sent chunked and the sender cannot finish reading
		// it until the handler returns; net/http then tears the connection down
		// while the request body is unread, which aborts it with a reset and
		// discards the response along with any pending retransmission of it.
		// Write a complete response instead, then hold the connection open
		// until the sender reads the response and closes it.
		responseBody := message + "\n"
		responseHeader := w.Header()
		responseHeader.Set("Content-Type", "text/plain; charset=utf-8")
		responseHeader.Set("Content-Length", strconv.Itoa(len(responseBody)))
		if r.ProtoMajor == 1 {
			responseHeader.Set("Connection", "close")
		}
		w.WriteHeader(statusCode)
		io.WriteString(w, responseBody)
		_ = responseController.Flush()
		_ = responseController.SetReadDeadline(time.Now().Add(taildropRejectDrainTimeout))
		_, _ = io.Copy(io.Discard, r.Body)
	default:
		http.Error(w, "expected method GET or PUT", http.StatusMethodNotAllowed)
	}
}

func (m *taildropManager) writePartialChecksums(w http.ResponseWriter, senderID string, baseName string) {
	if !m.beginIO() {
		http.Error(w, "taildrop closed", http.StatusServiceUnavailable)
		return
	}
	defer m.endIO()

	if validateTaildropFileName(baseName) != nil {
		http.Error(w, errTaildropInvalidFileName.Error(), http.StatusBadRequest)
		return
	}
	file, err := os.Open(filepath.Join(m.directory, baseName+"."+senderID+taildropPartialSuffix))
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		http.Error(w, "taildrop: open partial file", http.StatusInternalServerError)
		return
	}
	defer m.closeFile(file)
	encoder := json.NewEncoder(w)
	block := make([]byte, taildropBlockSize)
	for {
		n, readErr := io.ReadFull(file, block)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			m.logger.Error("taildrop: read partial file: ", readErr)
			return
		}
		if n == 0 {
			return
		}
		sum := sha256.Sum256(block[:n])
		err = encoder.Encode(taildropBlockChecksum{
			Checksum:  hex.EncodeToString(sum[:]),
			Algorithm: "sha256",
			Size:      int64(n),
		})
		if err != nil {
			return
		}
		if readErr != nil {
			return
		}
	}
}

func (t *Endpoint) SubscribeTaildropInbox(ctx context.Context, fn func(*adapter.TaildropInbox)) error {
 if t.runtime!=nil{child,ctx,leave,err:=t.runtimeOperation(ctx);if err!=nil{return err};defer leave();return child.SubscribeTaildropInbox(ctx,fn)}

	manager := t.taildrop
	signal := make(chan struct{}, 1)
	err := manager.watch(manager.inboxWatchers, signal)
	if err != nil {
		return err
	}
	defer manager.unwatch(manager.inboxWatchers, signal)
	for {
		if manager.isClosed() {
			return os.ErrClosed
		}
		fn(manager.inbox())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-signal:
			if manager.isClosed() {
				return os.ErrClosed
			}
		}
	}
}

func (t *Endpoint) MarkTaildropInboxRead() error {
 if t.runtime!=nil{child,leave,err:=t.runtimeChild(true);if err!=nil{return err};defer leave();return child.MarkTaildropInboxRead()}

	if !t.taildrop.beginIO() {
		return os.ErrClosed
	}
	defer t.taildrop.endIO()

	t.taildrop.markInboxRead()
	return nil
}

func (t *Endpoint) OpenTaildropFile(fileName string) (io.ReadCloser, int64, error) {
 if t.runtime!=nil{child,leave,err:=t.runtimeChild(true);if err!=nil{return nil,0,err};defer leave();return child.OpenTaildropFile(fileName)}

	return t.taildrop.openFile(fileName)
}

func (t *Endpoint) DeleteTaildropFile(fileName string) error {
 if t.runtime!=nil{child,leave,err:=t.runtimeChild(true);if err!=nil{return err};defer leave();return child.DeleteTaildropFile(fileName)}

	return t.taildrop.deleteFile(fileName)
}

func (t *Endpoint) CancelTaildropReceiving(senderID string, fileName string) error {
 if t.runtime!=nil{child,leave,err:=t.runtimeChild(true);if err!=nil{return err};defer leave();return child.CancelTaildropReceiving(senderID,fileName)}

	if !t.taildrop.beginIO() {
		return os.ErrClosed
	}
	defer t.taildrop.endIO()

	err := validateTaildropFileName(fileName)
	if err != nil {
		return err
	}
	t.taildrop.cancelReceiving(senderID, fileName)
	return nil
}
