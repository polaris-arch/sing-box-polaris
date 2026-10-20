package fswatch

import (
	"os"
 "errors"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"github.com/fsnotify/fsnotify"
)

const DefaultWaitTimeout = 100 * time.Millisecond

// Watcher is a simple fsnotify wrapper to watch updates correctly.
type Watcher struct {
	watchDirect bool
	watchTarget []string
	watchPath   []string
 watchDirectory []string
	callback    func(path string)
	waitTimeout time.Duration
	logger      logger.Logger
	watcher     *fsnotify.Watcher

	stateAccess sync.Mutex
	timerMap    map[string]pendingCallback
	closed      bool
}

type pendingCallback struct {
	generation uint64
	timer      *time.Timer
}

type Options struct {
	// Path is the list of files or directories to watch
	// It is the caller's responsibility to ensure that paths are absolute.
 Path []string

 // Directory watches immediate children as well as deletion/recreation of
 // each directory itself. Paths must be absolute. This is not recursive.
 // Missing directories are allowed when their required parent exists.
 Directory []string

	// Direct is the flag to watch the file directly if file will never be removed
	Direct bool

	// Callback is the function to call when a file is updated
	Callback func(path string)

	// WaitTimeout is the time to wait write events before calling the callback
	// DefaultWaitTimeout is used by default
	WaitTimeout time.Duration

	// Logger is the logger to log errors
	// optional
	Logger logger.Logger
}

func NewWatcher(options Options) (*Watcher, error) {
	if (len(options.Path) == 0 && len(options.Directory) == 0) || options.Callback == nil {
		return nil, os.ErrInvalid
	}
	waitTimeout := options.WaitTimeout
	if waitTimeout == 0 {
		waitTimeout = DefaultWaitTimeout
	}
	var watchTarget []string
	if options.Direct {
		watchTarget = options.Path
	} else {
		watchTarget = common.Uniq(common.Map(options.Path, filepath.Dir))
		// TODO: update sing to use common.Remove when it's stable
		watchTarget = common.Filter(watchTarget, func(it string) bool {
			return !common.Any(watchTarget, func(path string) bool {
				return len(path) > len(it) && strings.HasPrefix(path, it)
			})
		})
	}
 directories := common.Uniq(common.Map(options.Directory,filepath.Clean))
 // Parents detect a configured directory's deletion/recreation. Explicit
 // directories are added separately after parents, allowing a missing target.
 watchTarget = common.Uniq(append(watchTarget,common.Map(directories,filepath.Dir)...))
 return &Watcher{
		watchDirect: options.Direct,
		watchTarget: watchTarget,
		watchPath:   options.Path,
  watchDirectory: directories,
		callback:    options.Callback,
		waitTimeout: waitTimeout,
		logger:      options.Logger,
		timerMap:    make(map[string]pendingCallback),
	}, nil
}

func (w *Watcher) Start() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return E.Cause(err, "fswatch: create fsnotify watcher")
	}
	if err = addWatchTargets(watcher, w.watchTarget); err != nil { return err }
 if err = addWatchDirectories(watcher,w.watchDirectory); err != nil { return err }
	w.watcher = watcher
	go w.loopUpdate()
	return nil
}

func (w *Watcher) Close() error {
	w.stateAccess.Lock()
	if w.closed {
		watcher := w.watcher
		w.stateAccess.Unlock()
		return common.Close(common.PtrOrNil(watcher))
	}
	w.closed = true
	timers := make([]*time.Timer, 0, len(w.timerMap))
	for path, pending := range w.timerMap {
		timers = append(timers, pending.timer)
		delete(w.timerMap, path)
	}
	watcher := w.watcher
	w.stateAccess.Unlock()

	for _, timer := range timers {
		timer.Stop()
	}
	return common.Close(common.PtrOrNil(watcher))
}

func (w *Watcher) loopUpdate() {
	for {
		select {
		case event, loaded := <-w.watcher.Events:
			if !loaded {
				return
			}
   if w.handleDirectoryEvent(event,w.watcher.Add) { continue }
   if common.Contains(w.watchTarget, event.Name) && (event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove)) {
				if w.logger != nil {
					w.logger.Error("fswatch: watcher removed: ", event.Name)
				}
			} else if common.Contains(w.watchPath, event.Name) && (event.Has(fsnotify.Create) || event.Has(fsnotify.Write)) {
				w.scheduleCallback(event.Name)
			}
		case err, loaded := <-w.watcher.Errors:
			if !loaded {
				return
			}
			if w.logger != nil {
				w.logger.Error("fswatch: ", err)
			}
		}
	}
}

func (w *Watcher) scheduleCallback(path string) {
	w.stateAccess.Lock()
	if w.closed {
		w.stateAccess.Unlock()
		return
	}

	pending := w.timerMap[path]
	generation := pending.generation + 1
	if pending.timer != nil {
		pending.timer.Stop()
	}
	w.timerMap[path] = pendingCallback{
		generation: generation,
		timer:      time.AfterFunc(w.waitTimeout, func() { w.fireCallback(path, generation) }),
	}
	w.stateAccess.Unlock()
}

func (w *Watcher) fireCallback(path string, generation uint64) {
	w.stateAccess.Lock()
	if w.closed {
		w.stateAccess.Unlock()
		return
	}

	pending, loaded := w.timerMap[path]
	if !loaded || pending.generation != generation {
		w.stateAccess.Unlock()
		return
	}
	delete(w.timerMap, path)
	callback := w.callback
	w.stateAccess.Unlock()

	callback(path)
}

// addWatchTargets owns the newly allocated watcher until successful handoff to
// Watcher.watcher. Every Add failure closes that exact unpublished allocation.
func addWatchTargets(watcher interface { Add(string) error; Close() error }, targets []string) error {
 for _, target := range targets {
  if err := watcher.Add(target); err != nil {
   cause := E.Cause(err, "fswatch: watch ", target)
   if closeErr := watcher.Close(); closeErr != nil {
    return &startCleanupError{cause: errors.Join(cause, E.Cause(closeErr, "fswatch: failed-start cleanup"))}
   }
   return cause
  }
 }
 return nil
}
// An unsuccessful native Close remains observable by the enclosing lifecycle
// owner. It must not certify a failed preparation as fully reclaimed.
type startCleanupError struct { cause error }
func(e *startCleanupError) Error() string { return e.cause.Error() }
func(e *startCleanupError) Unwrap() error { return e.cause }
func(*startCleanupError) RuntimeCleanupIncomplete() bool { return true }

// matchesDirectoryEvent never uses string prefixes: sibling names and
// grandchildren are not immediate children, even when their prefixes match.
func(w *Watcher)matchesDirectoryEvent(event fsnotify.Event)bool{
 if !event.Has(fsnotify.Create)&&!event.Has(fsnotify.Write)&&!event.Has(fsnotify.Remove)&&!event.Has(fsnotify.Rename){return false}
 path:=filepath.Clean(event.Name)
 return common.Contains(w.watchDirectory,path)||common.Contains(w.watchDirectory,filepath.Dir(path))
}
func addWatchDirectories(watcher interface{Add(string)error;Close()error},directories []string)error{
 for _,path:=range directories{
  if err:=watcher.Add(path);err!=nil&&!os.IsNotExist(err){
   cause:=E.Cause(err,"fswatch: watch directory ",path)
   if closeErr:=watcher.Close();closeErr!=nil{return &startCleanupError{cause:errors.Join(cause,E.Cause(closeErr,"fswatch: failed-directory-start cleanup"))}}
   return cause
  }
 }
 return nil
}

func(w *Watcher)handleDirectoryEvent(event fsnotify.Event,add func(string)error)bool{
 if !w.matchesDirectoryEvent(event){return false}
 path:=filepath.Clean(event.Name)
 if common.Contains(w.watchDirectory,path)&&event.Has(fsnotify.Create){
  // Only the exact original backend is passed here; this path never creates
  // a replacement watcher. A close race therefore cannot resurrect native IO.
  if err:=w.addDirectoryIfOpen(path,add);err!=nil&&!os.IsNotExist(err)&&!errors.Is(err,os.ErrClosed)&&w.logger!=nil{
   w.logger.Error("fswatch: rewatch directory: ",path,": ",err)
  }
 }
 // scheduleCallback rechecks closed under stateAccess. Late backend Add
 // completion cannot schedule an unfenced callback after Close.
 w.scheduleCallback(path)
 return true
}
func(w *Watcher)addDirectoryIfOpen(path string,add func(string)error)error{
 w.stateAccess.Lock();closed:=w.closed;w.stateAccess.Unlock()
 if closed{return os.ErrClosed}
 err:=add(path)
 w.stateAccess.Lock();closed=w.closed;w.stateAccess.Unlock()
 if closed{return os.ErrClosed}
 return err
}
