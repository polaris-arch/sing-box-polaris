package log

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/observable"
)

// One owner survives graph replacement, including a disabled cold start.
// Component loggers pin an emission generation, never a file or NOP factory.
type runtimeFactory struct {
	control         sync.Mutex
	access          sync.Mutex
	base            Options
	current         *runtimeLogGeneration
	generations     map[*runtimeLogGeneration]struct{}
	pending         *RuntimeOptionsChange
	writers         []PlatformWriter
	subscriber      *observable.Subscriber[Entry]
	observer        *observable.Observer[Entry]
	started, closed bool
	closeOnce       sync.Once
	closeDone       chan struct{}
	closeErr        error
}

type runtimeLogGeneration struct {
	options              option.LogOptions
	sink                 *defaultFactory
	refs                 int
	draining, idleClosed bool
	idle, done           chan struct{}
	err                  error
}

var _ ObservableFactory = (*runtimeFactory)(nil)

func newRuntimeFactory(options Options) (Factory, error) {
	f := &runtimeFactory{
		base: options, generations: make(map[*runtimeLogGeneration]struct{}),
		subscriber: observable.NewSubscriber[Entry](128), closeDone: make(chan struct{}),
	}
	if options.PlatformWriter != nil {
		f.writers = []PlatformWriter{options.PlatformWriter}
	}
	g, err := f.newGeneration(options.Options, false)
	if err != nil {
		return nil, err
	}
	f.current = g
	f.generations[g] = struct{}{}
	return f, nil
}

func (f *runtimeFactory) newGeneration(options option.LogOptions, existingFile bool) (*runtimeLogGeneration, error) {
	g := &runtimeLogGeneration{options: options, idle: make(chan struct{}), done: make(chan struct{})}
	if options.Disabled {
		return g, nil
	}
	settings := f.base
	settings.Options, settings.Observable, settings.PlatformWriter = options, false, nil
	value, err := newConfiguredFactory(settings)
	if err != nil {
		return nil, err
	}
	sink, ok := value.(*defaultFactory)
	if !ok {
		return nil, errors.New("runtime logger requires built-in output")
	}
	sink.needObservable = f.base.Observable
	sink.subscriber, sink.observer = f.subscriber, f.observer
	sink.sharedObservable, sink.runtimeExistingFile = true, existingFile
	for _, writer := range f.writers {
		sink.AttachPlatformWriter(writer)
	}
	g.sink = sink
	return g, nil
}

func (f *runtimeFactory) Start() error {
	f.control.Lock()
	defer f.control.Unlock()
	f.access.Lock()
	if f.closed {
		f.access.Unlock()
		return os.ErrClosed
	}
	if f.started {
		f.access.Unlock()
		return nil
	}
	g := f.current
	f.access.Unlock()
	if g.sink != nil {
		if err := g.sink.Start(); err != nil {
			return err
		}
	}
	f.access.Lock()
	if f.base.Observable && f.observer == nil {
		f.observer = observable.NewObserver[Entry](f.subscriber, 64)
		for generation := range f.generations {
			if generation.sink != nil {
				generation.sink.observer = f.observer
			}
		}
	}
	f.started = true
	f.access.Unlock()
	return nil
}

func (f *runtimeFactory) pin() *runtimeLogGeneration {
	f.access.Lock()
	defer f.access.Unlock()
	if f.closed || f.current == nil || f.current.options.Disabled {
		return nil
	}
	g := f.current
	g.refs++
	return g
}

func (f *runtimeFactory) release(g *runtimeLogGeneration) {
	f.access.Lock()
	defer f.access.Unlock()
	g.refs--
	if g.draining && g.refs == 0 && !g.idleClosed {
		g.idleClosed = true
		close(g.idle)
	}
}

func (f *runtimeFactory) drain(g *runtimeLogGeneration) {
	if g == nil {
		return
	}
	f.access.Lock()
	if g.draining {
		f.access.Unlock()
		return
	}
	g.draining = true
	if g.refs == 0 {
		g.idleClosed = true
		close(g.idle)
	}
	f.access.Unlock()
	go func() {
		<-g.idle
		if g.sink != nil {
			g.err = g.sink.Close()
		}
		f.access.Lock()
		delete(f.generations, g)
		f.access.Unlock()
		close(g.done)
	}()
}

func (f *runtimeFactory) Close() error {
	f.closeOnce.Do(func() {
		f.control.Lock()
		f.access.Lock()
		f.closed = true
		f.current = nil
		var all []*runtimeLogGeneration
		for g := range f.generations {
			all = append(all, g)
		}
		f.access.Unlock()
		f.control.Unlock()
		for _, g := range all {
			f.drain(g)
		}
		for _, g := range all {
			<-g.done
			f.closeErr = errors.Join(f.closeErr, g.err)
		}
		if f.observer != nil {
			f.closeErr = errors.Join(f.closeErr, f.observer.Close())
		} else {
			f.closeErr = errors.Join(f.closeErr, f.subscriber.Close())
		}
		close(f.closeDone)
	})
	<-f.closeDone
	return f.closeErr
}

func (f *runtimeFactory) Level() Level {
	f.access.Lock()
	defer f.access.Unlock()
	if f.current == nil || f.current.options.Disabled {
		return LevelTrace
	}
	if f.current.sink != nil {
		return f.current.sink.Level()
	}
	level, _ := runtimeOptionLevel(f.current.options.Level)
	return level
}

func (f *runtimeFactory) SetLevel(level Level) {
	f.access.Lock()
	defer f.access.Unlock()
	if f.current != nil {
		f.current.options.Level = FormatLevel(level)
		if f.current.sink != nil {
			f.current.sink.SetLevel(level)
		}
	}
}

func (f *runtimeFactory) AttachPlatformWriter(writer PlatformWriter) {
	f.access.Lock()
	defer f.access.Unlock()
	f.writers = append(f.writers, writer)
	for g := range f.generations {
		if g.sink != nil {
			g.sink.AttachPlatformWriter(writer)
		}
	}
}

func (f *runtimeFactory) Logger() ContextLogger { return f.NewLogger("") }
func (f *runtimeFactory) NewLogger(tag string) ContextLogger {
	return &runtimeLogger{owner: f, tag: tag}
}

func (f *runtimeFactory) Subscribe() (observable.Subscription[Entry], <-chan struct{}, error) {
	f.access.Lock()
	defer f.access.Unlock()
	if f.closed {
		return nil, nil, os.ErrClosed
	}
	if !f.started || !f.base.Observable || f.current.options.Disabled {
		return nil, nil, os.ErrInvalid
	}
	return f.observer.Subscribe()
}

func (f *runtimeFactory) UnSubscribe(subscription observable.Subscription[Entry]) {
	f.access.Lock()
	observer := f.observer
	f.access.Unlock()
	if observer != nil {
		observer.UnSubscribe(subscription)
	}
}

// Existing subscriptions stay owned by the stable bus across a disable/enable.
// Disabled generations emit nothing, including platform/file/observer output.
// New subscriptions while disabled have the same ErrInvalid as a cold NOP.
type runtimeLogger struct {
	owner *runtimeFactory
	tag   string
}

func (l *runtimeLogger) Log(ctx context.Context, level Level, args []any) {
	g := l.owner.pin()
	if g == nil {
		return
	}
	defer l.owner.release(g)
	(&observableLogger{defaultFactory: g.sink, tag: l.tag}).Log(ctx, level, args)
}

func (l *runtimeLogger) Trace(args ...any)                             { l.TraceContext(context.Background(), args...) }
func (l *runtimeLogger) TraceContext(ctx context.Context, args ...any) { l.Log(ctx, LevelTrace, args) }

func (l *runtimeLogger) Debug(args ...any)                             { l.DebugContext(context.Background(), args...) }
func (l *runtimeLogger) DebugContext(ctx context.Context, args ...any) { l.Log(ctx, LevelDebug, args) }

func (l *runtimeLogger) Info(args ...any)                             { l.InfoContext(context.Background(), args...) }
func (l *runtimeLogger) InfoContext(ctx context.Context, args ...any) { l.Log(ctx, LevelInfo, args) }

func (l *runtimeLogger) Warn(args ...any)                             { l.WarnContext(context.Background(), args...) }
func (l *runtimeLogger) WarnContext(ctx context.Context, args ...any) { l.Log(ctx, LevelWarn, args) }

func (l *runtimeLogger) Error(args ...any)                             { l.ErrorContext(context.Background(), args...) }
func (l *runtimeLogger) ErrorContext(ctx context.Context, args ...any) { l.Log(ctx, LevelError, args) }

func (l *runtimeLogger) Fatal(args ...any)                             { l.FatalContext(context.Background(), args...) }
func (l *runtimeLogger) FatalContext(ctx context.Context, args ...any) { l.Log(ctx, LevelFatal, args) }

func (l *runtimeLogger) Panic(args ...any)                             { l.PanicContext(context.Background(), args...) }
func (l *runtimeLogger) PanicContext(ctx context.Context, args ...any) { l.Log(ctx, LevelPanic, args) }

func runtimeOptionLevel(value string) (Level, error) {
	if value == "" {
		return LevelTrace, nil
	}
	return ParseLevel(value)
}

// This is a pure, factory-bound eligibility query. It does not open a path.
// File output is limited to the original configured destination; disabling
// may omit that destination, as the real client generator does.
func RuntimeOptionsEligible(factory Factory, next option.LogOptions) bool {
	f, ok := factory.(*runtimeFactory)
	if !ok || f == nil {
		return false
	}
	f.access.Lock()
	defer f.access.Unlock()
	return f.eligible(next)
}

func (f *runtimeFactory) eligible(next option.LogOptions) bool {
	if f.closed || next.Timestamp != f.base.Options.Timestamp || next.DisableColor != f.base.Options.DisableColor {
		return false
	}
	if next.Output != f.base.Options.Output && !(next.Disabled && next.Output == "") {
		return false
	}
	_, err := runtimeOptionLevel(next.Level)
	return err == nil
}

// Retained until publication/abort and emission retirement have all completed.
type RuntimeOptionsChange struct {
	owner        *runtimeFactory
	before, next *runtimeLogGeneration
	options      option.LogOptions
	levelOnly    bool
	fenced       atomic.Bool
	state        atomic.Uint32 // 0 prepared, 1 published, 2 aborted
}

func PrepareRuntimeOptions(factory Factory, next option.LogOptions) (*RuntimeOptionsChange, error) {
	f, ok := factory.(*runtimeFactory)
	if !ok || f == nil {
		return nil, errors.New("logger has no stable runtime options owner")
	}
	f.control.Lock()
	defer f.control.Unlock()
	f.access.Lock()
	if !f.eligible(next) || f.pending != nil || len(f.generations) >= 64 || (!f.started && f.current.options.Disabled != next.Disabled) {
		f.access.Unlock()
		return nil, errors.New("unsupported or busy runtime log options")
	}
	p := &RuntimeOptionsChange{owner: f, before: f.current, options: next}
	p.levelOnly = f.current.options.Disabled == next.Disabled
	if p.levelOnly {
		p.next = p.before
		f.pending = p
		f.access.Unlock()
		return p, nil
	}
	started := f.started
	// Serialize writer attachment with the registry insertion.
	g, err := f.newGeneration(next, true)
	if err != nil {
		f.access.Unlock()
		return nil, err
	}
	f.generations[g] = struct{}{}
	f.access.Unlock()
	if started && g.sink != nil {
		if err := g.sink.Start(); err != nil {
			f.drain(g)
			<-g.done
			return nil, errors.Join(err, g.err)
		}
	}
	p.next = g
	f.access.Lock()
	f.pending = p
	f.access.Unlock()
	return p, nil
}

// The short metadata fence prevents Close/another prepare racing publication,
// while ordinary logging remains unblocked. The coordinator must always call
// Finish, including graph CAS failure, before invoking Abort or Retire.
type RuntimeLogPublication struct {
	change *RuntimeOptionsChange
	once   sync.Once
}

func (p *RuntimeOptionsChange) PreparePublication() (*RuntimeLogPublication, error) {
	f := p.owner
	if !p.fenced.CompareAndSwap(false, true) {
		return nil, errors.New("runtime log publication already fenced")
	}
	f.control.Lock()
	f.access.Lock()
	valid := !f.closed && f.pending == p && f.current == p.before && p.state.Load() == 0
	f.access.Unlock()
	if !valid {
		p.fenced.Store(false)
		f.control.Unlock()
		return nil, errors.New("runtime log publication lost its owner")
	}
	return &RuntimeLogPublication{change: p}, nil
}

func (p *RuntimeLogPublication) Publish() {
	c := p.change
	f := c.owner
	f.access.Lock()
	if c.state.CompareAndSwap(0, 1) {
		if c.levelOnly {
			c.before.options = c.options
			if c.before.sink != nil {
				level, _ := runtimeOptionLevel(c.options.Level)
				c.before.sink.SetLevel(level)
			}
		} else {
			f.current = c.next
		}
		f.pending = nil
	}
	f.access.Unlock()
}

func (p *RuntimeLogPublication) Finish() {
	p.once.Do(func() { p.change.fenced.Store(false); p.change.owner.control.Unlock() })
}

func (p *RuntimeOptionsChange) Abort() error {
	f := p.owner
	f.control.Lock()
	if p.state.Load() == 1 {
		f.control.Unlock()
		return errors.New("published runtime logger cannot be aborted")
	}
	p.state.Store(2)
	f.access.Lock()
	if f.pending == p {
		f.pending = nil
	}
	f.access.Unlock()
	f.control.Unlock()
	if p.levelOnly {
		return nil
	}
	f.drain(p.next)
	<-p.next.done
	return p.next.err
}

func (p *RuntimeOptionsChange) Retire(ctx context.Context) error {
	if p.state.Load() != 1 {
		return errors.New("runtime log generation was not published")
	}
	if p.levelOnly {
		return nil
	}
	p.owner.drain(p.before)
	select {
	case <-p.before.done:
		return p.before.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
