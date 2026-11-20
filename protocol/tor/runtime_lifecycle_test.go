package tor

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	binetor "github.com/sagernet/sing-box/common/binetor"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/cretz/bine/process"
)

type torResourceDirectoryManager struct{ filemanager.Manager }

func (m torResourceDirectoryManager) ConfigurationDirectoryPath(path string) string {
	return m.BasePath(path)
}

func TestTorExternalProcessRetainsResourceDirectory(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows helper resource-directory contract")
	}
	directory := t.TempDir()
	ctx := filemanager.WithDefault(context.Background(), directory, "", 0, 0)
	plain := &Outbound{startConf: &binetor.StartConf{ExePath: "cmd.exe"}}
	if err := plain.initRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.runtimeCleanup() })
	command, err := plain.processOwner.creator.(process.CmdCreatorFunc)(ctx)
	if err != nil || command.Dir != "" {
		t.Fatalf("ordinary file manager changed process cwd: %v, %v", command, err)
	}
	ctx = service.ContextWith[filemanager.Manager](ctx, torResourceDirectoryManager{service.FromContext[filemanager.Manager](ctx)})
	for _, executable := range []string{`.\tor.exe`, "cmd.exe"} {
		t.Run(executable, func(t *testing.T) {
			outbound := &Outbound{startConf: &binetor.StartConf{ExePath: executable}}
			if err := outbound.initRuntime(ctx); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = outbound.runtimeCleanup() })
			factory := outbound.processOwner.creator.(process.CmdCreatorFunc)
			command, err := factory(ctx, "--GeoIPFile", "relative-geoip")
			if err != nil {
				t.Fatal(err)
			}
			if command.Dir != directory || len(command.Args) != 3 || command.Args[2] != "relative-geoip" {
				t.Fatalf("command dir=%q args=%q", command.Dir, command.Args)
			}
			expected := filepath.Join(directory, "tor.exe")
			if executable == "cmd.exe" {
				expected, err = exec.LookPath(executable)
				if err != nil {
					t.Fatal(err)
				}
			}
			if command.Path != expected {
				t.Fatalf("executable = %q; want %q", command.Path, expected)
			}
		})
	}
}

type torTestProcess struct {
	entered, proceed chan struct{}
	waits            atomic.Int32
	panicWait        bool
}

func (*torTestProcess) Start() error { return nil }
func (p *torTestProcess) Wait() error {
	p.waits.Add(1)
	close(p.entered)
	<-p.proceed
	if p.panicWait {
		panic("native wait")
	}
	return errors.New("exit status after cancellation")
}

func (*torTestProcess) EmbeddedControlConn() (net.Conn, error) {
	return nil, process.ErrControlConnUnsupported
}

type torTestCreator struct{ process *torTestProcess }

func (c torTestCreator) New(context.Context, ...string) (process.Process, error) {
	return c.process, nil
}

func TestTorOwnerJoinsSingleActualWait(t *testing.T) {
	for _, panicWait := range []bool{false, true} {
		raw := &torTestProcess{entered: make(chan struct{}), proceed: make(chan struct{}), panicWait: panicWait}
		owner := &runtimeProcessCreator{creator: torTestCreator{raw}}
		p, err := owner.New(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Start(); err != nil {
			t.Fatal(err)
		}
		<-raw.entered
		observer := make(chan error, 1)
		go func() { observer <- p.Wait() }()
		closed := make(chan error, 1)
		go func() { closed <- owner.closeAndWait() }()
		select {
		case <-closed:
			t.Fatal("process completion inferred before actual Wait returned")
		default:
		}
		close(raw.proceed)
		<-observer
		err = <-closed
		if panicWait && err == nil {
			t.Fatal("unknown native completion lost")
		}
		if !panicWait && err != nil {
			t.Fatal("actual observed process exit was mistaken for uncertainty")
		}
		if raw.waits.Load() != 1 {
			t.Fatal("multiple actual process Wait calls")
		}
	}
}
