//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"testing"
	"time"
	"path/filepath"

	"github.com/sagernet/sing/service"
	"github.com/sagernet/tailscale/tsnet"

	"github.com/sagernet/sing-box/adapter"
)

func testPreparedDirectoryPlan() (*PreparedDirectoryLeases,*preparedDirectoryEntry) {
	p := &PreparedDirectoryLeases{}
	p.ctx = context.WithValue(context.Background(),preparedDirectoryKey{},p)
	d := newDirectoryOwner(p.ctx,"node","selected")
	d.node.DirectoryIdentity,d.node.Incarnation,d.node.DirectoryEpoch = "identity","incarnation","epoch"
	e := &preparedDirectoryEntry{tag:"node",originalState:"logical",originalTaildrop:"logical/drop",state:"selected",taildrop:"selected/drop",owner:d,validate:func() error { return nil }}
	p.entries = []*preparedDirectoryEntry{e}
	return p,e
}

func TestPreparedDirectoryBindingSingleUseAndExactTuple(t *testing.T) {
	p,e := testPreparedDirectoryPlan()
	if _,err := beginPreparedDirectoryBinding(p.ctx,"node","other","logical/drop"); err == nil { t.Fatal("mismatched tuple accepted") }
	b,err := beginPreparedDirectoryBinding(p.ctx,"node","logical","logical/drop")
	if err != nil { t.Fatal(err) }
	if b.entry.owner != e.owner || b.entry.state != "selected" { t.Fatal("original selected owner lost") }
	if _,err := beginPreparedDirectoryBinding(p.ctx,"node","logical","logical/drop"); err == nil { t.Fatal("concurrent binding accepted") }
	b.finish(true)
	if _,err := beginPreparedDirectoryBinding(p.ctx,"node","logical","logical/drop"); err == nil { t.Fatal("binding replay accepted") }
}

func TestPreparedDirectoryAbortRetainsInflightOwner(t *testing.T) {
	p,e := testPreparedDirectoryPlan()
	b,err := beginPreparedDirectoryBinding(p.ctx,"node","logical","logical/drop")
	if err != nil { t.Fatal(err) }
	called := false
	b.publish(func() error { called = true; return nil })
	if err := p.Abort(); err == nil || called { t.Fatal("abort closed in-flight constructor") }
	b.finish(false)
	if p.entries[0].owner != e.owner || len(p.Snapshot()) != 1 { t.Fatal("Unknown original owner discarded") }
	if err := p.Commit(); err == nil { t.Fatal("aborted plan committed") }
}

func TestPreparedDirectoryAbortCallbackOutsideGuard(t *testing.T) {
	p,_ := testPreparedDirectoryPlan()
	b,err := beginPreparedDirectoryBinding(p.ctx,"node","logical","logical/drop")
	if err != nil { t.Fatal(err) }
	calls := 0
	failure := errors.New("cleanup uncertain")
	b.publish(func() error { p.mu.Lock(); p.mu.Unlock(); calls++; return failure })
	b.finish(false)
	if err := p.Abort(); !errors.Is(err,failure) { t.Fatal("cleanup evidence lost",err) }
	_ = p.Abort()
	if calls != 1 || len(p.Snapshot()) != 1 { t.Fatal("cleanup replay or original owner lost") }
}

func TestPreparedDirectoryCommitRequiresExactObservedInventory(t *testing.T) {
	p,e := testPreparedDirectoryPlan()
	b,_ := beginPreparedDirectoryBinding(p.ctx,"node","logical","logical/drop")
	b.finish(true)
	if err := p.Commit(); err == nil { t.Fatal("unvalidated plan committed") }
	n := e.owner.snapshot()
	wrong := n; wrong.DirectoryEpoch = "different"
	if err := p.Validate([]adapter.TailscaleDirectoryNode{wrong}); err == nil { t.Fatal("foreign epoch accepted") }
	if err := p.Validate([]adapter.TailscaleDirectoryNode{n,n}); err == nil { t.Fatal("duplicate derived entry dropped") }
	if err := p.Validate([]adapter.TailscaleDirectoryNode{n}); err != nil { t.Fatal(err) }
	if err := p.Commit(); err != nil { t.Fatal(err) }
	if err := p.Commit(); err == nil { t.Fatal("commit replay accepted") }
	if err := p.Abort(); err == nil { t.Fatal("caller reclaimed transferred owner") }
}

func TestPreparedDirectoryPanicFinishesFailedBinding(t *testing.T) {
	p,_ := testPreparedDirectoryPlan()
	func() {
		defer func() { if recover() == nil { t.Error("fixture did not panic") } }()
		b,_ := beginPreparedDirectoryBinding(p.ctx,"node","logical","logical/drop")
		defer b.finish(false)
		b.publish(func() error { return nil })
		panic("constructor observer")
	}()
	if p.entries[0].binding || !p.entries[0].failed { t.Fatal("panic lost binding ownership") }
	if err := p.Abort(); err != nil { t.Fatal(err) }
}

func TestPreparedActualConstructorTailObserverPanicRetainsOriginal(t *testing.T) {
	p,e := testPreparedDirectoryPlan()
	b,err := beginPreparedDirectoryBinding(p.ctx,"node","logical","logical/drop")
	if err != nil { t.Fatal(err) }
	observed := false
	observer := adapter.TailscaleStoreConstructionObserver{Observe:func(adapter.TailscaleStoreNode,func(time.Time) adapter.TailscaleStoreNode) bool { observed = true; panic("actual store observer") }}
	ctx := service.ContextWithPtr(p.ctx,&observer)
	endpoint := &Endpoint{directory:e.owner,taildrop:newTaildropManager(ctx,nil,"node",t.TempDir(),nil),server:&tsnet.Server{}}
	func() {
		defer func() { if recover() == nil { t.Error("actual observer did not panic") } }()
		_ = endpoint.finishDirectoryConstruction(ctx,"node",filepath.Join(t.TempDir(),"state"),b)
	}()
	if !observed || e.binding || !e.failed || e.cleanup == nil || endpoint.stateStore != nil { t.Fatal("observer panic lost partially initialized original owner") }
	if err := p.Abort(); err != nil { t.Fatal(err) }
	select { case <-e.owner.retired: default: t.Fatal("actual constructor cleanup did not retire original owner") }
	if len(p.Snapshot()) != 1 { t.Fatal("failed original census disappeared") }
}

func TestPreparedActualConstructorTailCanceledScope(t *testing.T) {
	p,e := testPreparedDirectoryPlan()
	b,err := beginPreparedDirectoryBinding(p.ctx,"node","logical","logical/drop")
	if err != nil { t.Fatal(err) }
	parent,cancel := context.WithCancel(p.ctx)
	scope := adapter.NewScope(parent,nil)
	ctx := adapter.ContextWithConstructionScope(parent,scope)
	cancel()
	endpoint := &Endpoint{directory:e.owner,taildrop:newTaildropManager(ctx,nil,"node",t.TempDir(),nil),server:&tsnet.Server{}}
	if err := endpoint.finishDirectoryConstruction(ctx,"node",filepath.Join(t.TempDir(),"state"),b); err == nil { t.Fatal("immediately cleaned endpoint returned usable") }
	if e.binding || !e.failed || endpoint.stateStore == nil || !endpoint.stateStore.isSealed() { t.Fatal("immediate Scope cleanup was not observed") }
	select { case <-e.owner.retired: default: t.Fatal("original retirement did not complete") }
	if err := p.Abort(); err != nil { t.Fatal(err) }
	if len(p.Snapshot()) != 1 { t.Fatal("aborted owner evidence lost") }
}
