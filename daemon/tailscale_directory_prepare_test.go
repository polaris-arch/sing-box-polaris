package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func TestDirectoryPreparationCommitWinsRequestCancellation(t *testing.T) {
	request,cancelRequest := context.WithCancel(context.Background())
	defer cancelRequest()
	runtime,cancelRuntime := context.WithCancel(context.Background())
	defer cancelRuntime()
	w := watchDirectoryPreparation(request,cancelRuntime)
	if err := w.commit(request,func() error { return nil }); err != nil { t.Fatal(err) }
	cancelRequest()
	if runtime.Err() != nil { t.Fatal("request lifetime captured successful runtime") }
}

func TestDirectoryPreparationReservedCancellationWinsCommit(t *testing.T) {
	request,cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan struct{})
	w := watchDirectoryPreparation(request,func() { close(called) })
	cancel()
	select { case <-called: case <-time.After(5*time.Second): t.Fatal("cancellation callback watchdog") }
	committed := false
	if err := w.commit(context.Background(),func() error { committed = true; return nil }); err == nil || committed { t.Fatal("commit ignored already reserved cancellation") }
}

func TestPreparedOriginalAuthoritySurvivesNilHostAndDowngradesFrozen(t *testing.T) {
	d,err := adapter.NewTailscaleDirectoryDomain(filepath.Join(t.TempDir(),"polaris"),"original")
	if err != nil { t.Fatal(err) }
	if err := d.SetFailureHandler(func(error) error { return nil }); err != nil { t.Fatal(err) }
	if err := d.Activate(); err != nil { t.Fatal(err) }
	r := &tailscaleRetirementRun{directoryAuthority:d,directoryAuthorityBound:true,directoryFinal:&tailscaleDirectoryInstance{Terminal:"SealedDrained",CensusComplete:true,Nodes:[]adapter.TailscaleDirectoryNode{}}}
	s := &StartedService{ctx:context.Background(),tailscaleRetirementRuns:[]*tailscaleRetirementRun{r}}
	read := func() tailscaleDirectoryInstance {
		var response struct { Instances []tailscaleDirectoryInstance `json:"instances"` }
		if err := json.Unmarshal([]byte(s.ExportTailscaleDirectoryRetirement()),&response); err != nil { t.Fatal(err) }
		return response.Instances[0]
	}
	if got := read(); !got.CensusComplete || got.Terminal != "SealedDrained" { t.Fatal("nil host erased exact original authority",got) }
	if err := d.Fail(errors.New("original revoked")); err != nil { t.Fatal(err) }
	if got := read(); got.CensusComplete || got.Terminal != "Unknown" { t.Fatal("frozen positive survived original revocation",got) }
	if !r.directoryFinal.CensusComplete { t.Fatal("export mutated frozen original") }
	r.directoryAuthorityBound = false
	if got := read(); got.CensusComplete { t.Fatal("legacy nil authority accepted") }
}

func TestPreparationCancellationBeforeCallbackPreservesStartedInstance(t *testing.T) {
	host,_ := retirementPureHost(t)
	oldCtx,cancelOld := context.WithCancel(context.Background())
	defer cancelOld()
	old := &Instance{ctx:oldCtx,cancel:cancelOld}
	host.instance = old
	host.serviceStatus = &ServiceStatus{Status:ServiceStatus_STARTED}
	request,cancel := context.WithCancel(context.Background())
	cancel()
	callback := false
	err := host.StartOrReloadServiceWithBeforeStart(request,`{}`,nil,func() { callback = true })
	if !errors.Is(err,context.Canceled) { t.Fatal("missing preparation cancellation",err) }
	if callback || host.instance != old || old.closeStarted.Load() || oldCtx.Err() != nil || host.serviceStatus.Status != ServiceStatus_STARTED { t.Fatal("pre-admission cancellation changed old service/snapshot") }
}

type preparationFixtureResources struct {
	ctx context.Context
	nodes []adapter.TailscaleDirectoryNode
	aborted,committed bool
}
func (p *preparationFixtureResources) Context() context.Context { return p.ctx }
func (p *preparationFixtureResources) Snapshot() []adapter.TailscaleDirectoryNode { return append([]adapter.TailscaleDirectoryNode(nil),p.nodes...) }
func (p *preparationFixtureResources) Abort() error { p.aborted = true; return nil }
func (p *preparationFixtureResources) Validate(nodes []adapter.TailscaleDirectoryNode) error {
	if len(nodes) != len(p.nodes) { return errors.New("fixture inventory mismatch") }
	return nil
}
func (p *preparationFixtureResources) Commit() error { p.committed = true; return nil }

func TestActualReloadPreparationFailurePreservesOldAndOriginalCensus(t *testing.T) {
	for failAt:=0; failAt<3; failAt++ {
		host,_ := retirementPureHost(t)
		oldCtx,cancelOld := context.WithCancel(context.Background())
		old := &Instance{ctx:oldCtx,cancel:cancelOld}
		host.instance = old
		host.serviceStatus = &ServiceStatus{Status:ServiceStatus_STARTED}
		p,err := host.prepareInstance(context.Background(),`{}`,nil)
		if err != nil { t.Fatal(err) }
		resources := &preparationFixtureResources{ctx:p.ctx}
		callback := false
		injected := errors.New("capacity exhausted")
		prepare := func(request context.Context,p *preparedInstance) error {
			r := &tailscaleRetirementRun{binding:adapter.TailscaleStoreRunBinding{RunNonce:"original",ConfigDigest:"digest"},expected:[]string{"a","b","c"}}
			p.directoryPlan,p.directoryRun = resources,r
			p.directoryFinished = make(chan struct{})
			r.closeFinished = p.directoryFinished
			p.directoryCancel = func() {}
			p.directoryWatch = watchDirectoryPreparation(request,p.directoryCancel)
			r.installPreparedDirectories(resources,nil)
			host.tailscaleRetirementRuns = append(host.tailscaleRetirementRuns,r)
			for index,tag := range r.expected {
				if index == failAt { return injected }
				resources.nodes = append(resources.nodes,adapter.TailscaleDirectoryNode{Tag:tag,StateDirectory:tag,RunNonce:r.binding.RunNonce,ConfigDigest:r.binding.ConfigDigest,CensusVersion:1,WriterState:"Unknown",DirectoryIdentity:tag,Incarnation:"incarnation",DirectoryEpoch:"epoch"})
			}
			return nil
		}
		err = host.prepareReloadAdmission(context.Background(),p,func(){callback=true},prepare)
		if !errors.Is(err,injected) || callback || host.instance != old || old.closeStarted.Load() || oldCtx.Err()!=nil || host.serviceStatus.Status != ServiceStatus_STARTED { t.Fatal("real preparation boundary mutated old service",failAt,err) }
		if !resources.aborted || len(host.tailscaleRetirementRuns)!=1 || host.tailscaleRetirementRuns[0]!=p.directoryRun { t.Fatal("failed preparation lost original run or cleanup") }
		p.directoryRun.access.Lock()
		snapshot := p.directoryRun.directorySnapshotUnderLock()
		p.directoryRun.access.Unlock()
		if snapshot.CensusComplete || snapshot.Terminal!="Unknown" || len(snapshot.Nodes)!=failAt || snapshot.RunNonce!="original" { t.Fatal("partial census was fabricated/pruned",snapshot) }
		cancelOld()
	}
}

func TestActualPreparedCommitKeepsSingleRunAndCompletionSignal(t *testing.T) {
	host,_ := retirementPureHost(t)
	p,err := host.prepareInstance(context.Background(),`{}`,nil)
	if err != nil { t.Fatal(err) }
	resources := &preparationFixtureResources{ctx:p.ctx}
	r := &tailscaleRetirementRun{binding:adapter.TailscaleStoreRunBinding{RunNonce:"original",ConfigDigest:"digest"}}
	p.directoryPlan,p.directoryRun = resources,r
	p.directoryFinished = make(chan struct{})
	r.closeFinished = p.directoryFinished
	p.directoryCancel = func() {}
	p.directoryWatch = watchDirectoryPreparation(p.request,p.directoryCancel)
	r.installPreparedDirectories(resources,nil)
	host.tailscaleRetirementRuns = append(host.tailscaleRetirementRuns,r)
	i := &Instance{tailscaleRetirement:r,closeFinished:make(chan struct{})}
	if err := p.attachPreparedDirectoryRun(i); err != nil { t.Fatal(err) }
	if err := p.commitDirectories(resources.Snapshot); err != nil { t.Fatal(err) }
	if len(host.tailscaleRetirementRuns)!=1 || host.tailscaleRetirementRuns[0]!=r || i.closeFinished!=p.directoryFinished || r.closeFinished!=i.closeFinished || !resources.committed || !p.directoryCommitted { t.Fatal("commit substituted original run/signal") }
	if err := p.abortDirectories(); err != nil || resources.aborted { t.Fatal("committed resources reclaimed by preparation") }
	close(i.closeFinished)
	select { case <-r.closeFinished: default: t.Fatal("original run did not observe original Instance completion") }
}
