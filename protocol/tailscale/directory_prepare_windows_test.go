//go:build windows && with_tailscale

package tailscale

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func windowsPreparedPlanFixture(t *testing.T,root string) *PreparedDirectoryLeases {
	t.Helper()
	d,err := adapter.NewTailscaleWindowsDirectoryDomain(root,strings.Repeat("a",32))
	if err != nil { t.Fatal(err) }
	if err := d.SetFailureHandler(func(error) error { return PoisonDirectoryDomain(d.PhysicalRoot()) }); err != nil { t.Fatal(err) }
	if err := d.Activate(); err != nil { t.Fatal(err) }
	logical := filepath.Join(root,"tailscale","node")
	drop := filepath.Join(logical,"Taildrop")
	m,err := adapter.NewTailscaleDirectoryMapping(d,[]adapter.TailscaleDirectoryMappingInput{{StateDirectory:logical,TaildropDirectory:drop}})
	if err != nil { t.Fatal(err) }
	ctx := adapter.ContextWithTailscaleDirectoryMapping(adapter.ContextWithTailscaleDirectoryDomain(context.Background(),d),m)
	ctx = service.ContextWithPtr(ctx,&adapter.TailscaleStoreRunBinding{RunNonce:strings.Repeat("b",64),ConfigDigest:strings.Repeat("c",64)})
	p,err := NewPreparedDirectoryLeases(ctx,option.Options{Endpoints:[]option.Endpoint{{Type:C.TypeTailscale,Tag:"node",Options:&option.TailscaleEndpointOptions{StateDirectory:logical,TaildropDirectory:drop}}}})
	if err != nil { t.Fatal(err) }
	return p
}

func TestWindowsPreparedLeaseBindingDoesNotAppend(t *testing.T) {
	// Native admission bootstraps the physical root, not its trusted parent.
	root := t.TempDir()
	old,err := windowsTestManagedWriter(root,"node")
	if err != nil { t.Fatal(err) }
	defer old.Close()
	p := windowsPreparedPlanFixture(t,root)
	if err := p.Acquire(context.Background()); err != nil { t.Fatal(err) }
	defer p.Abort()
	e := p.entries[0]
	before,err := e.owner.lease.readPrivate(e.owner.lease.control,e.owner.lease.markerName,windowsMarkerLimit+1)
	if err != nil { t.Fatal(err) }
	b,err := beginPreparedDirectoryBinding(p.ctx,e.tag,e.originalState,e.originalTaildrop)
	if err != nil { t.Fatal(err) }
	if err := b.entry.validate(); err != nil { t.Fatal(err) }
	b.finish(true)
	after,err := e.owner.lease.readPrivate(e.owner.lease.control,e.owner.lease.markerName,windowsMarkerLimit+1)
	if err != nil { t.Fatal(err) }
	if string(before) != string(after) || b.entry.owner.lease != e.owner.lease { t.Fatal("constructor reacquired or appended instead of consuming original lease") }
	if err := p.Acquire(context.Background()); err == nil { t.Fatal("acquisition replay accepted") }
}

func TestWindowsPreparedLeaseRejectsDistinctDomainDurablePoison(t *testing.T) {
	root := t.TempDir()
	old,err := windowsTestManagedWriter(root,"node")
	if err != nil { t.Fatal(err) }
	defer old.Close()
	p := windowsPreparedPlanFixture(t,root)
	if err := p.Acquire(context.Background()); err != nil { t.Fatal(err) }
	defer p.Abort()
	if err := p.entries[0].validate(); err != nil { t.Fatal("prepared lease invalid before revocation",err) }
	if err := old.revoke(); err != nil { t.Fatal(err) }
	if !adapter.TailscaleDirectoryDomainFromContext(p.ctx).Active() { t.Fatal("fixture unexpectedly shares domain object") }
	if err := p.entries[0].validate(); err == nil || !strings.Contains(err.Error(),"domain permanently revoked") { t.Fatal("in-memory Active bypassed durable revocation",err) }
	// Revocation retains admission custody until the old owner closes. Release
	// it before the prepared owner's deferred abort needs to persist poison.
	if err := old.Close(); err == nil || !strings.Contains(err.Error(),"domain permanently revoked") { t.Fatal("old revoked lease close lost poison evidence",err) }
	if old.target != 0 || old.lifetime != 0 || old.admission != 0 { t.Fatal("old revoked lease retained custody after close") }
}

// This seam executes the production serial-acquisition loop without native IO.
func TestWindowsPreparedPartialAcquisitionKeepsOnlyActualOriginalNodes(t *testing.T) {
	for failAt := 0; failAt < 3; failAt++ {
		t.Run(fmt.Sprint(failAt),func(t *testing.T) {
			root := filepath.Join(t.TempDir(),"polaris")
			d,err := adapter.NewTailscaleWindowsDirectoryDomain(root,strings.Repeat("a",32))
			if err != nil { t.Fatal(err) }
			if err := d.SetFailureHandler(func(error) error { return nil }); err != nil { t.Fatal(err) }
			if err := d.Activate(); err != nil { t.Fatal(err) }
			var inputs []adapter.TailscaleDirectoryMappingInput
			var options option.Options
			for index:=0; index<3; index++ {
				tag := fmt.Sprint(index)
				state := filepath.Join(root,"tailscale",tag)
				drop := filepath.Join(state,"Taildrop")
				inputs = append(inputs,adapter.TailscaleDirectoryMappingInput{StateDirectory:state,TaildropDirectory:drop})
				options.Endpoints = append(options.Endpoints,option.Endpoint{Type:C.TypeTailscale,Tag:tag,Options:&option.TailscaleEndpointOptions{StateDirectory:state,TaildropDirectory:drop}})
			}
			mapping,err := adapter.NewTailscaleDirectoryMapping(d,inputs)
			if err != nil { t.Fatal(err) }
			ctx := adapter.ContextWithTailscaleDirectoryMapping(adapter.ContextWithTailscaleDirectoryDomain(context.Background(),d),mapping)
			ctx = service.ContextWithPtr(ctx,&adapter.TailscaleStoreRunBinding{RunNonce:"original",ConfigDigest:"digest"})
			p,err := NewPreparedDirectoryLeases(ctx,options)
			if err != nil { t.Fatal(err) }
			calls := 0
			injected := errors.New("capacity exhausted")
			err = p.acquire(context.Background(),func(logical,physical string) (string,*directoryLease,error) {
				index := calls; calls++
				if index == failAt { return "",nil,injected }
				return physical,&directoryLease{Identity:fmt.Sprint(index),Incarnation:"incarnation",Epoch:"epoch"},nil
			})
			if !errors.Is(err,injected) || calls != failAt+1 { t.Fatal("acquisition did not stop at first error",err,calls) }
			nodes := p.Snapshot()
			if len(nodes) != failAt { t.Fatal("fabricated census for failed acquisition",nodes) }
			for _, n := range nodes { if n.RunNonce != "original" || n.ConfigDigest != "digest" || n.WriterState != "Unknown" { t.Fatal("original partial evidence changed",n) } }
			if err := p.Abort(); err != nil { t.Fatal(err) }
			if len(p.Snapshot()) != failAt { t.Fatal("abort pruned original observed nodes") }
		})
	}
}
