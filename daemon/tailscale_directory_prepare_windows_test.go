//go:build windows && with_tailscale

package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestInheritedWindowsAuthorityRejectsBeforeReloadCallback(t *testing.T) {
	d,err := adapter.NewTailscaleWindowsDirectoryDomain(`C:\polaris-warm-fixture`,strings.Repeat("a",32))
	if err != nil { t.Fatal(err) }
	if err := d.SetFailureHandler(func(error) error { return nil }); err != nil { t.Fatal(err) }
	if err := d.Activate(); err != nil { t.Fatal(err) }
	state := filepath.Join(d.LogicalRoot(),"node")
	mapping,err := adapter.NewTailscaleDirectoryMapping(d,[]adapter.TailscaleDirectoryMappingInput{{StateDirectory:state,TaildropDirectory:filepath.Join(state,"Taildrop")}})
	if err != nil { t.Fatal(err) }
	for _,ctx := range []context.Context{adapter.ContextWithTailscaleDirectoryDomain(context.Background(),d),adapter.ContextWithTailscaleDirectoryMapping(context.Background(),mapping)} {
		host,_ := retirementPureHost(t)
		old := &Instance{}
		host.instance = old
		host.serviceStatus = &ServiceStatus{Status:ServiceStatus_STARTED}
		p := &preparedInstance{ctx:ctx,request:context.Background()}
		called := false
		err := host.prepareReloadAdmission(context.Background(),p,func(){called=true},host.prepareManagedDirectories)
		if err==nil || !strings.Contains(err.Error(),"inherited managed") || called || host.instance!=old || old.closeStarted.Load() || host.serviceStatus.Status!=ServiceStatus_STARTED || len(host.tailscaleRetirementRuns)!=0 { t.Fatal("inherited authority crossed preparation boundary",err) }
	}
}
