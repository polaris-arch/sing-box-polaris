//go:build windows && with_tailscale

package box

import (
 "context"
 "encoding/json"
 "path/filepath"
 "runtime/debug"
 "strings"
 "testing"
 "github.com/sagernet/sing-box/adapter"
 C "github.com/sagernet/sing-box/constant"
 "github.com/sagernet/sing-box/experimental/directorywindows"
 "github.com/sagernet/sing-box/option"
 "github.com/sagernet/sing/service"
)
func TestWindowsDirectorySourceContract(t *testing.T){
 source:=strings.Repeat("a",40);clean:=&debug.BuildInfo{Settings:[]debug.BuildSetting{{Key:"vcs",Value:"git"},{Key:"vcs.revision",Value:source},{Key:"vcs.modified",Value:"false"}}}
 if err:=directorywindows.ValidateSource(source,source,clean);err!=nil{t.Fatal(err)}
 if err:=directorywindows.ValidateSource(source,source,nil);err!=nil{t.Fatal("clean-source ldflag contract without optional VCS",err)}
 for _,x:=range []struct{expected,actual string;info *debug.BuildInfo}{
  {source,"",nil},{"",source,nil},{source,strings.Repeat("b",40),nil},{strings.ToUpper(source),source,nil},
  {source,source,&debug.BuildInfo{Settings:[]debug.BuildSetting{{Key:"vcs",Value:"git"}}}},
  {source,source,&debug.BuildInfo{Settings:[]debug.BuildSetting{{Key:"vcs",Value:"git"},{Key:"vcs.revision",Value:source},{Key:"vcs.modified",Value:"true"}}}},
  {source,source,&debug.BuildInfo{Settings:[]debug.BuildSetting{{Key:"vcs",Value:"git"},{Key:"vcs.revision",Value:source},{Key:"vcs.modified",Value:"false"},{Key:"vcs.modified",Value:"false"}}}},
 }{if err:=directorywindows.ValidateSource(x.expected,x.actual,x.info);err==nil{t.Fatalf("accepted invalid identity: %+v",x)}}
}
func TestWindowsDirectoryReservedNamespaceWholeConfig(t *testing.T){
 for _,raw:=range []string{`{"log":{"output":"C:\\x\\tailscale-windows-v1\\log"}}`,`{"cache":"TAILSCALE-WINDOWS-V1"}`,`{"other":"tailscale\u002dwindows-v1"}`}{if err:=directorywindows.RejectReservedPaths([]byte(raw));err==nil{t.Fatalf("accepted %s",raw)}}
 t.Setenv("POLARIS_TEST_PATH","C:\\tailscale-windows-v1")
 if err:=directorywindows.RejectReservedPaths([]byte(`{"other":"${POLARIS_TEST_PATH}"}`));err==nil{t.Fatal("env-expanded physical path accepted")}
 if err:=directorywindows.RejectReservedPaths([]byte(`{"other":"tailscale","nested":["normal"]}`));err!=nil{t.Fatal(err)}
}
type windowsActivationRegistry struct{}
func(windowsActivationRegistry)OptionTypes()[]string{return []string{C.TypeTailscale}}
func(windowsActivationRegistry)CreateOptions(kind string)(any,bool){if kind==C.TypeTailscale{return new(option.TailscaleEndpointOptions),true};return nil,false}
func TestWindowsDirectoryActivationAndOriginalBinding(t *testing.T){
 root:=t.TempDir();nonce:=strings.Repeat("1",32)
 envelope:=map[string]any{"version":1,"root":root,"run_nonce":nonce,"expected_source":C.SourceRevision}
 endpoint:=map[string]any{"type":C.TypeTailscale,"tag":"node","state_directory":filepath.Join(root,"tailscale","node"),"taildrop_directory":filepath.Join(root,"tailscale","node","Taildrop")}
 raw,err:=json.Marshal(map[string]any{"polaris_windows_directory":envelope,"endpoints":[]any{endpoint}});if err!=nil{t.Fatal(err)}
 ctx:=service.ContextWith[option.EndpointOptionsRegistry](context.Background(),windowsActivationRegistry{})
 var options option.Options;if err:=options.UnmarshalJSONContext(ctx,raw);err!=nil{t.Fatal(err)}
 original:=&adapter.TailscaleStoreRunBinding{RunNonce:strings.Repeat("2",64),ConfigDigest:strings.Repeat("3",64)};ctx=service.ContextWithPtr(ctx,original)
 prepared,err:=prepareWindowsDirectoryDomain(ctx,options);if err!=nil{t.Fatal("official source-bound activation must succeed",err)}
 domain:=adapter.TailscaleDirectoryDomainFromContext(prepared);mapping:=adapter.TailscaleDirectoryMappingFromContext(prepared)
 if domain==nil||!domain.Active()||mapping==nil||domain.PhysicalRoot()!=filepath.Join(root,"tailscale-windows-v1"){t.Fatal("no actual managed capability")}
 if got:=service.PtrFromContext[adapter.TailscaleStoreRunBinding](prepared);got!=original{t.Fatal("original daemon binding overwritten")}
 state,taildrop,ok:=mapping.Resolve(endpoint["state_directory"].(string),endpoint["taildrop_directory"].(string));if !ok||state!=filepath.Join(root,"tailscale-windows-v1","node")||taildrop!=filepath.Join(state,"Taildrop"){t.Fatal("incorrect physical mapping")}
 options.Endpoints[0].Options.(*option.TailscaleEndpointOptions).SSHServer=&option.TailscaleSSHServerOptions{Enabled:true}
 if _,err:=prepareWindowsDirectoryDomain(ctx,options);err==nil{t.Fatal("unbounded SSH admitted")}
 options.Endpoints[0].Options.(*option.TailscaleEndpointOptions).SSHServer=nil
 options.PolarisWindowsDirectory.ExpectedSource=strings.Repeat("0",40)
 if _,err:=prepareWindowsDirectoryDomain(ctx,options);err==nil{t.Fatal("source mismatch activated")}
}
