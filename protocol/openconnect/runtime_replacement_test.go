package openconnect

import (
 "testing"
 "github.com/sagernet/sing-box/option"
)
func TestRuntimeReplacementProblemIsReplacementOnlyPolicy(t *testing.T){
 if field,_:=RuntimeReplacementProblem(option.OpenConnectEndpointOptions{});field!=""{t.Fatal("ordinary userspace client rejected")}
 configured:=option.OpenConnectEndpointOptions{};configured.DTLSLocalPort=443
 if field,_:=RuntimeReplacementProblem(configured);field!="dtls_local_port"{t.Fatal("fixed-port replacement not identified")}
 // Constructor admission is independent: this helper is called by the actual
 // replacement census, never simply because the option is present initially.
}
