package adapter

import (
 "context"
 "testing"
)
func TestRuntimeTailscalePhysicalBaseDoesNotInheritLogicalCancellation(t *testing.T) {
 logical,cancel:=context.WithCancel(context.Background())
 canonical:=[]byte(`{"endpoints":[]}`)
 logical=ContextWithRuntimeTailscaleConfiguration(logical,canonical)
 stable,stop:=context.WithCancel(context.Background());defer stop()
 registration:=ContextWithRuntimeTailscaleChildBase(logical,stable)
 cancel()
 base,ok:=RuntimeTailscaleChildBase(registration)
 if !ok||base.Err()!=nil{t.Fatal("physical base inherited retired logical cancellation")}
 captured,ok:=RuntimeTailscaleConfiguration(registration)
 if !ok||string(captured)!=string(canonical){t.Fatal("birth configuration changed")}
 stop();if base.Err()==nil{t.Fatal("physical base lost its own cancellation")}
}
