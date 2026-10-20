package daemon

import (
 "reflect"
 "testing"
)

func TestRuntimeStartupOverrideSnapshotIsDetached(t *testing.T) {
 input:=&OverrideOptions{AutoRedirect:true,IncludePackage:[]string{"one"},ExcludePackage:[]string{"two"}}
 captured:=cloneRuntimeOverrides(input)
 input.IncludePackage[0]="changed";input.ExcludePackage[0]="changed"
 next:=cloneRuntimeOverrides(captured);next.IncludePackage[0]="request"
 if captured.IncludePackage[0]!="one" || captured.ExcludePackage[0]!="two" || !captured.AutoRedirect { t.Fatal("startup snapshot mutated") }
 if cloneRuntimeOverrides(nil)!=nil { t.Fatal("nil override became explicit") }
}
func TestRuntimePackageProjectionIsIdempotentForEffectiveJSON(t *testing.T) {
 configured:=[]string{"base","override"};overrides:=[]string{"override","added","added"}
 projected:=appendRuntimeOverridePackages(configured,overrides)
 if !reflect.DeepEqual(projected,[]string{"base","override","added"}) { t.Fatal(projected) }
 if !reflect.DeepEqual(appendRuntimeOverridePackages(projected,overrides),projected) { t.Fatal("reloaded effective config duplicated overrides") }
 projected[0]="changed";if configured[0]!="base" { t.Fatal("projection mutated source") }
}
