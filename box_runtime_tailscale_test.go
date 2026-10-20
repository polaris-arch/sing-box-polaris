//go:build with_tailscale

package box

import (
 "path/filepath"
 "testing"
)

func TestRuntimeTailscaleDirectoryOverlapIsComponentBounded(t *testing.T){
 root:=filepath.Join(string(filepath.Separator),"state","node")
 for _,test:=range []struct{a,b string;overlap bool}{
  {root,root,true},
  {root,filepath.Join(root,"Taildrop"),true},
  {filepath.Join(root,"Taildrop"),root,true},
  {root,root+"-other",false},
  {filepath.Join(root,"a"),filepath.Join(root,"b"),false},
 }{if got:=runtimeTailscaleDirectoriesOverlap(test.a,test.b);got!=test.overlap{t.Fatalf("overlap(%q,%q)=%v",test.a,test.b,got)}}
}
