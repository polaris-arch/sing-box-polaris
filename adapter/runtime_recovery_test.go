package adapter

import (
 "context"
 "path/filepath"
 "testing"
)
func TestRuntimeRecoveryRootRequiresExplicitAbsoluteHostPath(t *testing.T){
 for _,root:=range []string{"",".","state"}{
  if _,ok:=RuntimeRecoveryRootFromContext(ContextWithRuntimeRecoveryRoot(context.Background(),root));ok{t.Fatal("implicit cwd gained recovery authority")}
 }
 root:=t.TempDir()
 ctx:=ContextWithRuntimeRecoveryRoot(context.Background(),root)
 if actual,ok:=RuntimeRecoveryRootFromContext(ctx);!ok||actual!=filepath.Clean(root){t.Fatal("explicit root lost")}
 if _,ok:=RuntimeRecoveryRootFromContext(ContextWithRuntimeRecoveryRoot(ctx,""));ok{t.Fatal("invalid replacement retained inherited root")}
}
