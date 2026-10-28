package tka

import (
 "errors"
 "os"
 "path/filepath"
 "testing"
 "github.com/sagernet/tailscale/util/dirscope"
)
func TestSealedChonkDoesNotCreateDirectory(t *testing.T) {
 scope:=new(dirscope.Scope)
 scope.Seal()
 path:=filepath.Join(t.TempDir(),"not-created")
 if _,err:=ChonkDirWithScope(path,scope); !errors.Is(err,dirscope.ErrSealed) {t.Fatal(err)}
 if _,err:=os.Stat(path); !os.IsNotExist(err){t.Fatalf("unexpected directory: %v",err)}
}
