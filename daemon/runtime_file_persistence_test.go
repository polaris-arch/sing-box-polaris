package daemon

import (
 "bytes"
 "context"
 "errors"
 "os"
 "path/filepath"
 "runtime"
 "testing"

 box "github.com/sagernet/sing-box"
)

func TestRuntimePersistenceRequestBindingIsPerInstance(t *testing.T) {
 var first, fallback int
 original := func(box.RuntimeIdentity, []byte) error { first++; return nil }
 other := func(box.RuntimeIdentity, []byte) error { fallback++; return nil }
 ctx := ContextWithRuntimePersistence(context.Background(), original)
 if err := runtimePersistenceForRequest(ctx, other)(box.RuntimeIdentity{}, nil); err != nil { t.Fatal(err) }
 if err := runtimePersistenceForRequest(context.Background(), other)(box.RuntimeIdentity{}, nil); err != nil { t.Fatal(err) }
 if first != 1 || fallback != 1 { t.Fatal("request binding leaked") }
 if runtimePersistenceForRequest(ContextWithRuntimePersistence(ctx, nil), other) != nil { t.Fatal("explicit unbound owner inherited fallback") }
}
func TestRuntimeOwnedFilePreservesModeAndRejectsExternalEdit(t *testing.T) {
 if runtime.GOOS == "windows" { t.Skip("Unix permission-mode assertion") }
 path := filepath.Join(t.TempDir(), "config.json")
 original := []byte(`{"route":{}}`)
 if err := os.WriteFile(path, original, 0640); err != nil { t.Fatal(err) }
 if err := os.Chmod(path, 0640); err != nil { t.Fatal(err) }
 persist, err := NewRuntimeFilePersistence(path, original)
 if err != nil { t.Fatal(err) }
 next := []byte(`{"route":{"final":"direct"}}`)
 identity := box.RuntimeIdentity{Incarnation:"one"}
 if err := persist(identity, next); err != nil { t.Fatal(err) }
 got, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
 info, err := os.Stat(path); if err != nil { t.Fatal(err) }
 if !bytes.Equal(got,next) || info.Mode().Perm()!=0640 { t.Fatal("replacement changed content or mode") }
 external := []byte(`{"external":true}`)
 if err := os.WriteFile(path, external, 0640); err != nil { t.Fatal(err) }
 if err := persist(identity, original); err == nil { t.Fatal("external edit overwritten") }
 got, _ = os.ReadFile(path); if !bytes.Equal(got,external) { t.Fatal("conflicting source changed") }
}
func TestRuntimePersistencePostRenameFailureRetainsNewExpectedBytes(t *testing.T) {
 calls:=0
 p:=&runtimeFilePersistence{expected:[]byte("before"),write:func(_ string, expected, content []byte)(bool,error){
  calls++
  if calls==1 { if string(expected)!="before" { t.Fatal("wrong initial content") }; return true,errors.New("directory sync failed") }
  if string(expected)!="after" { t.Fatal("rename failure lost physical state") }
  return true,nil
 }}
 identity:=box.RuntimeIdentity{Incarnation:"one"}
 if p.persist(identity,[]byte("after"))==nil { t.Fatal("post-rename failure certified durable") }
 if err:=p.persist(identity,[]byte("retry"));err!=nil { t.Fatal(err) }
 if p.persist(box.RuntimeIdentity{Incarnation:"two"},nil)==nil { t.Fatal("binding crossed incarnations") }
}
func TestRuntimePersistenceRejectsSymlinkSource(t *testing.T) {
 if runtime.GOOS=="windows" { t.Skip("symlink fixture requires local symlink privilege") }
 directory:=t.TempDir();target:=filepath.Join(directory,"target");link:=filepath.Join(directory,"link")
 if err:=os.WriteFile(target,[]byte("before"),0600);err!=nil { t.Fatal(err) }
 if err:=os.Symlink(target,link);err!=nil { t.Fatal(err) }
 persist,err:=NewRuntimeFilePersistence(link,[]byte("before"));if err!=nil { t.Fatal(err) }
 if persist(box.RuntimeIdentity{Incarnation:"one"},[]byte("after"))==nil { t.Fatal("symlink source accepted") }
 got,_:=os.ReadFile(target);if string(got)!="before" { t.Fatal("symlink target changed") }
}

func TestRuntimeReplacementFlushFailureIsPending(t *testing.T) {
 failure := errors.New("native flush failed")
 var replaced bool
 committed, err := replaceAndFlushRuntimeFile("temp", "owned", func(source, destination string) error {
  if source!="temp" || destination!="owned" { t.Fatal("wrong replacement") }
  replaced=true; return nil
 }, func(path string) error {
  if !replaced || path!="owned" { t.Fatal("flush preceded replacement") }
  return failure
 })
 if !committed || !errors.Is(err,failure) { t.Fatal("post-replacement failure lost") }
}
func TestRuntimeReplacementFailureDoesNotFlush(t *testing.T) {
 failure:=errors.New("replace failed")
 committed,err:=replaceAndFlushRuntimeFile("temp","owned",func(string,string)error{return failure},func(string)error{t.Fatal("flushed failed replacement");return nil})
 if committed || !errors.Is(err,failure) { t.Fatal("replacement failure certified") }
}
