package fswatch

import (
 "errors"
 "os"
 "path/filepath"
 "testing"
 "sync"
 "time"

 "github.com/fsnotify/fsnotify"
)

func TestDirectoryEventMatchingIsImmediateAndBoundaryExact(t *testing.T){
 root:=filepath.Join(string(filepath.Separator),"certificates")
 watcher:=&Watcher{watchDirectory:[]string{root}}
 for _,op:=range []fsnotify.Op{fsnotify.Create,fsnotify.Write,fsnotify.Remove,fsnotify.Rename}{
  for _,path:=range []string{root,filepath.Join(root,"root.pem")} {
   if !watcher.matchesDirectoryEvent(fsnotify.Event{Name:path,Op:op}){t.Fatalf("directory event omitted: %q %v",path,op)}
  }
  for _,path:=range []string{root+"-unrelated",filepath.Join(root+"-unrelated","root.pem"),filepath.Join(root,"subdirectory","root.pem")} {
   if watcher.matchesDirectoryEvent(fsnotify.Event{Name:path,Op:op}){t.Fatalf("unrelated/nonrecursive event accepted: %q %v",path,op)}
  }
 }
 if watcher.matchesDirectoryEvent(fsnotify.Event{Name:filepath.Join(root,"root.pem"),Op:fsnotify.Chmod}){t.Fatal("unrequested metadata event accepted")}
}
func TestDirectoryOnlyConfigurationKeepsRequiredParent(t *testing.T){
 directory:=filepath.Join(string(filepath.Separator),"trust","roots")
 watcher,err:=NewWatcher(Options{Directory:[]string{directory,directory},Callback:func(string){}})
 if err!=nil{t.Fatal(err)}
 if len(watcher.watchDirectory)!=1||len(watcher.watchTarget)!=1||watcher.watchTarget[0]!=filepath.Dir(directory){t.Fatal("directory targets not exact and deduplicated")}
}
type directoryStartFixture struct{adds,closes int;errors map[int]error;closeErr error}
func(f *directoryStartFixture)Add(string)error{f.adds++;return f.errors[f.adds]}
func(f *directoryStartFixture)Close()error{f.closes++;return f.closeErr}
func TestMissingDirectoryDoesNotDiscardRequiredParentWatcher(t *testing.T){
 fixture:=&directoryStartFixture{errors:map[int]error{1:os.ErrNotExist}}
 if err:=addWatchDirectories(fixture,[]string{"missing","present"});err!=nil{t.Fatal(err)}
 if fixture.adds!=2||fixture.closes!=0{t.Fatal("missing directory destroyed parent watch")}
}
func TestDirectoryAddFailureRetainsNativeCloseUncertainty(t *testing.T){
 failure,cleanup:=errors.New("directory permission failure"),errors.New("native close failure")
 fixture:=&directoryStartFixture{errors:map[int]error{2:failure},closeErr:cleanup}
 err:=addWatchDirectories(fixture,[]string{"first","failed","never"})
 var marker interface{RuntimeCleanupIncomplete()bool}
 if fixture.adds!=2||fixture.closes!=1||!errors.Is(err,failure)||!errors.Is(err,cleanup)||!errors.As(err,&marker)||!marker.RuntimeCleanupIncomplete(){t.Fatal("partial directory watcher failure lost cleanup ownership",err)}
}

func flushDirectoryFixture(t *testing.T,w *Watcher,path string){
 t.Helper();w.stateAccess.Lock();pending,ok:=w.timerMap[path];w.stateAccess.Unlock()
 if !ok{t.Fatal("directory callback was not scheduled")};pending.timer.Stop();w.fireCallback(path,pending.generation)
}
func TestDirectoryDeletionAndRecreationReattachesExactBackend(t *testing.T){
 directory:=filepath.Join(string(filepath.Separator),"trust","roots")
 calls,adds:=0,0
 w,err:=NewWatcher(Options{Directory:[]string{directory},WaitTimeout:time.Hour,Callback:func(path string){if path!=directory{t.Error("wrong directory callback",path)};calls++}});if err!=nil{t.Fatal(err)};defer w.Close()
 add:=func(path string)error{if path!=directory{t.Error("unrelated directory reattached",path)};adds++;return nil}
 if !w.handleDirectoryEvent(fsnotify.Event{Name:directory,Op:fsnotify.Remove},add){t.Fatal("directory removal not handled")}
 flushDirectoryFixture(t,w,directory)
 if adds!=0||calls!=1{t.Fatal("removal reattached backend or lost reload")}
 if !w.handleDirectoryEvent(fsnotify.Event{Name:directory,Op:fsnotify.Create},add){t.Fatal("directory recreation not handled")}
 flushDirectoryFixture(t,w,directory)
 if adds!=1||calls!=2{t.Fatal("recreation did not reattach and reload exactly once")}
}
func TestCloseRacingDirectoryReAddCannotScheduleLateCallback(t *testing.T){
 directory:=filepath.Join(string(filepath.Separator),"trust","roots")
 callbacks:=make(chan struct{},1)
 w,err:=NewWatcher(Options{Directory:[]string{directory},WaitTimeout:time.Hour,Callback:func(string){callbacks<-struct{}{}}});if err!=nil{t.Fatal(err)}
 entered,finish,done:=make(chan struct{}),make(chan struct{}),make(chan struct{})
 var releaseOnce sync.Once
 releaseFinish:=func(){releaseOnce.Do(func(){close(finish)})}
 t.Cleanup(func(){
  releaseFinish()
  if err:=w.Close();err!=nil{t.Error(err)}
  select{case <-done:case <-time.After(5*time.Second):t.Error("dynamic add fixture did not unwind")}
 })
 go func(){w.handleDirectoryEvent(fsnotify.Event{Name:directory,Op:fsnotify.Create},func(string)error{close(entered);<-finish;return nil});close(done)}()
 select{case <-entered:case <-time.After(5*time.Second):t.Fatal("dynamic add not entered")}
 if err:=w.Close();err!=nil{t.Fatal(err)}
 releaseFinish()
 select{case <-done:case <-time.After(5*time.Second):t.Fatal("dynamic add did not return")}
 w.stateAccess.Lock();pending:=len(w.timerMap);w.stateAccess.Unlock()
 if pending!=0{t.Fatal("close race scheduled a late directory callback")}
 select{case <-callbacks:t.Fatal("late directory callback executed");default:}
 if err:=w.addDirectoryIfOpen(directory,func(string)error{t.Fatal("closed watcher re-added native directory");return nil});!errors.Is(err,os.ErrClosed){t.Fatal("closed add did not fail",err)}
}
