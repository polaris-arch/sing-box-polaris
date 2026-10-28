package fswatch

import (
 "errors"
 "testing"
)

type failedStartWatcher struct{at,adds,closes int;addErr,closeErr error}
func(w *failedStartWatcher)Add(string)error{w.adds++;if w.adds==w.at{return w.addErr};return nil}
func(w *failedStartWatcher)Close()error{w.closes++;return w.closeErr}
func TestFailedAddClosesUnpublishedWatcher(t *testing.T){
 cause:=errors.New("injected add failure")
 for _,at:=range []int{1,2,3}{
  watcher:=&failedStartWatcher{at:at,addErr:cause}
  err:=addWatchTargets(watcher,[]string{"first","middle","last"})
  if !errors.Is(err,cause)||watcher.closes!=1||watcher.adds!=at{t.Fatalf("failure %d did not unwind once: %+v / %v",at,watcher,err)}
 }
}
func TestSuccessfulAddTransfersWithoutClosing(t *testing.T){
 watcher:=&failedStartWatcher{}
 if err:=addWatchTargets(watcher,[]string{"one","two"});err!=nil{t.Fatal(err)}
 if watcher.adds!=2||watcher.closes!=0{t.Fatal("successful allocation not transferred")}
}
func TestFailedAddPreservesCleanupFailure(t *testing.T){
 cause,cleanup:=errors.New("add failure"),errors.New("close failure")
 watcher:=&failedStartWatcher{at:1,addErr:cause,closeErr:cleanup}
 err:=addWatchTargets(watcher,[]string{"one"})
 var marker interface{RuntimeCleanupIncomplete()bool}
 if !errors.Is(err,cause)||!errors.Is(err,cleanup)||!errors.As(err,&marker)||!marker.RuntimeCleanupIncomplete(){t.Fatal("uncertain cleanup was certified successful")}
 if watcher.closes!=1{t.Fatal("cleanup repeated")}
}
