//go:build linux || darwin || (windows && (amd64 || 386))

package bridge

import "testing"

type blockedRuntimeReturn struct{entered,proceed chan struct{};packets int}
func(r *blockedRuntimeReturn)ReturnHeadroom()int{close(r.entered);<-r.proceed;return 0}
func(r *blockedRuntimeReturn)ReturnPackets(packets [][]byte)[][]byte{r.packets++;return packets}

func TestBridgeDetachJoinsCopiedReturnSnapshot(t *testing.T){
	backend:=&backendBase{}
	callback:=&blockedRuntimeReturn{entered:make(chan struct{}),proceed:make(chan struct{})}
	if err:=backend.AttachReturn(callback);err!=nil{t.Fatal(err)}
	delivered:=make(chan struct{});go func(){backend.deliverReturn([]byte{1});close(delivered)}();<-callback.entered
	backend.returnAccess.Lock();copied:=backend.returnPaths[0];backend.returnAccess.Unlock()
	// Seal explicitly to make the callback-admission boundary deterministic.
	_ = copied.fence.Close()
	detached:=make(chan error,1);go func(){detached<-backend.DetachReturn(callback)}()
	select{case <-detached:t.Fatal("detach released an in-flight copied callback");default:}
	close(callback.proceed);<-delivered
	if err:=<-detached;err!=nil{t.Fatal(err)}
	if callback.packets!=0{t.Fatal("copied return snapshot reached original after detach seal")}
}
