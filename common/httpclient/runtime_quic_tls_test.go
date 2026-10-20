//go:build with_quic

package httpclient

import (
	"crypto/tls"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
)

func TestRuntimeQUICTLSProviderCallbackIsIndependentOfRunContext(t *testing.T){
	entered,finish:=make(chan struct{}),make(chan struct{});var calls atomic.Int32
	original:=&tls.Config{Time:func()time.Time{calls.Add(1);close(entered);<-finish;return time.Unix(123,0)}}
	fence:=outbound.NewRuntimeIOFence(nil);guarded:=guardRuntimeQUICTLS(original,fence)
	returned:=make(chan struct{});go func(){defer close(returned);_ = guarded.Time()}();<-entered
	if err:=fence.Close();err!=nil&&!errors.Is(err,outbound.ErrRuntimeClosePending){t.Fatal(err)}
	closed:=make(chan error,1);go func(){closed<-fence.Wait()}()
	select{case <-closed:t.Fatal("provider callback tail was not joined");default:}
	close(finish);<-returned;if err:=<-closed;err!=nil{t.Fatal(err)}
	_ = guarded.Time();if calls.Load()!=1{t.Fatal("late provider callback reached retired owner")}
	if guarded.VerifyConnection!=nil||guarded.GetConfigForClient!=nil||guarded.ClientSessionCache!=nil{t.Fatal("nil capabilities changed ChromeParrot validation")}
	if original.Time==nil{t.Fatal("caller config mutated")}
}
