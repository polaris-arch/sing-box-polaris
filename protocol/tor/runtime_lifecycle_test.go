package tor

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/cretz/bine/process"
)

type torTestProcess struct{entered,proceed chan struct{};waits atomic.Int32;panicWait bool}
func(*torTestProcess)Start()error{return nil}
func(p *torTestProcess)Wait()error{p.waits.Add(1);close(p.entered);<-p.proceed;if p.panicWait{panic("native wait")};return errors.New("exit status after cancellation")}
func(*torTestProcess)EmbeddedControlConn()(net.Conn,error){return nil,process.ErrControlConnUnsupported}
type torTestCreator struct{process *torTestProcess}
func(c torTestCreator)New(context.Context,...string)(process.Process,error){return c.process,nil}

func TestTorOwnerJoinsSingleActualWait(t *testing.T){
	for _,panicWait:=range []bool{false,true}{
		raw:=&torTestProcess{entered:make(chan struct{}),proceed:make(chan struct{}),panicWait:panicWait}
		owner:=&runtimeProcessCreator{creator:torTestCreator{raw}}
		p,err:=owner.New(context.Background());if err!=nil{t.Fatal(err)}
		if err:=p.Start();err!=nil{t.Fatal(err)};<-raw.entered
		observer:=make(chan error,1);go func(){observer<-p.Wait()}()
		closed:=make(chan error,1);go func(){closed<-owner.closeAndWait()}()
		select{case <-closed:t.Fatal("process completion inferred before actual Wait returned");default:}
		close(raw.proceed);<-observer
		err=<-closed
		if panicWait&&err==nil{t.Fatal("unknown native completion lost")}
		if !panicWait&&err!=nil{t.Fatal("actual observed process exit was mistaken for uncertainty")}
		if raw.waits.Load()!=1{t.Fatal("multiple actual process Wait calls")}
	}
}
