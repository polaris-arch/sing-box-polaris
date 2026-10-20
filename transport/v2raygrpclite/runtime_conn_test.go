package v2raygrpclite

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

type runtimeCloseBarrier struct{entered,finish chan struct{};once sync.Once;calls atomic.Int32}
func(b *runtimeCloseBarrier)Read([]byte)(int,error){return 0,io.EOF}
func(b *runtimeCloseBarrier)Write(p []byte)(int,error){return len(p),nil}
func(b *runtimeCloseBarrier)Close()error{b.calls.Add(1);b.once.Do(func(){close(b.entered)});<-b.finish;return nil}

func TestLateGunConnCloseJoinsSetupAndBodyClose(t *testing.T){
	writer:=&runtimeCloseBarrier{entered:make(chan struct{}),finish:make(chan struct{})};close(writer.finish)
	body:=&runtimeCloseBarrier{entered:make(chan struct{}),finish:make(chan struct{})}
	conn:=newLateGunConn(writer,func(){})
	closed:=make(chan error,1);go func(){closed<-conn.Close()}();<-writer.entered
	select{case <-closed:t.Fatal("close escaped before response publication");default:}
	conn.setup(body,nil);<-body.entered
	select{case <-closed:t.Fatal("close escaped before actual body close");default:}
	close(body.finish);if err:=<-closed;err!=nil{t.Fatal(err)}
	if err:=conn.Close();err!=nil{t.Fatal(err)};if body.calls.Load()!=1{t.Fatal("body closed more than once")}
}
