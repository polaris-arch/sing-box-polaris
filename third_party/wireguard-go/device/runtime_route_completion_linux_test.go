//go:build linux

package device

import (
 "runtime"
 "testing"

 "github.com/sagernet/wireguard-go/rwcancel"
 "golang.org/x/sys/unix"
)

func TestRuntimeRouteCancellationWithContinuouslyReadyInput(t *testing.T) {
 sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
 if err != nil { t.Fatal(err) }
 defer unix.Close(sockets[1])
 cancel, err := rwcancel.NewRWCancel(sockets[0])
 if err != nil { unix.Close(sockets[0]); t.Fatal(err) }
 device := new(Device)
 device.net.routeStopping.Add(1)
 stop, writerDone := make(chan struct{}), make(chan struct{})
 go func() {
  defer close(writerDone)
  for {
   select { case <-stop: return; default: }
   // Invalid short datagrams exercise the receive loop without peer state.
   _ = unix.Sendmsg(sockets[1], []byte{0}, nil, nil, unix.MSG_DONTWAIT)
   runtime.Gosched()
  }
 }()
 defer func() { close(stop); <-writerDone }()
 go device.routineRouteListener(nil, sockets[0], cancel)
 if err := cancel.Cancel(); err != nil { t.Fatal(err) }
 done := make(chan struct{})
 go func() { device.net.routeStopping.Wait(); close(done) }()
 runtimeAwait(t, done)
}
