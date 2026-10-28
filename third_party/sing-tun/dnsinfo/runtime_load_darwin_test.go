//go:build cgo

package dnsinfo

import (
 "sync"
 "testing"
)

// Concurrent smoke coverage for initial symbol publication. This is not a
// substitute for Darwin native/race validation of the C implementation.
func TestConcurrentRuntimeConfigurationCopies(t *testing.T) {
 var workers sync.WaitGroup
 start:=make(chan struct{})
 for i:=0;i<16;i++{workers.Add(1);go func(){defer workers.Done();<-start;for n:=0;n<8;n++{_ = Copy()}}()}
 close(start)
 workers.Wait()
}
