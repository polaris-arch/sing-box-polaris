package listener

import "errors"

// PreparedListenerPublication holds only the already staged admission guards.
// Prepare performs validation and allocation; Publish only opens prevalidated
// gates after the graph has become current. The coordinator must call Finish
// outside the graph admission guard to release transaction reservations.
type PreparedListenerPublication struct {
 transaction *ListenerSetTransaction
 gates []chan struct{}
 published bool
 finished bool
}

func (t *ListenerSetTransaction) PreparePublication() (*PreparedListenerPublication, error) {
 if err := t.begin(); err != nil { return nil, err }
 if !t.staged { t.end(); return nil, errors.New("listener set not staged") }
 p := &PreparedListenerPublication{transaction:t, gates:make([]chan struct{},len(t.next))}
 locked := 0
 for index, candidate := range t.next {
  r := candidate.runtime
  r.mu.Lock(); r.gateway.mu.Lock(); locked++
  g := r.gateway
  if r.phase != "armed" || r.controlOpen || r.controlEnding || g.sealed || g.pausing != 0 || g.admission == nil || g.source == nil {
   for i:=locked-1;i>=0;i-- { old:=t.next[i].runtime;old.gateway.mu.Unlock();old.mu.Unlock() }
   t.end();return nil,errors.New("listener publication gate changed")
  }
  p.gates[index]=make(chan struct{})
 }
 return p,nil
}

// Publish is called once by the same serialized transaction owner. It performs
// no sockets, callbacks, allocations or new mutex acquisitions.
func(p *PreparedListenerPublication)Publish(){
 if p==nil||p.finished||p.published{return}
 t:=p.transaction
 for index,candidate:=range t.next {
  r:=candidate.runtime;g:=r.gateway
  if !g.open { g.open=true;close(g.changed);g.changed=p.gates[index] }
  r.phase="active"
 }
 p.published=true
 for i:=len(t.next)-1;i>=0;i-- { r:=t.next[i].runtime;r.gateway.mu.Unlock();r.mu.Unlock() }
}

func(p *PreparedListenerPublication)Finish(){
 if p==nil||p.finished{return}
 p.finished=true;t:=p.transaction
 if !p.published {
  for i:=len(t.next)-1;i>=0;i-- { r:=t.next[i].runtime;r.gateway.mu.Unlock();r.mu.Unlock() }
  t.end();return
 }
 t.mu.Lock();t.finished=true;t.busy=false;t.mu.Unlock()
 t.releaseReservations()
}
