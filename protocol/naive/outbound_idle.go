//go:build with_naive_outbound

package naive

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"

	"github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"
)

type naiveClientIncarnation struct {
	client  *cronet.NaiveClient
	runtime *outboundRuntime
}

// The outbound remains registered while each client and its physical carriers
// are owned and closed together. At most one such client is live in the slot.
type naiveClientSlot struct {
	mu        sync.Mutex
	owner     *outboundRuntime
	options   cronet.NaiveClientOptions
	current   *naiveClientIncarnation
	borrowers int
	keep      bool
	pinned    bool
	closed    bool
	retiring  chan struct{}
	closeErr  error
}

func (s *naiveClientSlot) newIncarnation() (*naiveClientIncarnation, error) {
	instance := &naiveClientIncarnation{runtime: newOutboundRuntime(s.options.Context)}
	instance.runtime.begin = s.owner.begin
	options := instance.runtime.guardClientOptions(s.options)
	options.OnIdle = func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.current == instance {
			s.retireIdleLocked(false)
		}
	}
	client, err := cronet.NewNaiveClient(options)
	if err != nil {
		instance.runtime.cancel()
		return nil, err
	}
	instance.client = client
	instance.runtime.client = client
	return instance, nil
}

func (s *naiveClientSlot) retireIdleLocked(explicit bool) <-chan struct{} {
	if s.retiring != nil {
		return s.retiring
	}
	if (s.keep && !explicit) || s.pinned || s.closed || s.closeErr != nil || s.borrowers != 0 ||
		s.current == nil || !s.current.client.TrySealIdle() {
		return nil
	}
	instance := s.current
	done := make(chan struct{})
	s.retiring = done
	// The last native callback can claim the retirement. The actual close then
	// runs on a Go worker which can join that callback and the carrier workers.
	go func() {
		err := instance.runtime.close()
		s.mu.Lock()
		defer s.mu.Unlock()
		if err == nil {
			s.current = nil
		}
		s.closeErr = err
		s.retiring = nil
		close(done)
	}()
	return done
}

func (s *naiveClientSlot) setKeep(keep bool) {
	s.mu.Lock()
	s.keep = keep
	var done <-chan struct{}
	if !keep {
		done = s.retireIdleLocked(false)
	}
	s.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (s *naiveClientSlot) closeIdle() {
	s.mu.Lock()
	// Pause and memory reclamation can release even a referenced idle client.
	done := s.retireIdleLocked(true)
	s.mu.Unlock()
	if done != nil {
		<-done
	}
}

// When create is false, borrow only a warm client. Waiting for an already
// admitted retirement never turns a warm probe into a new persistent client.
func (s *naiveClientSlot) acquire(ctx context.Context, create bool) (*naiveClientIncarnation, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.mu.Lock()
		if s.closed || s.closeErr != nil {
			err := s.closeErr
			s.mu.Unlock()
			if err != nil {
				return nil, err
			}
			return nil, net.ErrClosed
		}
		if done := s.retiring; done != nil {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-done:
				continue
			}
		}
		instance := s.current
		if !create && (instance == nil || instance.client.IsDormant()) {
			s.mu.Unlock()
			return nil, nil
		}
		if instance == nil {
			var err error
			instance, err = s.newIncarnation()
			if err == nil {
				err = instance.client.StartOnDemand()
				if err == nil {
					s.current = instance
				} else {
					err = errors.Join(err, instance.runtime.close())
				}
			}
			if err != nil {
				s.mu.Unlock()
				return nil, err
			}
		}
		s.borrowers++
		s.mu.Unlock()
		return instance, nil
	}
}

func (s *naiveClientSlot) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.borrowers--
	s.retireIdleLocked(false)
}

func (s *naiveClientSlot) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	instance, err := s.acquire(ctx, true)
	if err != nil {
		return nil, err
	}
	defer s.release()
	return instance.client.DialEarly(ctx, destination)
}

func (s *naiveClientSlot) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (s *naiveClientSlot) closeAllConnections() {
	s.mu.Lock()
	instance := s.current
	if instance == nil || s.retiring != nil || s.closed || s.closeErr != nil {
		s.mu.Unlock()
		return
	}
	s.borrowers++
	s.mu.Unlock()
	defer s.release()
	instance.client.CloseAllConnections()
}

func (s *naiveClientSlot) rawClient() *cronet.NaiveClient {
	instance, err := s.acquire(s.options.Context, true)
	if err != nil {
		return nil
	}
	defer s.release()
	s.mu.Lock()
	// Standalone callers may retain a raw Engine borrowed from this client.
	s.pinned = true
	s.mu.Unlock()
	return instance.client
}

func (s *naiveClientSlot) Close() error {
	s.mu.Lock()
	s.closed = true
	if done := s.retiring; done != nil {
		s.mu.Unlock()
		<-done
		s.mu.Lock()
	}
	instance, err := s.current, s.closeErr
	s.mu.Unlock()
	if err != nil || instance == nil {
		return err
	}
	return instance.runtime.close()
}
