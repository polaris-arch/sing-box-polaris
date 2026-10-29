package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type taildropProviderFixture struct {
	adapter.Endpoint
	adapter.TailscaleEndpoint
	send  func(context.Context, string, string, int64, io.Reader, func(int64)) error
	calls atomic.Int32
}

func (*taildropProviderFixture) Type() string { return C.TypeTailscale }
func (*taildropProviderFixture) Tag() string  { return "taildrop-fixture" }
func (p *taildropProviderFixture) SendTaildropFile(ctx context.Context, peer, name string, size int64, content io.Reader, progress func(int64)) error {
	p.calls.Add(1)
	return p.send(ctx, peer, name, size, content, progress)
}

type taildropEndpointManagerFixture struct {
	adapter.EndpointManager
	endpoint adapter.Endpoint
}

func (m *taildropEndpointManagerFixture) Endpoints() []adapter.Endpoint {
	return []adapter.Endpoint{m.endpoint}
}
func (m *taildropEndpointManagerFixture) Get(tag string) (adapter.Endpoint, bool) {
	return m.endpoint, m.endpoint != nil && tag == m.endpoint.Tag()
}
func taildropStartedFixture(t *testing.T, p *taildropProviderFixture) *StartedService {
	t.Helper()
	s := admissionTestService(t)
	s.instance = &Instance{ctx: context.Background(), endpointManager: &taildropEndpointManagerFixture{endpoint: p}}
	s.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTED}
	return s
}
func taildropClientFixture(t *testing.T, s *StartedService) StartedServiceClient {
	t.Helper()
	listener := bufconn.Listen(64 * 1024)
	server := NewServer(s, "taildrop-test-secret")
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///taildrop-owned-fixture",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		server.Stop()
		_ = listener.Close()
		<-done
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		stopped := make(chan struct{})
		go func() { server.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			server.Stop()
			select {
			case <-stopped:
			case <-time.After(2 * time.Second):
				t.Error("owned RPC handlers did not join")
			}
		}
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("owned gRPC server did not join")
		}
	})
	return NewStartedServiceClient(connection)
}
func taildropCallContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer taildrop-test-secret"), cancel
}
func taildropStart(files ...*TaildropOutgoingFile) *TaildropSendClientMessage {
	return &TaildropSendClientMessage{Message: &TaildropSendClientMessage_Start{Start: &TaildropSendStart{EndpointTag: "taildrop-fixture", PeerStableID: "peer", Files: files}}}
}
func taildropChunk(data []byte) *TaildropSendClientMessage {
	return &TaildropSendClientMessage{Message: &TaildropSendClientMessage_Chunk{Chunk: &TaildropFileChunk{Data: data}}}
}
func taildropFileDone() *TaildropSendClientMessage {
	return &TaildropSendClientMessage{Message: &TaildropSendClientMessage_FileDone{FileDone: &TaildropFileDone{}}}
}
func taildropAwait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("owned Taildrop operation did not reach its barrier")
	}
}

// This is the actual StartedService handler and authenticated gRPC transport.
// The provider requires a source prefix before it can produce any response.
func TestTaildropInitialHeadersPrecedeResumeInputWithoutFabricatedProgress(t *testing.T) {
	entered, read := make(chan struct{}), make(chan struct{})
	payload := []byte("same-name retained prefix and the remaining source bytes")
	observed := make(chan []byte, 1)
	p := &taildropProviderFixture{send: func(ctx context.Context, peer, name string, size int64, source io.Reader, progress func(int64)) error {
		close(entered)
		prefix := make([]byte, 17)
		if _, err := io.ReadFull(source, prefix); err != nil {
			return err
		}
		close(read)
		rest, err := io.ReadAll(source)
		if err != nil {
			return err
		}
		observed <- append(prefix, rest...)
		progress(size)
		return nil
	}}
	client := taildropClientFixture(t, taildropStartedFixture(t, p))
	ctx, cancel := taildropCallContext(t)
	defer cancel()
	stream, err := client.SendTaildropFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.Send(taildropStart(&TaildropOutgoingFile{Name: "same.bin", Size: int64(len(payload))})); err != nil {
		t.Fatal(err)
	}
	// Old ordering blocks here: no Chunk is available to the provider until Header returns.
	if _, err = stream.Header(); err != nil {
		t.Fatal(err)
	}
	taildropAwait(t, entered)
	select {
	case <-read:
		t.Fatal("resume consumed bytes before the client supplied them")
	default:
	}
	if err = stream.Send(taildropChunk(payload)); err != nil {
		t.Fatal(err)
	}
	if err = stream.Send(taildropFileDone()); err != nil {
		t.Fatal(err)
	}
	if err = stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	completed := 0
	for {
		message, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			t.Fatal(recvErr)
		}
		if message.GetReceivedBytes() != 0 {
			t.Fatal("sub-ACK payload fabricated received bytes")
		}
		if progress := message.GetProgress(); progress != nil {
			if progress.SentBytes != int64(len(payload)) {
				t.Fatal(progress)
			}
			if progress.FileCompleted {
				completed++
			}
		}
	}
	if completed != 1 {
		t.Fatal("missing unique completion", completed)
	}
	select {
	case actual := <-observed:
		if !bytes.Equal(actual, payload) || sha256.Sum256(actual) != sha256.Sum256(payload) {
			t.Fatal("source bytes changed")
		}
	default:
		t.Fatal("provider did not finish")
	}
}

func TestTaildropLargeMultifileAndEagerLegacyClientsKeepCumulativeACKs(t *testing.T) {
	for _, eager := range []bool{false, true} {
		t.Run(map[bool]string{false: "headers-first", true: "eager-cli-libbox"}[eager], func(t *testing.T) {
			files := [][]byte{bytes.Repeat([]byte{3}, TaildropReceiveAckInterval+70001), bytes.Repeat([]byte{7}, TaildropReceiveAckInterval+123)}
			captured := make(chan []byte, 2)
			p := &taildropProviderFixture{send: func(_ context.Context, _, _ string, _ int64, r io.Reader, progress func(int64)) error {
				b, e := io.ReadAll(r)
				if e == nil {
					captured <- b
					progress(int64(len(b)))
				}
				return e
			}}
			client := taildropClientFixture(t, taildropStartedFixture(t, p))
			ctx, cancel := taildropCallContext(t)
			defer cancel()
			stream, err := client.SendTaildropFiles(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = stream.Send(taildropStart(&TaildropOutgoingFile{Name: "first.bin", Size: int64(len(files[0]))}, &TaildropOutgoingFile{Name: "second.bin", Size: int64(len(files[1]))})); err != nil {
				t.Fatal(err)
			}
			if !eager {
				if _, err = stream.Header(); err != nil {
					t.Fatal(err)
				}
			}
			sent := make(chan error, 1)
			sendTerminal := make(chan struct{})
			go func() {
				defer close(sendTerminal)
				for _, b := range files {
					for len(b) > 0 {
						n := min(len(b), TaildropChunkSize)
						if e := stream.Send(taildropChunk(b[:n])); e != nil {
							sent <- e
							return
						}
						b = b[n:]
					}
					if e := stream.Send(taildropFileDone()); e != nil {
						sent <- e
						return
					}
				}
				sent <- stream.CloseSend()
			}()
			defer func() { cancel(); taildropAwait(t, sendTerminal) }()
			var ack int64
			completed := 0
			for {
				m, e := stream.Recv()
				if e == io.EOF {
					break
				}
				if e != nil {
					cancel()
					<-sent
					t.Fatal(e)
				}
				if next := m.GetReceivedBytes(); next != 0 {
					if next <= ack || next-ack < TaildropReceiveAckInterval {
						t.Fatal("invalid cumulative ACK", ack, next)
					}
					ack = next
				}
				if pr := m.GetProgress(); pr != nil && pr.FileCompleted {
					if completed >= len(files) || pr.FileIndex != int32(completed) || pr.SentBytes != int64(len(files[completed])) {
						t.Fatal(pr)
					}
					completed++
				}
			}
			if err = <-sent; err != nil {
				t.Fatal(err)
			}
			total := int64(len(files[0]) + len(files[1]))
			if completed != 2 || ack < TaildropReceiveAckInterval || total-ack >= TaildropReceiveAckInterval {
				t.Fatal("lost ACK/completion", ack, completed)
			}
			for _, want := range files {
				if got := <-captured; !bytes.Equal(got, want) {
					t.Fatal("file boundary or SHA changed")
				}
			}
		})
	}
}

type taildropDirectStream struct {
	grpc.ServerStream
	ctx       context.Context
	frames    []*TaildropSendClientMessage
	headerErr error
	headers   int
	sent      []*TaildropSendServerMessage
}

func (s *taildropDirectStream) Context() context.Context { return s.ctx }
func (s *taildropDirectStream) Recv() (*TaildropSendClientMessage, error) {
	if len(s.frames) == 0 {
		return nil, io.EOF
	}
	m := s.frames[0]
	s.frames = s.frames[1:]
	return m, nil
}
func (s *taildropDirectStream) SendHeader(metadata.MD) error { s.headers++; return s.headerErr }
func (s *taildropDirectStream) Send(m *TaildropSendServerMessage) error {
	s.sent = append(s.sent, m)
	return nil
}

func TestTaildropHeaderFailureAndAdmissionErrorsNeverInvokeProvider(t *testing.T) {
	p := &taildropProviderFixture{send: func(context.Context, string, string, int64, io.Reader, func(int64)) error {
		return errors.New("provider reached rejected admission")
	}}
	s := taildropStartedFixture(t, p)
	failure := errors.New("owned header write failed")
	stream := &taildropDirectStream{ctx: context.Background(), frames: []*TaildropSendClientMessage{taildropStart(&TaildropOutgoingFile{Name: "a", Size: 1})}, headerErr: failure}
	if err := s.SendTaildropFiles(stream); !errors.Is(err, failure) || stream.headers != 1 || len(stream.sent) != 0 {
		t.Fatal("header failure changed", err, stream)
	}
	for _, frames := range [][]*TaildropSendClientMessage{{taildropChunk(nil)}, {taildropStart()}, {taildropStart(&TaildropOutgoingFile{Name: "a", Size: 1})}} {
		if len(frames) == 1 && frames[0].GetStart() != nil && len(frames[0].GetStart().Files) > 0 {
			frames[0].GetStart().EndpointTag = "missing"
		}
		rejected := &taildropDirectStream{ctx: context.Background(), frames: frames}
		if err := s.SendTaildropFiles(rejected); err == nil || rejected.headers != 0 || len(rejected.sent) != 0 {
			t.Fatal("rejected request established transport", err)
		}
	}
	s.instance.closeStarted.Store(true)
	rejected := &taildropDirectStream{ctx: context.Background(), frames: []*TaildropSendClientMessage{taildropStart(&TaildropOutgoingFile{Name: "a", Size: 1})}}
	if err := s.SendTaildropFiles(rejected); status.Code(err) != codes.Unavailable || rejected.headers != 0 {
		t.Fatal("closing instance admitted", err)
	}
	if p.calls.Load() != 0 {
		t.Fatal("rejection invoked provider")
	}
}

func TestTaildropActualAuthRejectsBeforeProviderAndCancelJoinsBlockedRead(t *testing.T) {
	entered, returned := make(chan struct{}), make(chan struct{})
	p := &taildropProviderFixture{send: func(_ context.Context, _, _ string, _ int64, r io.Reader, _ func(int64)) error {
		close(entered)
		defer close(returned)
		_, err := io.ReadFull(r, make([]byte, 17))
		return err
	}}
	client := taildropClientFixture(t, taildropStartedFixture(t, p))
	bad, cancelBad := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelBad()
	rejected, err := client.SendTaildropFiles(bad)
	if err != nil {
		t.Fatal(err)
	}
	_ = rejected.Send(taildropStart(&TaildropOutgoingFile{Name: "a", Size: 17}))
	if _, err = rejected.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
	if p.calls.Load() != 0 {
		t.Fatal("unauthenticated provider call")
	}
	ctx, cancel := taildropCallContext(t)
	stream, err := client.SendTaildropFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.Send(taildropStart(&TaildropOutgoingFile{Name: "a", Size: 17})); err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Header(); err != nil {
		t.Fatal(err)
	}
	taildropAwait(t, entered)
	cancel()
	_, err = stream.Recv()
	if status.Code(err) != codes.Canceled {
		t.Fatal(err)
	}
	taildropAwait(t, returned)
}

func TestTaildropDeclaredSizeEOFAndMessageOrderRemainStrict(t *testing.T) {
	for _, test := range []struct {
		name   string
		size   int64
		frames []*TaildropSendClientMessage
		want   codes.Code
	}{
		{"short", 5, []*TaildropSendClientMessage{taildropChunk([]byte("abc")), taildropFileDone()}, codes.InvalidArgument},
		{"long", 2, []*TaildropSendClientMessage{taildropChunk([]byte("abc")), taildropFileDone()}, codes.InvalidArgument},
		{"missing-file-done", 3, []*TaildropSendClientMessage{taildropChunk([]byte("abc"))}, codes.Unknown},
		{"start-in-content", 3, []*TaildropSendClientMessage{taildropStart()}, codes.InvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := &taildropProviderFixture{send: func(_ context.Context, _, _ string, size int64, r io.Reader, _ func(int64)) error {
				_, err := io.CopyN(io.Discard, r, size)
				if err == io.EOF {
					return nil
				}
				return err
			}}
			s := taildropStartedFixture(t, p)
			stream := &taildropDirectStream{ctx: context.Background(), frames: append([]*TaildropSendClientMessage{taildropStart(&TaildropOutgoingFile{Name: "a", Size: test.size})}, test.frames...)}
			err := s.SendTaildropFiles(stream)
			if status.Code(err) != test.want {
				t.Fatal(err)
			}
			for _, m := range stream.sent {
				if m.GetProgress().GetFileCompleted() {
					t.Fatal("bad source completed")
				}
			}
		})
	}
}
