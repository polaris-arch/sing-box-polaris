package box

import (
 "context"
 "errors"
 "net/netip"
 "testing"

 C "github.com/sagernet/sing-box/constant"
 "github.com/sagernet/sing-box/dns/transport/fakeip"
 "github.com/sagernet/sing-box/log"
 "github.com/sagernet/sing-box/option"
 "github.com/sagernet/sing/common/json"
)

func runtimeFakeIPCandidate(t *testing.T, prefix string) *preparedRuntimeGraph {
 t.Helper()
 var configuration option.FakeIPDNSServerOptions
 content, err := json.Marshal(map[string]string{"inet4_range":prefix})
 if err != nil { t.Fatal(err) }
 if err := json.Unmarshal(content,&configuration); err != nil { t.Fatal(err) }
 server := option.DNSServerOptions{}
 server.Type = C.DNSTypeFakeIP
 server.Options = &configuration
 dns := &option.DNSOptions{}
 dns.Servers = []option.DNSServerOptions{server}
 return &preparedRuntimeGraph{options:option.Options{DNS:dns}}
}

func TestRuntimeFakeIPCandidateCannotAnswerBeforePublication(t *testing.T) {
 manager := fakeip.NewEmptyManager(context.Background(),log.NewNOPFactory().Logger())
 if err := manager.Start(); err != nil { t.Fatal(err) }
 defer manager.Close()
 instance := &Box{runtime:&runtimeCoordinator{ctx:context.Background(),fakeIP:manager}}
 prepared := runtimeFakeIPCandidate(t,"198.18.0.0/29")
 if err := instance.prepareRuntimeFakeIP(context.Background(),prepared); err != nil { t.Fatal(err) }
 defer prepared.abort()
 store, err := prepared.fakeIPMigration.Borrow(netip.MustParsePrefix("198.18.0.0/29"),netip.Prefix{})
 if err != nil { t.Fatal(err) }; defer store.Close()
 if _,err := store.Create("before.example",false); !errors.Is(err,fakeip.ErrCandidateNotCommitted) { t.Fatal("candidate emitted an answer",err) }
 commit,err := prepared.fenceRuntimeFakeIP()
 if err != nil { t.Fatal(err) }; defer commit.Abort()
 commit.Publish()
 if _,err := store.Create("after.example",false); err != nil { t.Fatal(err) }
}

func TestRuntimeFakeIPAbortLeavesOriginalAllocator(t *testing.T) {
 manager,err := fakeip.NewManager(context.Background(),log.NewNOPFactory().Logger(),netip.MustParsePrefix("198.18.0.0/29"),netip.Prefix{})
 if err != nil { t.Fatal(err) }; if err := manager.Start(); err != nil { t.Fatal(err) }; defer manager.Close()
 old,err := manager.Borrow(netip.MustParsePrefix("198.18.0.0/29"),netip.Prefix{})
 if err != nil { t.Fatal(err) }; defer old.Close()
 first,err := old.Create("same.example",false); if err != nil { t.Fatal(err) }
 instance := &Box{runtime:&runtimeCoordinator{ctx:context.Background(),fakeIP:manager}}
 candidate := runtimeFakeIPCandidate(t,"198.19.0.0/29")
 if err := instance.prepareRuntimeFakeIP(context.Background(),candidate); err != nil { t.Fatal(err) }
 candidate.abort()
 again,err := old.Create("same.example",false)
 if err != nil || again != first { t.Fatal("abort mutated original allocator",again,err) }
 removed := &preparedRuntimeGraph{}
 if err := instance.prepareRuntimeFakeIP(context.Background(),removed); err != nil { t.Fatal(err) }
 if domain,ok := manager.RecognitionStore().Lookup(first); !ok || domain!="same.example" { t.Fatal("removal lost old recognition") }
}
