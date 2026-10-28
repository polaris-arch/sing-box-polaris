package dns

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Fixtures are complete cargo-example output, not handwritten approximations.
// Native DNS transports and the final node socket are mocked to avoid network I/O;
// option decoding, policy walker/cache and both actual resolve-dialer methods run.
type appPolicySocket struct{ tcp, udp []M.Socksaddr }

func (s *appPolicySocket) DialContext(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	s.tcp = append(s.tcp, destination)
	return nil, nil
}

func (s *appPolicySocket) ListenPacket(_ context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.udp = append(s.udp, destination)
	return &appPolicyPacket{}, nil
}

type appPolicyPacket struct{ net.PacketConn }

func (*appPolicyPacket) Close() error { return nil }

func TestAppGeneratedNodePolicyDialAndListen(t *testing.T) {
	for _, platform := range []string{"linux", "android", "ios"} {
		for _, scenario := range []string{"tier1-hit", "poison-tier2"} {
			t.Run(platform+"/"+scenario, func(t *testing.T) {
				data, err := os.ReadFile(filepath.Join("testdata", "node-policy", platform+".json"))
				require.NoError(t, err)
				var config struct {
					DNS struct {
						Rules   []option.DNSRule `json:"rules"`
						Servers []struct {
							Tag  string `json:"tag"`
							Type string `json:"type"`
						} `json:"servers"`
					} `json:"dns"`
					Outbounds []struct {
						Server   string                       `json:"server"`
						Resolver *option.DomainResolveOptions `json:"domain_resolver"`
					} `json:"outbounds"`
				}
				require.NoError(t, json.UnmarshalContext(context.Background(), data, &config))
				var scoped []option.DNSRule
				for _, rule := range config.DNS.Rules {
					if dnsPolicyID(rule) == testPolicyID {
						scoped = append(scoped, rule)
					}
				}
				require.NotEmpty(t, scoped)
				var candidates []*policyTestTransport
				tags := map[string]*policyTestTransport{}
				for _, server := range config.DNS.Servers {
					if !strings.HasPrefix(server.Tag, "dns-node-native-") {
						continue
					}
					tag := server.Tag
					transport := &policyTestTransport{tag: tag, exchange: func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
						// A clean current-family answer, with a mixed poison in Tier1 in scenario2.
						select {
						case <-time.After(5 * time.Millisecond):
						case <-ctx.Done():
							return nil, ctx.Err()
						}
						ip := "192.0.2.77"
						if msg.Question[0].Qtype == mDNS.TypeAAAA {
							ip = "2001:db8::77"
						}
						ips := []netip.Addr{netip.MustParseAddr(ip)}
						if scenario == "poison-tier2" && strings.HasPrefix(tag, "dns-node-native-1-") {
							ips = append(ips, netip.MustParseAddr("8.7.198.45"))
						}
						response := FixedResponse(msg.Id, msg.Question[0], ips, 60)
						if scenario == "poison-tier2" && strings.HasPrefix(tag, "dns-node-native-1-") && msg.Question[0].Qtype == mDNS.TypeAAAA {
							response.Answer = append(response.Answer, &mDNS.A{Hdr: mDNS.RR_Header{Name: msg.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60}, A: net.ParseIP("8.7.198.45").To4()})
						}
						return response, nil
					}}
					candidates = append(candidates, transport)
					tags[tag] = transport
					if server.Type == "local" {
						require.Equal(t, "linux", platform)
					}
				}
				router := policyRouter(t, scoped, candidates...)
				ctx := service.ContextWith[adapter.DNSRouter](context.Background(), router)
				var resolver *option.DomainResolveOptions
				for _, outbound := range config.Outbounds {
					if outbound.Server == "node.native.test" {
						resolver = outbound.Resolver
					}
				}
				require.NotNil(t, resolver)
				options, err := dialer.NewDNSQueryOptions(ctx, resolver, true)
				require.NoError(t, err)
				socket := &appPolicySocket{}
				resolved := dialer.NewResolveDialer(ctx, socket, false, "", options, 0)
				destination := M.ParseSocksaddr("node.native.test:443")
				_, err = resolved.DialContext(ctx, "tcp", destination)
				require.NoError(t, err)
				before := int32(0)
				for _, upstream := range candidates {
					before += upstream.calls.Load()
				}
				packet, err := resolved.ListenPacket(ctx, destination)
				require.NoError(t, err)
				require.NoError(t, packet.Close())
				after := int32(0)
				for _, upstream := range candidates {
					after += upstream.calls.Load()
				}
				require.Equal(t, before, after, "ListenPacket must reuse final policy cache")
				require.Equal(t, netip.MustParseAddr("192.0.2.77"), socket.tcp[0].Addr)
				require.Equal(t, netip.MustParseAddr("192.0.2.77"), socket.udp[0].Addr)
				if scenario == "tier1-hit" {
					require.Zero(t, tags["dns-node-native-2-0"].calls.Load())
				} else {
					require.Positive(t, tags["dns-node-native-2-0"].calls.Load())
				}
			})
		}
	}
}
