package urltest

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sagernet/sing-box/adapter"
)

type legacyPoolProbeDNSKey struct{}

func ContextWithLegacyPoolProbeDNS(ctx context.Context, resolver string) context.Context {
	return context.WithValue(ctx, legacyPoolProbeDNSKey{}, resolver)
}

func IsLegacyPoolProbeDNS(ctx context.Context, resolver string) bool {
	tag, loaded := ctx.Value(legacyPoolProbeDNSKey{}).(string)
	return loaded && tag == resolver
}

const (
	PoolProbeTicketVersion  = 1
	PoolProbeMemberMaxBytes = 512
	PoolProbeTicketMaxBytes = 768
	poolProbeTicketLifetime = 15 * time.Second
	poolProbeTicketClaims   = 8 + 4 // expiry in Unix milliseconds and pool slot
)

var poolProbeTicketKey = sync.OnceValue(func() [sha256.Size]byte {
	var key [sha256.Size]byte
	_, _ = rand.Read(key[:])
	return key
})

// NormalizePoolProbeAuthority accepts explicit TCP ports and canonicalizes IP
// literals and ASCII DNS names for the signing and CONNECT paths.
func NormalizePoolProbeAuthority(authority string) (string, bool) {
	if len(authority) > 260 {
		return "", false
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil || host == "" || port == "" || port[0] < '0' || port[0] > '9' {
		return "", false
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", false
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		host = ip.Unmap().String()
	} else {
		if authority[0] == '[' || len(strings.TrimSuffix(host, ".")) > 253 {
			return "", false
		}
		for label := range strings.SplitSeq(strings.TrimSuffix(host, "."), ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", false
			}
			for _, char := range label {
				if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
					return "", false
				}
			}
		}
		host = strings.ToLower(host)
	}
	return net.JoinHostPort(host, strconv.FormatUint(portNumber, 10)), true
}

// IssuePoolProbeTicket signs a probe already authorized against the admitted graph.
func IssuePoolProbeTicket(graph string, slot uint32, member, authority string, background bool) (string, bool) {
	return issuePoolProbeTicket(graph, slot, member, authority, background, time.Now())
}

func issuePoolProbeTicket(graph string, slot uint32, member, authority string, background bool, now time.Time) (string, bool) {
	if _, ok := adapter.ParseRuntimeRevisionToken(graph); !ok || len(member) == 0 || len(member) > PoolProbeMemberMaxBytes || !utf8.ValidString(member) {
		return "", false
	}
	target, ok := NormalizePoolProbeAuthority(authority)
	if !ok {
		return "", false
	}
	claims := make([]byte, 0, poolProbeTicketClaims+len(member)+sha256.Size)
	claims = binary.BigEndian.AppendUint64(claims, uint64(now.Add(poolProbeTicketLifetime).UnixMilli()))
	claims = binary.BigEndian.AppendUint32(claims, slot)
	claims = append(claims, member...)
	return base64.RawURLEncoding.EncodeToString(append(claims, poolProbeMAC(claims, graph, target, background)...)), true
}

// VerifyPoolProbeTicket authenticates the requested CONNECT against its ticket.
// The caller must still enforce the graph and slot on the captured route.
func VerifyPoolProbeTicket(ticket, graph string, member adapter.ProbeMemberDigest, authority string, background bool) (string, uint32, bool) {
	return verifyPoolProbeTicket(ticket, graph, member, authority, background, time.Now())
}

func verifyPoolProbeTicket(ticket, graph string, member adapter.ProbeMemberDigest, authority string, background bool, now time.Time) (string, uint32, bool) {
	if len(ticket) == 0 || len(ticket) > PoolProbeTicketMaxBytes || strings.ContainsAny(ticket, "\r\n") {
		return "", 0, false
	}
	if _, ok := adapter.ParseRuntimeRevisionToken(graph); !ok {
		return "", 0, false
	}
	target, ok := NormalizePoolProbeAuthority(authority)
	if !ok {
		return "", 0, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(ticket)
	if err != nil || len(decoded) <= poolProbeTicketClaims+sha256.Size || len(decoded) > poolProbeTicketClaims+PoolProbeMemberMaxBytes+sha256.Size {
		return "", 0, false
	}
	claims, tag := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	if !hmac.Equal(tag, poolProbeMAC(claims, graph, target, background)) {
		return "", 0, false
	}
	expiry := int64(binary.BigEndian.Uint64(claims[:8]))
	if expiry <= now.UnixMilli() || expiry > now.Add(poolProbeTicketLifetime).UnixMilli() {
		return "", 0, false
	}
	memberTag := claims[poolProbeTicketClaims:]
	digest := sha256.Sum256(memberTag)
	if !hmac.Equal(digest[:], member[:]) {
		return "", 0, false
	}
	return string(memberTag), binary.BigEndian.Uint32(claims[8:12]), true
}

func poolProbeMAC(claims []byte, graph, authority string, background bool) []byte {
	key := poolProbeTicketKey()
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("polaris-pool-probe/v1\x00" + graph + "\x00" + authority + "\x00"))
	if background {
		mac.Write([]byte{1})
	} else {
		mac.Write([]byte{0})
	}
	mac.Write(claims)
	return mac.Sum(nil)
}
