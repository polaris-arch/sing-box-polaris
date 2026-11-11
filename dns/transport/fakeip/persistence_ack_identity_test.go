package fakeip

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/sagernet/sing-box/dns/transport/lifecycle"
)

// Use the real Manager prepare/publication/worker/ACK lifecycle with the bounded
// existing backend fixture. This does not claim physical database durability.
func TestExactPersistenceAcknowledgementKeepsSameDigestTransactionsSeparate(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		name := "success"
		if failWrite {
			name = "failed-write-original-retry"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			m := fixtureEmptyManager(t)
			anchor, peer := fixtureBackend("exact-anchor"), fixtureBackend("exact-allocator")
			resolver := fixtureResolver(anchor, peer)
			prefix := netip.MustParsePrefix("198.18.0.0/29")
			const effectiveID = "same-canonical-effective-configuration"
			prepare := func(id string) *RangeMigration {
				t.Helper()
				options := fixtureOptions(anchor, resolver, id)
				options.Backend = peer
				options.EffectiveConfigurationID = effectiveID
				candidate, err := m.PreparePersistentRanges(ctx, prefix, netip.Prefix{}, options)
				if err != nil {
					t.Fatal(err)
				}
				sourceReusePublishDurable(t, candidate)
				return candidate
			}
			first := prepare("exact-T1")
			if err := first.AcknowledgePersistence(ctx, effectiveID); err != nil {
				t.Fatal(err)
			}
			requireExactAcknowledgement(t, first, true, anchor, peer)
			old, err := m.Borrow(prefix, netip.Prefix{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = old.Close() })
			address, err := old.Create("retained-original.example", false)
			if err != nil {
				t.Fatal(err)
			}
			answer, err := m.ProtectAnswer(fakeAnswer(address, "retained-original.example", 60))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(answer.Abort)
			firstAnchor, firstPeer := sourceReuseInspect(m, anchor, resolver), sourceReuseInspect(m, peer, resolver)
			second := prepare("exact-T2")
			if second.persistent == first.persistent || second.namespace == first.namespace || second.persistent.link.ID == first.persistent.link.ID {
				t.Fatal("same canonical digest did not produce a distinct real transaction")
			}
			m.mappingAccess.Lock()
			retained := first.namespace.retired && first.namespace.handles != 0 && m.protection.namespaceCounts[first.namespace.id] != 0
			m.mappingAccess.Unlock()
			if !retained {
				t.Fatal("original real namespace/answer borrower was not retained")
			}
			if err := first.AcknowledgePersistence(ctx, effectiveID); err != nil {
				t.Fatal("original repeat-safe ACK failed", err)
			}
			requireExactAcknowledgement(t, second, false, anchor, peer)
			if err := m.AcknowledgePersistence(ctx, effectiveID); !errors.Is(err, ErrPersistenceIdentity) {
				t.Fatal("ambiguous digest-only ACK chose a transaction", err)
			}
			if err := second.AcknowledgePersistence(ctx, "different-canonical"); !errors.Is(err, ErrPersistenceIdentity) {
				t.Fatal("wrong digest acknowledged original participant", err)
			}
			if failWrite {
				peer.access.Lock()
				peer.failLink = true
				peer.access.Unlock()
				if err := second.AcknowledgePersistence(ctx, effectiveID); err == nil {
					t.Fatal("actual backend ACK write failure reported success")
				}
				m.mappingAccess.Lock()
				acknowledged := second.persistent.acknowledged
				m.mappingAccess.Unlock()
				peer.access.Lock()
				peerAcknowledged := peer.links[second.persistent.link.ID].Acknowledged
				peer.failLink = false
				peer.access.Unlock()
				if acknowledged || peerAcknowledged {
					t.Fatal("failed backend ACK closed its actual participant/link")
				}
				options := fixtureOptions(anchor, resolver, "must-stay-blocked")
				options.EffectiveConfigurationID = effectiveID
				if rejected, err := m.PreparePersistentRanges(ctx, prefix, netip.Prefix{}, options); !errors.Is(err, ErrPersistencePending) || rejected != nil {
					t.Fatal("failed original ACK released pending guard", err)
				}
				if err := first.AcknowledgePersistence(ctx, effectiveID); err != nil {
					t.Fatal(err)
				}
				m.mappingAccess.Lock()
				acknowledged = second.persistent.acknowledged
				m.mappingAccess.Unlock()
				if acknowledged {
					t.Fatal("old original retry settled newer transaction")
				}
			}
			if err := second.AcknowledgePersistence(ctx, effectiveID); err != nil {
				t.Fatal("same original ACK retry failed", err)
			}
			requireExactAcknowledgement(t, second, true, anchor, peer)
			for index, backend := range []*runtimeFixtureBackend{anchor, peer} {
				before := firstAnchor.links[first.persistent.link.ID]
				if index == 1 {
					before = firstPeer.links[first.persistent.link.ID]
				}
				backend.access.Lock()
				unchanged := reflect.DeepEqual(before, backend.links[first.persistent.link.ID])
				firstWrites, secondWrites := 0, 0
				for _, id := range backend.acknowledgedLinks {
					if id == first.persistent.link.ID {
						firstWrites++
					}
					if id == second.persistent.link.ID {
						secondWrites++
					}
				}
				backend.access.Unlock()
				if !unchanged || firstWrites != 1 || secondWrites == 0 {
					t.Fatal("exact ACK rewrote T1 or missed T2 on its actual backend", unchanged, firstWrites, secondWrites)
				}
			}
			third := prepare("exact-T3")
			requireExactAcknowledgement(t, third, false, anchor, peer)
			if err := second.AcknowledgePersistence(ctx, effectiveID); err != nil {
				t.Fatal(err)
			}
			requireExactAcknowledgement(t, third, false, anchor, peer)
			if err := third.AcknowledgePersistence(ctx, effectiveID); err != nil {
				t.Fatal(err)
			}
			requireExactAcknowledgement(t, third, true, anchor, peer)
			answer.Abort()
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			address, err = m.create("ordinary-after-exact-ack.example", false)
			if err != nil {
				t.Fatal(err)
			}
			anchor.access.Lock()
			anchorObserved := anchor.observed
			anchor.access.Unlock()
			peer.access.Lock()
			peerObserved := peer.observed
			peer.access.Unlock()
			ordinary, err := m.ProtectAnswer(fakeAnswer(address, "ordinary-after-exact-ack.example", 60))
			if err != nil {
				t.Fatal(err)
			}
			ordinary.Delivered(time.Now())
			anchor.access.Lock()
			anchorAfter := anchor.observed
			anchor.access.Unlock()
			peer.access.Lock()
			peerAfter := peer.observed
			peer.access.Unlock()
			if anchorAfter != anchorObserved || peerAfter != peerObserved {
				t.Fatal("settled exact ACK retained per-answer synchronous certification")
			}
		})
	}
}

func requireExactAcknowledgement(t *testing.T, candidate *RangeMigration, acknowledged bool, backends ...*runtimeFixtureBackend) {
	t.Helper()
	p := candidate.persistent
	candidate.manager.mappingAccess.Lock()
	participantAcknowledged := p.acknowledged
	candidate.manager.mappingAccess.Unlock()
	if participantAcknowledged != acknowledged {
		t.Fatal("original participant ACK differs", p.options.TransactionID, participantAcknowledged, acknowledged)
	}
	for _, backend := range backends {
		backend.access.Lock()
		link, found := backend.links[p.link.ID]
		backend.access.Unlock()
		if !found || !sameRuntimeLink(link, p.link) || (acknowledged && !link.DiscoveryReady) || link.Acknowledged != acknowledged {
			t.Fatal("original backend link ACK differs", p.options.TransactionID, backend.descriptor, link, acknowledged)
		}
	}
}

func TestExactPersistenceAcknowledgementRejectsUnpublishedForeignAndStoppedParticipants(t *testing.T) {
	ctx := context.Background()
	m := fixtureEmptyManager(t)
	backend := fixtureBackend("identity-anchor")
	resolver := fixtureResolver(backend)
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	options := fixtureOptions(backend, resolver, "identity-original")
	candidate, err := m.PreparePersistentRanges(ctx, prefix, netip.Prefix{}, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(candidate.Abort)
	if err := candidate.AcknowledgePersistence(ctx, options.EffectiveConfigurationID); !errors.Is(err, ErrPersistenceIdentity) {
		t.Fatal("unpublished participant was acknowledged", err)
	}
	sourceReusePublishDurable(t, candidate)
	other := fixtureEmptyManager(t)
	if err := other.acknowledgePersistence(ctx, options.EffectiveConfigurationID, candidate.persistent); !errors.Is(err, ErrPersistenceIdentity) {
		t.Fatal("different Manager borrowed original participant", err)
	}
	unregistered := &persistentPreparation{candidate: candidate, options: options, link: candidate.persistent.link}
	if err := m.acknowledgePersistence(ctx, options.EffectiveConfigurationID, unregistered); !errors.Is(err, ErrPersistenceIdentity) {
		t.Fatal("matching transaction fields replaced exact published membership", err)
	}
	requireExactAcknowledgement(t, candidate, false, backend)
	if err := candidate.AcknowledgePersistence(ctx, options.EffectiveConfigurationID); err != nil {
		t.Fatal(err)
	}
	if err := candidate.AcknowledgePersistence(ctx, options.EffectiveConfigurationID); err != nil {
		t.Fatal("same original repeat failed", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := candidate.AcknowledgePersistence(ctx, options.EffectiveConfigurationID); !errors.Is(err, lifecycle.ErrStopped) {
		t.Fatal("stopped Manager accepted participant ACK", err)
	}
}
