package dns

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"

	"github.com/miekg/dns"
)

type fakeIPRouterAdmissionKey struct{}

// Only the final selected response is protected. Inner policy candidates and
// cache refresh responses must not be mistaken for externally issued answers.
func protectFinalFakeIPAnswer(receiver, caller context.Context, transport adapter.DNSTransport, response *dns.Msg) error {
	if protection, ok := adapter.FakeIPProtectionFromContext(receiver); ok {
		caller = adapter.ContextWithFakeIPProtection(caller, protection)
	}
	if observer, ok := transport.(adapter.FakeIPAnswerProtection); ok {
		caller = adapter.ContextWithFakeIPAnswerProtection(caller, observer)
	} else if _, runtimeProtection := adapter.FakeIPProtectionFromContext(caller); runtimeProtection {
		return errors.New("selected fake-IP transport has no namespace answer observer")
	}
	return adapter.ProtectFakeIPAnswer(caller, response)
}

func fakeIPClientOwnsAdmission(ctx context.Context) bool {
	routed, _ := ctx.Value(fakeIPRouterAdmissionKey{}).(bool)
	return !routed
}
