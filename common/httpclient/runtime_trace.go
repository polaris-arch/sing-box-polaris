package httpclient

import (
	"net/http/httptrace"
	"net/textproto"

	"github.com/sagernet/sing-box/adapter/outbound"
)

func guardCallback0(fence *outbound.RuntimeIOFence, callback func()) func() {
	if callback == nil {
		return nil
	}
	return func() {
		release, err := fence.Acquire()
		if err != nil {
			return
		}
		defer release()
		callback()
	}
}

func guardCallback1[A any](fence *outbound.RuntimeIOFence, callback func(A)) func(A) {
	if callback == nil {
		return nil
	}
	return func(a A) {
		release, err := fence.Acquire()
		if err != nil {
			return
		}
		defer release()
		callback(a)
	}
}

func guardCallback2[A, B any](fence *outbound.RuntimeIOFence, callback func(A, B)) func(A, B) {
	if callback == nil {
		return nil
	}
	return func(a A, b B) {
		release, err := fence.Acquire()
		if err != nil {
			return
		}
		defer release()
		callback(a, b)
	}
}

func guardCallback3[A, B, C any](fence *outbound.RuntimeIOFence, callback func(A, B, C)) func(A, B, C) {
	if callback == nil {
		return nil
	}
	return func(a A, b B, c C) {
		release, err := fence.Acquire()
		if err != nil {
			return
		}
		defer release()
		callback(a, b, c)
	}
}

func (r *runtimeRequestBoundary) guardTrace(trace *httptrace.ClientTrace) *httptrace.ClientTrace {
	guarded := &httptrace.ClientTrace{
		GetConn:              guardCallback1(r.callbacks, trace.GetConn),
		GotConn:              guardCallback1(r.callbacks, trace.GotConn),
		PutIdleConn:          guardCallback1(r.callbacks, trace.PutIdleConn),
		GotFirstResponseByte: guardCallback0(r.callbacks, trace.GotFirstResponseByte),
		Got100Continue:       guardCallback0(r.callbacks, trace.Got100Continue),
		DNSStart:             guardCallback1(r.callbacks, trace.DNSStart),
		DNSDone:              guardCallback1(r.callbacks, trace.DNSDone),
		ConnectStart:         guardCallback2(r.callbacks, trace.ConnectStart),
		ConnectDone:          guardCallback3(r.callbacks, trace.ConnectDone),
		TLSHandshakeStart:    guardCallback0(r.callbacks, trace.TLSHandshakeStart),
		TLSHandshakeDone:     guardCallback2(r.callbacks, trace.TLSHandshakeDone),
		WroteHeaderField:     guardCallback2(r.callbacks, trace.WroteHeaderField),
		WroteHeaders:         guardCallback0(r.callbacks, trace.WroteHeaders),
		Wait100Continue:      guardCallback0(r.callbacks, trace.Wait100Continue),
		WroteRequest:         guardCallback1(r.callbacks, trace.WroteRequest),
	}
	if trace.Got1xxResponse != nil {
		callback := trace.Got1xxResponse
		guarded.Got1xxResponse = func(code int, header textproto.MIMEHeader) error {
			release, err := r.callbacks.Acquire()
			if err != nil {
				return err
			}
			defer release()
			return callback(code, header)
		}
	}
	return guarded
}
