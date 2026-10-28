//go:build with_quic

package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/runtimeingress"
	"github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

func init() {
	ConfigureHTTP3ListenerFunc = func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.QUICOptions) (io.Closer, error) {
		err := qtls.ConfigureHTTP3(tlsConfig)
		if err != nil {
			return nil, err
		}
		staged := listener.RuntimeEnabled()
		var udpConn net.PacketConn
		if !staged {
			udpConn, err = listener.ListenUDP()
			if err != nil {
				return nil, err
			}
		}
		quicConfig := httpclient.NewQUICConfig(options)
		if quicConfig.MaxIncomingStreams == 0 {
			quicConfig.MaxIncomingStreams = 1 << 60
		}
		quicConfig.Allow0RTT = true
		quicConfig.DisablePathManager = true
		quicConfig.EnableDatagrams = true
		var quicListener qtls.EarlyListener
		if staged {
			quicListener, err = runtimeingress.ListenQUIC(ctx, listener, tlsConfig, quicConfig, true)
		} else {
			quicListener, err = qtls.ListenEarly(udpConn, tlsConfig, quicConfig)
		}
		if err != nil {
			if udpConn != nil {
				_ = udpConn.Close()
			}
			return nil, err
		}
		http3Server := &http3.Server{
			Handler:         handler,
			EnableDatagrams: true,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				conn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestion_meta2.ProfileStandard))
				return log.ContextWithNewID(ctx)
			},
		}
		if staged {
			done := make(chan struct{})
			var serveErr error
			closeFence := outbound.NewRuntimeIOFence(func() error {
				err := quicListener.Close()
				err = errors.Join(err, http3Server.Close())
				<-done
				if serveErr != nil && !E.IsClosedOrCanceled(serveErr) {
					err = errors.Join(err, serveErr)
				}
				if err != nil {
					return fmt.Errorf("HTTP3 server cleanup incomplete: %v", err)
				}
				return nil
			})
			go func() {
				defer close(done)
				defer func() {
					if failure := recover(); failure != nil {
						serveErr = fmt.Errorf("HTTP3 Serve panic; cleanup unknown: %v", failure)
					}
				}()
				serveErr = http3Server.ServeListener(quicListener)
			}()
			context.AfterFunc(ctx, func() { _ = closeFence.RuntimeCloseAndWait() })
			if err := adapter.DeferConstructionCleanup(ctx, closeFence.RuntimeCloseAndWait); err != nil {
				return nil, err
			}
			if err := adapter.ConstructionScopeErr(ctx); err != nil {
				return nil, err
			}
			return &runtimeHTTP3Closer{fence: closeFence}, nil
		}
		go func() {
			serveErr := http3Server.ServeListener(quicListener)
			udpConn.Close()
			if serveErr != nil && !E.IsClosedOrCanceled(serveErr) {
				logger.Error("http3 server closed: ", serveErr)
			}
		}()
		return quicListener, nil
	}
	HTTP3StreamFunc = func(ctx context.Context, writer http.ResponseWriter) (DatagramStream, bool) {
		streamer, isStreamer := writer.(http3.HTTPStreamer)
		if !isStreamer {
			return nil, false
		}
		settingser, isSettingser := writer.(http3.Settingser)
		if !isSettingser {
			return nil, false
		}
		select {
		case <-settingser.ReceivedSettings():
		case <-ctx.Done():
			return nil, false
		}
		return &datagramStream{
			Stream:           streamer.HTTPStream(),
			datagramsEnabled: settingser.Settings().EnableDatagrams,
		}, true
	}
}

type datagramStream struct {
	*http3.Stream
	datagramsEnabled bool
}

func (s *datagramStream) SendDatagram(payload []byte) error {
	if !s.datagramsEnabled {
		return ErrDatagramUnsupported
	}
	err := s.Stream.SendDatagram(payload)
	if err == nil {
		return nil
	}
	if tooLarge, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
		return &DatagramTooLargeError{MaxPayloadSize: int(tooLarge.MaxDatagramPayloadSize) - VarintLen(uint64(s.Stream.StreamID()/4))}
	}
	return err
}

func (s *datagramStream) Close() error {
	s.Stream.SetWriteDeadline(time.Now())
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

type runtimeHTTP3Closer struct{ fence *outbound.RuntimeIOFence }

func (c *runtimeHTTP3Closer) Close() error               { return c.fence.RuntimeCloseAndWait() }
func (c *runtimeHTTP3Closer) RuntimeCloseAndWait() error { return c.Close() }
