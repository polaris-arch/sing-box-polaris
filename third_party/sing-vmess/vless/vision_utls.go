//go:build with_utls

package vless

import (
	"net"

	N "github.com/sagernet/sing/common/network"

	meta "github.com/metacubex/utls"
	refraction "github.com/refraction-networking/utls"
)

func init() {
	tlsRegistry = append(tlsRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, owner any) {
		uConn, loaded := N.CastReader[*meta.UConn](conn)
		if loaded {
			if uConn == nil || uConn.Conn == nil {
				return true, nil, nil
			}
			return true, uConn.NetConn(), uConn.Conn
		}
		tlsConn, loaded := N.CastReader[*meta.Conn](conn)
		if loaded {
			if tlsConn == nil {
				return true, nil, nil
			}
			return true, tlsConn.NetConn(), tlsConn
		}
		return
	}, func(conn net.Conn) (loaded bool, netConn net.Conn, owner any) {
		uConn, loaded := N.CastReader[*refraction.UConn](conn)
		if loaded {
			if uConn == nil || uConn.Conn == nil {
				return true, nil, nil
			}
			return true, uConn.NetConn(), uConn.Conn
		}
		tlsConn, loaded := N.CastReader[*refraction.Conn](conn)
		if loaded {
			if tlsConn == nil {
				return true, nil, nil
			}
			return true, tlsConn.NetConn(), tlsConn
		}
		return
	})
}
