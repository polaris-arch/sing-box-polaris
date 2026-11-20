//go:build !with_quic

package runtimeingress

import "errors"

func (c *QUICServerTLS) WaitReady() error {
	return errors.New("QUIC runtime adapter requires with_quic build")
}

func (c *QUICServerTLS) RuntimeValidate() error {
	return errors.New("QUIC runtime adapter requires with_quic build")
}
