package libbox

import (
	"errors"
	"os"
	"testing"
)

type interfaceBindingTestPlatform struct {
	PlatformInterface
	fd   int32
	name string
	err  error
}

func (p *interfaceBindingTestPlatform) BindInterfaceControl(fd int32, name string) error {
	p.fd, p.name = fd, name
	return p.err
}

func TestInterfaceBindingWrapperPreservesDescriptorNameAndError(t *testing.T) {
	p := &interfaceBindingTestPlatform{}
	w := &platformInterfaceWrapper{iif: p}
	if err := w.BindInterfaceControl(42, "wlan0"); err != nil {
		t.Fatal(err)
	}
	if p.fd != 42 || p.name != "wlan0" {
		t.Fatal("platform binding arguments changed")
	}
	p.err = errors.New("network no longer available")
	if err := w.BindInterfaceControl(43, "rmnet_data0"); !errors.Is(err, p.err) {
		t.Fatal("platform binding failure hidden")
	}
	if p.fd != 43 || p.name != "rmnet_data0" {
		t.Fatal("platform binding arguments changed on failure")
	}
}

func TestInterfaceBindingCheckConfigStubCannotBindSockets(t *testing.T) {
	var stub *platformInterfaceStub
	if err := stub.BindInterfaceControl(42, "wlan0"); !errors.Is(err, os.ErrInvalid) {
		t.Fatal("CheckConfig stub unexpectedly permits actual socket binding")
	}
}
