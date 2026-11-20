package tun

import (
	"net/netip"
	"os"
	"runtime"
	"unsafe"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// ConnectivityService.updateIngressToVpnAddressFiltering keys this map by the
// VPN address (IPv4-mapped) with the tun ifindex in both value slots, and the
// cgroup skb ingress program in netd.c drops packets for app uids to that
// address from any other interface, which includes the de-NATed replies of
// bypassed flows. ConnectivityService updates entries from LinkProperties diffs.
const androidIngressDiscardMapPath = "/sys/fs/bpf/netd_shared/map_netd_ingress_discard_map"

type bpfObjectAttribute struct {
	pathname       uint64
	fileDescriptor uint32
	fileFlags      uint32
}

type bpfMapAttribute struct {
	mapDescriptor uint32
	_             uint32
	key           uint64
	value         uint64
	flags         uint64
}

type bpfObjectInfoAttribute struct {
	fileDescriptor uint32
	length         uint32
	info           uint64
}

func bpfObjectGet(path string) (int, uint32, error) {
	pathBytes, err := unix.BytePtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var pinner runtime.Pinner
	pinner.Pin(pathBytes)
	defer pinner.Unpin()
	attribute := bpfObjectAttribute{pathname: uint64(uintptr(unsafe.Pointer(pathBytes)))}
	descriptor, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if errno != 0 {
		return 0, 0, errno
	}
	var info struct {
		mapType   uint32
		id        uint32
		keySize   uint32
		valueSize uint32
	}
	pinner.Pin(&info)
	infoAttribute := bpfObjectInfoAttribute{
		fileDescriptor: uint32(descriptor),
		length:         uint32(unsafe.Sizeof(info)),
		info:           uint64(uintptr(unsafe.Pointer(&info))),
	}
	_, _, errno = unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&infoAttribute)), unsafe.Sizeof(infoAttribute))
	if errno != 0 {
		unix.Close(int(descriptor))
		return 0, 0, errno
	}
	if info.id == 0 || info.mapType != unix.BPF_MAP_TYPE_HASH || info.keySize != 16 || info.valueSize != 8 {
		unix.Close(int(descriptor))
		return 0, 0, E.New("unexpected ingress discard map identity/layout: id ", info.id, ", type ", info.mapType, ", key ", info.keySize, ", value ", info.valueSize)
	}
	return int(descriptor), info.id, nil
}

func bpfMapCall(command uintptr, mapDescriptor int, key []byte, value []byte, flags uint64) error {
	var pinner runtime.Pinner
	pinner.Pin(&key[0])
	defer pinner.Unpin()
	attribute := bpfMapAttribute{
		mapDescriptor: uint32(mapDescriptor),
		key:           uint64(uintptr(unsafe.Pointer(&key[0]))),
		flags:         flags,
	}
	if value != nil {
		pinner.Pin(&value[0])
		attribute.value = uint64(uintptr(unsafe.Pointer(&value[0])))
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, command, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if errno != 0 {
		return errno
	}
	return nil
}

func (r *autoRedirect) removeAndroidIngressDiscardRulesLocked() error {
	if !r.enableIPv4 {
		return nil
	}
	_, err := os.Stat(androidIngressDiscardMapPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "stat ingress discard map")
	}
	mapDescriptor, mapID, err := bpfObjectGet(androidIngressDiscardMapPath)
	if err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return E.Cause(err, "open ingress discard map")
	}
	defer unix.Close(mapDescriptor)
	tunLink, err := netlink.LinkByName(r.tunOptions.Name)
	if err != nil {
		return E.Cause(err, "find tun interface")
	}
	if r.androidIngressDiscardValues == nil {
		r.androidIngressDiscardValues = make(map[netip.Addr]ingressDiscardReceipt)
	}
	ops := ingressDiscardKernelOps(mapDescriptor)
	for _, prefix := range r.tunOptions.Inet4Address {
		address := prefix.Addr()
		if err := removeIngressDiscard(r.androidIngressDiscardValues, address, mapID, tunLink.Attrs().Index, ops); err != nil {
			return E.Cause(err, "remove ingress discard rule for ", address)
		}
	}
	return nil
}

func ingressDiscardKernelOps(fd int) ingressDiscardOps {
	return ingressDiscardOps{
		lookup: func(address netip.Addr) ([8]byte, error) {
			key := address.As16()
			var value [8]byte
			err := bpfMapCall(unix.BPF_MAP_LOOKUP_ELEM, fd, key[:], value[:], 0)
			return value, err
		},
		remove: func(address netip.Addr) error {
			key := address.As16()
			return bpfMapCall(unix.BPF_MAP_DELETE_ELEM, fd, key[:], nil, 0)
		},
		restore: func(address netip.Addr, value [8]byte) error {
			key := address.As16()
			return bpfMapCall(unix.BPF_MAP_UPDATE_ELEM, fd, key[:], value[:], unix.BPF_NOEXIST)
		},
	}
}

func (r *autoRedirect) restoreAndroidIngressDiscardRulesLocked() error {
	if len(r.androidIngressDiscardValues) == 0 {
		return nil
	}
	tunLink, err := netlink.LinkByName(r.tunOptions.Name)
	if err != nil {
		return E.Cause(err, "restore ingress discard rules: find interface")
	}
	mapDescriptor, mapID, err := bpfObjectGet(androidIngressDiscardMapPath)
	if err != nil {
		return E.Cause(err, "restore ingress discard rules: open map")
	}
	defer unix.Close(mapDescriptor)
	return restoreIngressDiscard(r.androidIngressDiscardValues, mapID, tunLink.Attrs().Index, ingressDiscardKernelOps(mapDescriptor))
}
