package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/unix"
)

var _ LinuxTUN = (*NativeTun)(nil)

type NativeTun struct {
	networkNamespace    *pinnedNetworkNamespace
	namespaceRequired   bool
	resolved            resolvedLifecycle
	tunFd               int
	tunFile             *os.File
	iovecsOutputDefault []unix.Iovec
	interfaceCallback   *list.Element[DefaultInterfaceUpdateCallback]
	options             Options
	routeAccess         sync.Mutex
	ownedRoutes         ownedLinuxRoutes
	ruleAccess          sync.Mutex
	ownedRules          ownedLinuxRules
	readAccess          sync.Mutex
	writeAccess         sync.Mutex
	vnetHdr             bool
	multiQueue          bool
	writeBuffer         []byte
	readRawConn         syscall.RawConn
	pendingBuffer       []byte
	pendingLength       int
	vnetHdrWriteBuf     []byte
	gsoToWrite          []int
	tcpGROTable         *tcpGROTable
	udpGROTable         *udpGROTable
	gro                 groDisablementFlags
	txChecksumOffload   bool
}

func New(options Options) (Tun, error) {
	if options.FileDescriptor == 0 {
		return execInNetworkNamespace(options.NetNs, func() (Tun, error) {
			return newNativeTun(options, open, netlink.LinkByName, (*NativeTun).configure)
		})
	}
	nativeTun := &NativeTun{
		tunFd:   options.FileDescriptor,
		tunFile: os.NewFile(uintptr(options.FileDescriptor), "tun"),
		options: options,
	}
	if options.GSO {
		err := nativeTun.enableGSO()
		if err != nil {
			if options.Logger != nil {
				options.Logger.Warn(err)
			}
		}
	}
	return nativeTun, nil
}

// Keep acquisition and compensation in one production path; dependencies are
// explicit so constructor failures can be exercised without a real TUN device.
func newNativeTun(options Options, openDevice func(string, bool, bool) (int, bool, error), lookup func(string) (netlink.Link, error), configure func(*NativeTun, netlink.Link) error) (result Tun, resultErr error) {
	var namespace *pinnedNetworkNamespace
	if options.NetNs != "" {
		var err error
		namespace, err = pinCurrentNetworkNamespace()
		if err != nil {
			return nil, E.Cause(err, "pin native network namespace")
		}
		defer func() {
			if result == nil {
				resultErr = E.Errors(resultErr, namespace.close())
			}
		}()
	}
	tunFd, multiQueue, err := openDevice(options.Name, options.GSO, options.MultiQueue)
	if err != nil {
		return nil, E.Cause(err, "open tun")
	}
	tunLink, err := lookup(options.Name)
	if err != nil {
		return nil, E.Errors(err, unix.Close(tunFd))
	}
	nativeTun := &NativeTun{
		networkNamespace:  namespace,
		namespaceRequired: options.NetNs != "",
		tunFd:             tunFd,
		tunFile:           os.NewFile(uintptr(tunFd), "tun"),
		options:           options,
		multiQueue:        multiQueue,
	}
	err = configure(nativeTun, tunLink)
	if err != nil {
		return nil, failNativeTunConstruction(err, nativeTun.tunFile)
	}
	return nativeTun, nil
}

var controlPath string

func init() {
	const defaultTunPath = "/dev/net/tun"
	const androidTunPath = "/dev/tun"
	if rw.IsFile(androidTunPath) {
		controlPath = androidTunPath
	} else {
		controlPath = defaultTunPath
	}
}

// A persistent device created without IFF_MULTI_QUEUE refuses the flag with EINVAL
// (tun_set_iff), so the plain flags are retried and such a device stays single-queue.
func open(name string, vnetHdr bool, multiQueue bool) (int, bool, error) {
	flags := unix.IFF_TUN | unix.IFF_NO_PI
	if vnetHdr {
		flags |= unix.IFF_VNET_HDR
	}
	if multiQueue {
		fd, err := openTun(name, flags|unix.IFF_MULTI_QUEUE)
		if err == nil {
			return fd, true, nil
		}
		if !errors.Is(err, unix.EINVAL) {
			return -1, false, err
		}
	}
	fd, err := openTun(name, flags)
	if err != nil {
		return -1, false, err
	}
	return fd, false, nil
}

func openTun(name string, flags int) (int, error) {
	fd, err := unix.Open(controlPath, unix.O_RDWR, 0)
	if err != nil {
		return -1, E.Cause(err, "open ", controlPath)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return -1, E.Cause(err, "create ifreq")
	}
	ifr.SetUint16(uint16(flags))
	err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	if err != nil {
		unix.Close(fd)
		return -1, E.Cause(err, "TUNSETIFF")
	}
	err = unix.SetNonblock(fd, true)
	if err != nil {
		unix.Close(fd)
		return -1, E.Cause(err, "set nonblock")
	}
	return fd, nil
}

func (t *NativeTun) openQueue() (int, error) {
	return t.openQueueWith(openTun)
}

// Called by Go stack startup, not from a pin-held native configure callback.
// Use the acquired namespace object for every queue, never the discovery path.
func (t *NativeTun) openQueueWith(openDevice func(string, int) (int, error)) (int, error) {
	fd := -1
	err := t.runInOwnedNamespace(func() error {
		t.routeAccess.Lock()
		defer t.routeAccess.Unlock()
		if t.ownedRoutes.closed {
			return E.New("native device owner is closed")
		}
		if !t.multiQueue {
			return E.New("tun device is not multi-queue")
		}
		flags := unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE
		if t.options.GSO {
			flags |= unix.IFF_VNET_HDR
		}
		var err error
		fd, err = openDevice(t.options.Name, flags)
		return err
	})
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func (t *NativeTun) configure(tunLink netlink.Link) error {
	err := netlink.LinkSetMTU(tunLink, int(t.options.MTU))
	if errors.Is(err, unix.EPERM) {
		return nil
	} else if err != nil {
		return E.Cause(err, "set mtu")
	}
	if !t.options.EXP_ExternalConfiguration {
		if len(t.options.Inet4Address) > 0 {
			for _, address := range t.options.Inet4Address {
				addr4, _ := netlink.ParseAddr(address.String())
				err = netlink.AddrAdd(tunLink, addr4)
				if err != nil && !errors.Is(err, unix.EEXIST) {
					return E.Cause(err, "add address ", address)
				}
			}
		}
		if len(t.options.Inet6Address) > 0 {
			for _, address := range t.options.Inet6Address {
				addr6, _ := netlink.ParseAddr(address.String())
				err = netlink.AddrAdd(tunLink, addr6)
				if err != nil && !errors.Is(err, unix.EEXIST) {
					return E.Cause(err, "add address ", address)
				}
			}
		}
	}

	if t.options.GSO {
		err = t.enableGSO()
		if err != nil {
			if t.options.Logger != nil {
				t.options.Logger.Warn(err)
			}
		}
	}

	var rxChecksumOffload bool
	rxChecksumOffload, err = checkChecksumOffload(t.options.Name, unix.ETHTOOL_GRXCSUM)
	if err == nil && !rxChecksumOffload {
		_ = setChecksumOffload(t.options.Name, unix.ETHTOOL_SRXCSUM)
	}

	if t.options._TXChecksumOffload {
		var txChecksumOffload bool
		txChecksumOffload, err = checkChecksumOffload(t.options.Name, unix.ETHTOOL_GTXCSUM)
		if err != nil {
			return E.Cause(err, "check tx checksum offload")
		}
		if !txChecksumOffload {
			err = setChecksumOffload(t.options.Name, unix.ETHTOOL_STXCSUM)
			if err != nil {
				return E.Cause(err, "set tx checksum offload")
			}
		}
		t.txChecksumOffload = true
	}

	return nil
}

func (t *NativeTun) enableGSO() error {
	vnetHdrEnabled, err := checkVNETHDREnabled(t.tunFd, t.options.Name)
	if err != nil {
		return E.Cause(err, "enable offload: check IFF_VNET_HDR enabled")
	}
	if !vnetHdrEnabled {
		return E.Cause(err, "enable offload: IFF_VNET_HDR not enabled")
	}
	t.vnetHdr = true
	t.tcpGROTable = newTCPGROTable()
	t.udpGROTable = newUDPGROTable()
	err = setTCPOffload(t.tunFd)
	if err != nil {
		if !(errors.Is(err, unix.EPERM) && t.options.FileDescriptor != 0) {
			if t.options.Logger != nil {
				t.options.Logger.Warn(E.Cause(err, "enable offload: set tcp offload"))
			}
			t.gro.disableTCPGRO()
			t.gro.disableUDPGRO()
		}
	} else {
		err = setUDPOffload(t.tunFd)
		if err != nil {
			if t.options.Logger != nil {
				t.options.Logger.Warn(E.Cause(err, "enable offload: set udp offload"))
			}
			t.gro.disableUDPGRO()
		}
	}
	t.readRawConn, err = t.tunFile.SyscallConn()
	if err != nil {
		return E.Cause(err, "enable offload: get raw conn")
	}
	return nil
}

func (t *NativeTun) probeTCPGRO() error {
	probeAddr := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if len(t.options.Inet4Address) > 0 {
		probeAddr = t.options.Inet4Address[0].Addr()
	}
	ipPort := netip.AddrPortFrom(probeAddr, 0)
	fingerprint := []byte("sing-tun-probe-tun-gro")
	segmentSize := len(fingerprint)
	iphLen := 20
	tcphLen := 20
	totalLen := iphLen + tcphLen + segmentSize
	bufs := make([][]byte, 2)
	for i := range bufs {
		bufs[i] = make([]byte, virtioNetHdrLen+totalLen, virtioNetHdrLen+(totalLen*2))
		ipv4H := header.IPv4(bufs[i][virtioNetHdrLen:])
		ipv4H.Encode(&header.IPv4Fields{
			SrcAddr:  ipPort.Addr(),
			DstAddr:  ipPort.Addr(),
			Protocol: unix.IPPROTO_TCP,
			// Use a zero value TTL as best effort means to reduce chance of
			// probe packet leaking further than it needs to.
			TTL:         0,
			TotalLength: uint16(totalLen),
		})
		tcpH := header.TCP(bufs[i][virtioNetHdrLen+iphLen:])
		tcpH.Encode(&header.TCPFields{
			SrcPort:    ipPort.Port(),
			DstPort:    ipPort.Port(),
			SeqNum:     1 + uint32(i*segmentSize),
			AckNum:     1,
			DataOffset: 20,
			Flags:      header.TCPFlagAck,
			WindowSize: 3000,
		})
		copy(bufs[i][virtioNetHdrLen+iphLen+tcphLen:], fingerprint)
		ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
		pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ipv4H.SourceAddressSlice(), ipv4H.DestinationAddressSlice(), uint16(tcphLen+segmentSize))
		pseudoCsum = checksum.Checksum(bufs[i][virtioNetHdrLen+iphLen+tcphLen:], pseudoCsum)
		tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))
	}
	_, err := t.BatchWrite(bufs, virtioNetHdrLen)
	if err != nil {
		return E.Cause(err, "batch write")
	}
	return nil
}

func (t *NativeTun) Name() (string, error) {
	var ifr [unix.IFNAMSIZ + 64]byte
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(t.tunFd),
		uintptr(unix.TUNGETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return "", os.NewSyscallError("ioctl TUNGETIFF", errno)
	}
	return unix.ByteSliceToString(ifr[:]), nil
}

func (t *NativeTun) Start() error {
	if t.options.FileDescriptor == 0 {
		if !t.options.EXP_ExternalConfiguration && t.options.NetNs == "" {
			t.options.InterfaceMonitor.RegisterMyInterface(t.options.Name)
		}
		err := t.runInOwnedNamespace(t.start)
		if err != nil {
			return err
		}
	}
	// The kernel rejects writes with EIO while the device is not up (tun_get_user),
	// so the probe must run after LinkSetUp.
	if t.vnetHdr && t.gro.canTCPGRO() {
		err := t.probeTCPGRO()
		if err != nil {
			t.gro.disableTCPGRO()
			t.gro.disableUDPGRO()
			if t.options.Logger != nil {
				t.options.Logger.Warn(E.Cause(err, "disabled TUN TCP & UDP GRO due to GRO probe error"))
			}
		}
	}
	return nil
}

func (t *NativeTun) start() error {
	tunLink, err := netlink.LinkByName(t.options.Name)
	if err != nil {
		return E.Cause(err, "find tun interface")
	}

	err = netlink.LinkSetUp(tunLink)
	if err != nil {
		return E.Cause(err, "set tun up")
	}

	if t.options.EXP_ExternalConfiguration {
		return nil
	}

	// The kernel uses max(all, interface) as the effective rp_filter value, so
	// writing loose mode here relaxes an inherited strict mode but tightens a
	// disabled one, where loose mode still drops replies whose source has no
	// route on any interface.
	rpFilter := 0
	for _, procPath := range []string{
		"/proc/sys/net/ipv4/conf/all/rp_filter",
		"/proc/sys/net/ipv4/conf/" + t.options.Name + "/rp_filter",
	} {
		content, readErr := os.ReadFile(procPath)
		if readErr != nil {
			continue
		}
		value, parseErr := strconv.Atoi(strings.TrimSpace(string(content)))
		if parseErr != nil {
			continue
		}
		rpFilter = max(rpFilter, value)
	}
	if rpFilter == 1 {
		_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+t.options.Name+"/rp_filter", []byte("2"), 0o644)
	}

	if t.options.IPRoute2TableIndex == 0 {
		tableIndex, selectErr := chooseRouteTableIndex()
		if selectErr != nil {
			return E.Cause(selectErr, "select tun route table")
		}
		t.options.IPRoute2TableIndex = tableIndex
	}

	err = t.setRoute(tunLink)
	if err != nil {
		return E.Cause(err, "set routes")
	}

	err = t.unsetRules()
	if err != nil {
		return E.Cause(err, "cleanup rules")
	}
	err = t.setRules()
	if err != nil {
		return E.Errors(E.Cause(err, "set rules"), t.unsetRules())
	}

	if t.options.ManageLinuxResolved() {
		err = t.setSearchDomainForSystemdResolved()
		if err != nil {
			return E.Cause(err, "set search domain")
		}
	}

	if t.options.AutoRoute && runtime.GOOS == "android" {
		t.interfaceCallback = t.options.InterfaceMonitor.RegisterCallback(t.routeUpdate)
	}
	return nil
}

func (t *NativeTun) Close() error {
	t.resolved.stop()
	t.routeAccess.Lock()
	t.ownedRoutes.closed = true
	t.routeAccess.Unlock()
	// Unregistering does not drain callbacks already copied by the monitor.
	// Seal ownership before any teardown; those callbacks may clear but never
	// reinstall rules after this point.
	t.ruleAccess.Lock()
	t.ownedRules.closed = true
	t.ruleAccess.Unlock()
	if t.interfaceCallback != nil {
		t.options.InterfaceMonitor.UnregisterCallback(t.interfaceCallback)
	}
	if t.options.EXP_ExternalConfiguration {
		err := common.Close(common.PtrOrNil(t.tunFile))
		if t.networkNamespace != nil {
			err = E.Errors(err, t.networkNamespace.close())
		}
		return err
	}
	var networkErr error
	result := closeNativeTunResources(func() error {
		networkErr = t.runInOwnedNamespace(func() error {
			// Rules do not disappear with the TUN fd. Remove them before any
			// potentially slow resolver subprocess can consume the stop grace.
			rulesErr := t.unsetRules()
			t.unsetAddresses()
			return E.Errors(rulesErr, t.unsetRoute())
		})
		return networkErr
	}, func() error {
		if t.options.ManageLinuxResolved() {
			return t.unsetSearchDomainForSystemdResolved()
		}
		return nil
	}, func() error {
		return common.Close(common.PtrOrNil(t.tunFile))
	})
	if networkErr == nil && t.networkNamespace != nil {
		result = E.Errors(result, t.networkNamespace.close())
	}
	return result
}

func (t *NativeTun) Read(p []byte) (n int, err error) {
	if t.vnetHdr {
		if t.writeBuffer == nil {
			t.writeBuffer = make([]byte, virtioNetHdrLen+gsoMaxSize)
		}
		n, err = t.tunFile.Read(t.writeBuffer)
		if err != nil {
			if errors.Is(err, syscall.EBADFD) {
				err = os.ErrClosed
			}
			return
		}
		var sizes [1]int
		n, err = handleVirtioRead(t.writeBuffer[:n], [][]byte{p}, sizes[:], 0)
		if err != nil {
			return
		}
		if n == 0 {
			return
		}
		n = sizes[0]
		return
	} else {
		return t.tunFile.Read(p)
	}
}

// handleVirtioRead splits in into bufs, leaving offset bytes at the front of
// each buffer. It mutates sizes to reflect the size of each element of bufs,
// and returns the number of packets read.
func handleVirtioRead(in []byte, bufs [][]byte, sizes []int, offset int) (int, error) {
	payload, options, err := parseVirtioRead(in)
	if err != nil {
		return 0, err
	}
	return GSOSplit(payload, options, bufs, sizes, offset)
}

func parseVirtioRead(in []byte) ([]byte, GSOOptions, error) {
	var hdr virtioNetHdr
	err := hdr.decode(in)
	if err != nil {
		return nil, GSOOptions{}, err
	}
	in = in[virtioNetHdrLen:]

	options, err := hdr.toGSOOptions()
	if err != nil {
		return nil, GSOOptions{}, err
	}

	// Don't trust HdrLen from the kernel as it can be equal to the length
	// of the entire first packet when the kernel is handling it as part of a
	// FORWARD path. Instead, parse the transport header length and add it onto
	// CsumStart, which is synonymous for IP header length.
	if options.GSOType == GSOUDPL4 {
		options.HdrLen = options.CsumStart + 8
	} else if options.GSOType != GSONone {
		if len(in) <= int(options.CsumStart+12) {
			return nil, GSOOptions{}, errors.New("packet is too short")
		}

		tcpHLen := uint16(in[options.CsumStart+12] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			// A TCP header must be between 20 and 60 bytes in length.
			return nil, GSOOptions{}, fmt.Errorf("tcp header len is invalid: %d", tcpHLen)
		}
		options.HdrLen = options.CsumStart + tcpHLen
	}

	return in, options, nil
}

func gsoSegmentCount(payload []byte, options GSOOptions) int {
	dataLength := len(payload) - int(options.HdrLen)
	if options.GSOType == GSONone || options.GSOSize == 0 || dataLength < int(options.GSOSize) {
		return 1
	}
	return (dataLength + int(options.GSOSize) - 1) / int(options.GSOSize)
}

func (t *NativeTun) Write(p []byte) (n int, err error) {
	if t.vnetHdr {
		_, err = t.BatchWrite([][]byte{p}, virtioNetHdrLen)
		if err != nil {
			return
		}
		n = len(p)
		return
	}
	return t.tunFile.Write(p)
}

func (t *NativeTun) FrontHeadroom() int {
	if t.vnetHdr {
		return virtioNetHdrLen
	}
	return 0
}

func (t *NativeTun) BatchSize() int {
	if !t.vnetHdr {
		return 1
	}
	/* // Not works on some devices: https://github.com/SagerNet/sing-box/issues/1605
	batchSize := int(gsoMaxSize/t.options.MTU) * 2
	if batchSize > idealBatchSize {
		batchSize = idealBatchSize
	}
	return batchSize*/
	return idealBatchSize
}

func (t *NativeTun) BatchRead(buffers [][]byte, offset int, readN []int) (int, error) {
	t.readAccess.Lock()
	defer t.readAccess.Unlock()
	var used int
	if t.pendingLength > 0 {
		pendingLength := t.pendingLength
		t.pendingLength = 0
		count, err := handleVirtioRead(t.pendingBuffer[:pendingLength], buffers, readN, offset)
		if err != nil {
			return count, err
		}
		used = count
	}
	for used < len(buffers) {
		if t.writeBuffer == nil {
			t.writeBuffer = make([]byte, virtioNetHdrLen+gsoMaxSize)
		}
		var (
			readLength int
			err        error
		)
		if used == 0 {
			readLength, err = t.tunFile.Read(t.writeBuffer)
			if err != nil {
				return 0, err
			}
		} else {
			readLength, err = t.readNonblocking(t.writeBuffer)
			if err != nil || readLength == 0 {
				break
			}
		}
		payload, options, parseErr := parseVirtioRead(t.writeBuffer[:readLength])
		if parseErr != nil {
			if used > 0 {
				break
			}
			return 0, parseErr
		}
		if used > 0 && gsoSegmentCount(payload, options) > len(buffers)-used {
			t.writeBuffer, t.pendingBuffer = t.pendingBuffer, t.writeBuffer
			t.pendingLength = readLength
			break
		}
		count, splitErr := GSOSplit(payload, options, buffers[used:], readN[used:], offset)
		if splitErr != nil {
			if used > 0 {
				break
			}
			return count, splitErr
		}
		used += count
	}
	return used, nil
}

func (t *NativeTun) readNonblocking(buffer []byte) (int, error) {
	var (
		readLength int
		readErr    error
	)
	controlErr := t.readRawConn.Read(func(fd uintptr) bool {
		readLength, readErr = syscall.Read(int(fd), buffer)
		return true
	})
	if controlErr != nil {
		return 0, controlErr
	}
	if readErr != nil {
		if readErr == syscall.EAGAIN {
			return 0, nil
		}
		return 0, readErr
	}
	return readLength, nil
}

func (t *NativeTun) BatchWrite(buffers [][]byte, offset int) (int, error) {
	t.writeAccess.Lock()
	defer func() {
		if t.vnetHdr {
			t.tcpGROTable.reset()
			t.udpGROTable.reset()
		}
		t.writeAccess.Unlock()
	}()
	var (
		errs  error
		total int
	)
	t.gsoToWrite = t.gsoToWrite[:0]
	if t.vnetHdr {
		err := handleGRO(buffers, offset, t.tcpGROTable, t.udpGROTable, t.gro, &t.gsoToWrite)
		if err != nil {
			return 0, err
		}
		offset -= virtioNetHdrLen
	} else {
		for i := range buffers {
			t.gsoToWrite = append(t.gsoToWrite, i)
		}
	}
	for _, toWrite := range t.gsoToWrite {
		n, err := t.tunFile.Write(buffers[toWrite][offset:])
		if errors.Is(err, syscall.EBADFD) {
			return total, os.ErrClosed
		}
		if err != nil {
			errs = errors.Join(errs, err)
		} else {
			total += n
		}
	}
	return total, errs
}

func (t *NativeTun) TXChecksumOffload() bool {
	return t.txChecksumOffload
}

func (t *NativeTun) rawFileDescriptor() int {
	return t.tunFd
}

// os.NewFile registers a non-blocking descriptor with the runtime poller, which then wakes an
// idle thread for every packet the engine loop is already waiting for on its own epoll.
func (t *NativeTun) detachRuntimePoller() error {
	duplicated, err := unix.FcntlInt(uintptr(t.tunFd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	previous := t.tunFile
	t.tunFd = duplicated
	t.tunFile = newUnpolledFile(duplicated, "tun")
	t.readRawConn, err = t.tunFile.SyscallConn()
	return E.Errors(err, previous.Close())
}

func (t *NativeTun) vnetHeaderEnabled() (bool, error) {
	return checkVNETHDREnabled(t.tunFd, t.options.Name)
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

func (t *NativeTun) UpdateRouteOptions(tunOptions Options) error {
	return t.runInOwnedNamespace(func() error {
		t.routeAccess.Lock()
		defer t.routeAccess.Unlock()
		if t.ownedRoutes.closed {
			return E.New("routing route owner is closed")
		}
		if tunOptions.Name != t.options.Name || tunOptions.NetNs != t.options.NetNs ||
			tunOptions.FileDescriptor != t.options.FileDescriptor ||
			tunOptions.EXP_ExternalConfiguration != t.options.EXP_ExternalConfiguration {
			return E.New("route update cannot change native device ownership")
		}
		if t.options.FileDescriptor > 0 {
			return nil
		} else if t.options.EXP_ExternalConfiguration || !t.options.AutoRoute {
			t.ruleAccess.Lock()
			t.options = tunOptions
			t.ruleAccess.Unlock()
			return nil
		}
		tunLink, err := netlink.LinkByName(t.options.Name)
		if err != nil {
			return E.Cause(err, "find tun interface")
		}
		err = t.ownedRoutes.replace(func() ([]netlink.Route, error) {
			return routesForOptions(tunOptions, tunLink)
		}, netlink.RouteAdd, netlink.RouteDel)
		if err != nil {
			return err
		}
		// Publish only after a complete installation. A failed update leaves
		// old options and any precise cleanup debt, not a claimed new state.
		t.ruleAccess.Lock()
		t.options = tunOptions
		t.ruleAccess.Unlock()
		return nil
	})
}

func (t *NativeTun) routes(tunLink netlink.Link) ([]netlink.Route, error) {
	return routesForOptions(t.options, tunLink)
}

func routesForOptions(options Options, tunLink netlink.Link) ([]netlink.Route, error) {
	routeRanges, err := options.BuildAutoRouteRanges(false)
	if err != nil {
		return nil, E.Cause(err, "build auto route ranges")
	}
	// Do not create gateway on linux by default
	gateway4, gateway6 := options.Inet4GatewayAddr(), options.Inet6GatewayAddr()
	return common.Map(routeRanges, func(it netip.Prefix) netlink.Route {
		var gateway net.IP
		if it.Addr().Is4() && !gateway4.IsUnspecified() {
			gateway = gateway4.AsSlice()
		} else if it.Addr().Is6() && !gateway6.IsUnspecified() {
			gateway = gateway6.AsSlice()
		}
		return netlink.Route{
			Dst:       prefixToIPNet(it),
			Gw:        gateway,
			LinkIndex: tunLink.Attrs().Index,
			Table:     options.IPRoute2TableIndex,
		}
	}), nil
}

func (t *NativeTun) nextIndex6() int {
	ruleList, err := netlink.RuleList(netlink.FAMILY_V6)
	if err != nil {
		return -1
	}
	var minIndex int
	for _, rule := range ruleList {
		if rule.Priority > 0 && (minIndex == 0 || rule.Priority < minIndex) {
			minIndex = rule.Priority
		}
	}
	minIndex--
	return minIndex
}

func (t *NativeTun) rules() []*netlink.Rule {
	if !t.options.AutoRoute {
		if len(t.options.Inet6Address) > 0 {
			it := netlink.NewRule()
			it.Priority = t.nextIndex6()
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET6
			it.OifName = t.options.Name
			return []*netlink.Rule{it}
		}
		return nil
	}

	var p4, p6 bool
	var pRule int
	if len(t.options.Inet4Address) > 0 {
		p4 = true
		pRule += 1
	}
	if len(t.options.Inet6Address) > 0 {
		p6 = true
		pRule += 1
	}
	if pRule == 0 {
		return []*netlink.Rule{}
	}

	var rules []*netlink.Rule
	var it *netlink.Rule

	excludeRanges := t.options.ExcludedRanges()

	ruleStart := t.options.IPRoute2RuleIndex
	priority := ruleStart
	priority6 := priority

	if t.options.AutoRedirectMarkMode {
		inputMark := effectiveMark(t.options.AutoRedirectInputMark, DefaultAutoRedirectInputMark, DefaultAutoRedirectInputMarkAndroid)
		outputMark := effectiveMark(t.options.AutoRedirectOutputMark, DefaultAutoRedirectOutputMark, DefaultAutoRedirectOutputMarkAndroid)
		resetMark := effectiveMark(t.options.AutoRedirectResetMark, DefaultAutoRedirectResetMark, DefaultAutoRedirectResetMarkAndroid)
		tproxyMark := effectiveMark(t.options.AutoRedirectTProxyMark, DefaultAutoRedirectTProxyMark, DefaultAutoRedirectTProxyMarkAndroid)
		markMask := int(inputMark | outputMark | resetMark | tproxyMark)
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Mark = outputMark
			it.MarkSet = true
			it.Mask = markMask
			it.Goto = priority + 2
			it.Family = unix.AF_INET
			rules = append(rules, it)
			priority++

			it = netlink.NewRule()
			it.Priority = priority
			it.Mark = inputMark
			it.MarkSet = true
			it.Mask = markMask
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET
			rules = append(rules, it)
			priority++

			it = netlink.NewRule()
			it.Priority = priority
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Mark = outputMark
			it.MarkSet = true
			it.Mask = markMask
			it.Goto = priority6 + 2
			it.Family = unix.AF_INET6
			rules = append(rules, it)
			priority6++

			it = netlink.NewRule()
			it.Priority = priority6
			it.Mark = inputMark
			it.MarkSet = true
			it.Mask = markMask
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET6
			rules = append(rules, it)
			priority6++

			it = netlink.NewRule()
			it.Priority = priority6
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
		if p4 {
			it = netlink.NewRule()
			it.Priority = t.options.IPRoute2AutoRedirectFallbackRuleIndex
			it.Mark = outputMark
			it.MarkSet = true
			it.Mask = markMask
			it.Invert = true
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = t.options.IPRoute2AutoRedirectFallbackRuleIndex
			it.Mark = outputMark
			it.MarkSet = true
			it.Mask = markMask
			it.Invert = true
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
		return rules
	}

	nopPriority := ruleStart + 10
	for _, excludeRange := range excludeRanges {
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.UIDRange = netlink.NewRuleUIDRange(excludeRange.Start, excludeRange.End)
			it.Goto = nopPriority
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.UIDRange = netlink.NewRuleUIDRange(excludeRange.Start, excludeRange.End)
			it.Goto = nopPriority
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
	}
	if len(excludeRanges) > 0 {
		if p4 {
			priority++
		}
		if p6 {
			priority6++
		}
	}
	if len(t.options.IncludeInterface) > 0 {
		matchPriority := priority + 2
		matchPriority6 := priority6 + 2
		for _, includeInterface := range t.options.IncludeInterface {
			if p4 {
				it = netlink.NewRule()
				it.Priority = priority
				it.IifName = includeInterface
				it.Goto = matchPriority
				it.Family = unix.AF_INET
				rules = append(rules, it)
			}
			if p6 {
				it = netlink.NewRule()
				it.Priority = priority6
				it.IifName = includeInterface
				it.Goto = matchPriority6
				it.Family = unix.AF_INET6
				rules = append(rules, it)
			}
		}
		if p4 {
			priority++
		}
		if p6 {
			priority6++
		}
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Family = unix.AF_INET
			it.Goto = nopPriority
			rules = append(rules, it)
			priority++

			it = netlink.NewRule()
			it.Priority = matchPriority
			it.Family = unix.AF_INET
			rules = append(rules, it)
			priority++
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Family = unix.AF_INET6
			it.Goto = nopPriority
			rules = append(rules, it)
			priority6++

			it = netlink.NewRule()
			it.Priority = matchPriority6
			it.Family = unix.AF_INET6
			rules = append(rules, it)
			priority6++
		}
	} else if len(t.options.ExcludeInterface) > 0 {
		for _, excludeInterface := range t.options.ExcludeInterface {
			if p4 {
				it = netlink.NewRule()
				it.Priority = priority
				it.IifName = excludeInterface
				it.Goto = nopPriority
				it.Family = unix.AF_INET
				rules = append(rules, it)
			}
			if p6 {
				it = netlink.NewRule()
				it.Priority = priority6
				it.IifName = excludeInterface
				it.Goto = nopPriority
				it.Family = unix.AF_INET6
				rules = append(rules, it)
			}
		}

		if p4 {
			priority++
		}
		if p6 {
			priority6++
		}
	}

	if runtime.GOOS == "android" && t.options.InterfaceMonitor.AndroidVPNEnabled() {
		const protectedFromVPN = 0x20000
		if p4 {
			it = netlink.NewRule()
			if t.options.InterfaceMonitor.OverrideAndroidVPN() {
				it.Mark = protectedFromVPN
				it.MarkSet = true
			}
			it.Mask = protectedFromVPN
			it.Priority = priority
			it.Family = unix.AF_INET
			it.Goto = nopPriority
			rules = append(rules, it)
			priority++
		}
		if p6 {
			it = netlink.NewRule()
			if t.options.InterfaceMonitor.OverrideAndroidVPN() {
				it.Mark = protectedFromVPN
				it.MarkSet = true
			}
			it.Mask = protectedFromVPN
			it.Family = unix.AF_INET6
			it.Priority = priority6
			it.Goto = nopPriority
			rules = append(rules, it)
			priority6++
		}
	}

	if t.options.StrictRoute {
		if !p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Family = unix.AF_INET
			it.Type = unix.FR_ACT_UNREACHABLE
			rules = append(rules, it)
			priority++
		}
		if !p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Family = unix.AF_INET6
			it.Type = unix.FR_ACT_UNREACHABLE
			rules = append(rules, it)
			priority6++
		}
	}

	if runtime.GOOS != "android" {
		if p4 {
			for _, address := range t.options.Inet4Address {
				it = netlink.NewRule()
				it.Priority = priority
				it.Dst = address.Masked()
				it.Table = t.options.IPRoute2TableIndex
				it.Family = unix.AF_INET
				rules = append(rules, it)
			}
			priority++

			it = netlink.NewRule()
			it.Priority = priority
			it.Table = t.options.IPRoute2TableIndex
			it.SuppressPrefixlen = 0
			it.Family = unix.AF_INET
			rules = append(rules, it)
			priority++
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Table = t.options.IPRoute2TableIndex
			it.SuppressPrefixlen = 0
			it.Family = unix.AF_INET6
			rules = append(rules, it)
			priority6++
		}
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Invert = true
			it.Dport = netlink.NewRulePortRange(53, 53)
			it.Table = unix.RT_TABLE_MAIN
			it.SuppressPrefixlen = 0
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Invert = true
			it.Dport = netlink.NewRulePortRange(53, 53)
			it.Table = unix.RT_TABLE_MAIN
			it.SuppressPrefixlen = 0
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
	}
	if p4 {
		it = netlink.NewRule()
		it.Priority = priority
		it.IifName = t.options.Name
		it.Goto = nopPriority
		it.Family = unix.AF_INET
		rules = append(rules, it)
		priority++

		it = netlink.NewRule()
		it.Priority = priority
		it.Invert = true
		it.IifName = "lo"
		it.Table = t.options.IPRoute2TableIndex
		it.Family = unix.AF_INET
		rules = append(rules, it)

		it = netlink.NewRule()
		it.Priority = priority
		it.IifName = "lo"
		it.Src = netip.PrefixFrom(netip.IPv4Unspecified(), 32)
		it.Table = t.options.IPRoute2TableIndex
		it.Family = unix.AF_INET
		rules = append(rules, it)

		for _, address := range t.options.Inet4Address {
			it = netlink.NewRule()
			it.Priority = priority
			it.IifName = "lo"
			it.Src = address.Masked()
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		// priority++
	}
	if p6 {
		it = netlink.NewRule()
		it.Priority = priority6
		it.IifName = t.options.Name
		it.Goto = nopPriority
		it.Family = unix.AF_INET6
		rules = append(rules, it)
		priority6++

		for _, address := range t.options.Inet6Address {
			it = netlink.NewRule()
			it.Priority = priority6
			it.IifName = "lo"
			it.Src = address.Masked()
			it.Table = t.options.IPRoute2TableIndex
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
		priority6++

		it = netlink.NewRule()
		it.Priority = priority6
		it.IifName = "lo"
		it.Src = netip.PrefixFrom(netip.IPv6Unspecified(), 1)
		it.Goto = nopPriority
		it.Family = unix.AF_INET6
		rules = append(rules, it)

		it = netlink.NewRule()
		it.Priority = priority6
		it.IifName = "lo"
		it.Src = netip.PrefixFrom(netip.AddrFrom16([16]byte{0: 128}), 1)
		it.Goto = nopPriority
		it.Family = unix.AF_INET6
		rules = append(rules, it)
		priority6++

		it = netlink.NewRule()
		it.Priority = priority6
		it.Table = t.options.IPRoute2TableIndex
		it.Family = unix.AF_INET6
		rules = append(rules, it)
		// priority6++
	}
	if p4 {
		it = netlink.NewRule()
		it.Priority = nopPriority
		it.Family = unix.AF_INET
		rules = append(rules, it)
	}
	if p6 {
		it = netlink.NewRule()
		it.Priority = nopPriority
		it.Family = unix.AF_INET6
		rules = append(rules, it)
	}
	return rules
}

func (t *NativeTun) setRoute(tunLink netlink.Link) error {
	t.routeAccess.Lock()
	defer t.routeAccess.Unlock()
	return t.ownedRoutes.replace(func() ([]netlink.Route, error) {
		return t.routes(tunLink)
	}, netlink.RouteAdd, netlink.RouteDel)
}

func (t *NativeTun) setRules() error {
	t.ruleAccess.Lock()
	defer t.ruleAccess.Unlock()
	if t.ownedRules.closed {
		return E.New("routing rule owner is closed")
	}
	return t.ownedRules.install(t.rules(), netlink.RuleAdd)
}

func (t *NativeTun) unsetRoute() error {
	t.routeAccess.Lock()
	defer t.routeAccess.Unlock()
	// No link lookup or regenerated options: a disappeared interface must not
	// prevent retrying the exact receipts left by this owner.
	return t.ownedRoutes.clear(netlink.RouteDel)
}

func (t *NativeTun) unsetRules() error {
	t.ruleAccess.Lock()
	defer t.ruleAccess.Unlock()
	return t.ownedRules.clear(netlink.RuleDel)
}

func (t *NativeTun) unsetAddresses() {
	if t.options.FileDescriptor > 0 {
		return
	}
	tunLink, err := netlink.LinkByName(t.options.Name)
	if err != nil {
		return
	}
	for _, address := range t.options.Inet4Address {
		addr, _ := netlink.ParseAddr(address.String())
		_ = netlink.AddrDel(tunLink, addr)
	}
	for _, address := range t.options.Inet6Address {
		addr, _ := netlink.ParseAddr(address.String())
		_ = netlink.AddrDel(tunLink, addr)
	}
}

func (t *NativeTun) resetRules() error {
	t.ruleAccess.Lock()
	defer t.ruleAccess.Unlock()
	return t.ownedRules.reset(t.rules, netlink.RuleAdd, netlink.RuleDel)
}

func (t *NativeTun) routeUpdate(_ *control.Interface, flags int) {
	if flags&FlagAndroidVPNUpdate == 0 {
		return
	}
	err := t.resetRules()
	if err != nil {
		if t.options.Logger != nil {
			t.options.Logger.Error(E.Cause(err, "reset route"))
		}
	}
}

func (t *NativeTun) setSearchDomainForSystemdResolved() error {
	if !t.options.ManageLinuxResolved() {
		return nil
	}
	ctlPath, err := exec.LookPath("resolvectl")
	if err != nil {
		return nil
	}
	dnsAddress, err := t.options.DNSServerAddress()
	if err != nil {
		return err
	}
	return t.resolved.configure(resolvedCommand(ctlPath), t.options.Name, common.Map(dnsAddress, netip.Addr.String))
}

func (t *NativeTun) unsetSearchDomainForSystemdResolved() error {
	if !t.options.ManageLinuxResolved() {
		return nil
	}
	ctlPath, err := exec.LookPath("resolvectl")
	if err != nil {
		return nil
	}
	return t.resolved.close(resolvedCommand(ctlPath), t.options.Name)
}
