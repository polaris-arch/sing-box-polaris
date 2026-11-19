package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

var peerLoopbackIP = [4]byte{127, 0, 0, 1}

func peerBoundSocket(socketType, port int) (fd, actual int, err error) {
	fd, err = unix.Socket(unix.AF_INET, socketType|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return -1, 0, err
	}
	if err = unix.Bind(fd, &unix.SockaddrInet4{Addr: peerLoopbackIP, Port: port}); err == nil {
		var address unix.Sockaddr
		address, err = unix.Getsockname(fd)
		if err == nil {
			return fd, address.(*unix.SockaddrInet4).Port, nil
		}
	}
	return -1, 0, errors.Join(err, unix.Close(fd))
}

func peerFreeUDPPort() (int, error) {
	fd, port, err := peerBoundSocket(unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	return port, unix.Close(fd)
}

func peerMonotonic() float64 {
	var at unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &at) != nil {
		return 0
	}
	return float64(at.Sec) + float64(at.Nsec)/1e9
}

type peerUDPRow struct {
	family, local, remote, state, uid, inode string
}

func peerOwnedSocketInodes(pid int) (map[string]bool, string, error) {
	path := fmt.Sprintf("/proc/%d/fd", pid)
	fdDir, err := os.Open(path)
	if err != nil {
		return nil, "fd_list", err
	}
	defer fdDir.Close()
	entries, err := fdDir.ReadDir(4097)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, "fd_list", err
	}
	if len(entries) > 4096 {
		return nil, "fd_list", fmt.Errorf("UDP observer owner descriptor bound exceeded")
	}
	owned := make(map[string]bool)
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(path, entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, "fd_readlink", err
		}
		if inode, ok := strings.CutPrefix(target, "socket:["); ok {
			if inode, ok := strings.CutSuffix(inode, "]"); ok {
				owned[inode] = true
			}
		}
	}
	return owned, "fd_list", nil
}

func peerUDPPortRows(pid, port int, families ...string) ([]peerUDPRow, string, error) {
	targetPort := fmt.Sprintf(":%04X", port)
	rows := []peerUDPRow{}
	for _, family := range families {
		input, err := os.Open(fmt.Sprintf("/proc/%d/net/%s", pid, family))
		if err != nil {
			return nil, family + "_open", err
		}
		raw, err := readNativeBytes(input, 1<<20)
		err = errors.Join(err, input.Close())
		if err != nil {
			return nil, family + "_read", err
		}
		scanner := bufio.NewScanner(strings.NewReader(string(raw)))
		scanner.Scan() // Kernel table header.
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 {
				return nil, family + "_read", fmt.Errorf("UDP observer malformed socket row")
			}
			if !strings.HasSuffix(fields[1], targetPort) {
				continue
			}
			if len(fields) < 10 {
				return nil, family + "_read", fmt.Errorf("UDP observer malformed socket identity")
			}
			rows = append(rows, peerUDPRow{family, fields[1], fields[2], fields[3], fields[7], fields[9]})
		}
		if err := scanner.Err(); err != nil {
			return nil, family + "_read", err
		}
	}
	return rows, "", nil
}

const peerRelayMaxSources = 16

type peerRelaySlot struct {
	port                int
	fd                  int
	inode               string
	retired             bool
	retirementReason    *string
	received, forwarded [2]int
}

// A sequence dump can omit a live socket. Corroborate an empty port with
// absence of the prior inode from the pinned owner's descriptor snapshot.
func (slot *peerRelaySlot) observeEmptyPort(owned map[string]bool) {
	if slot == nil || slot.retired || owned[slot.inode] {
		return
	}
	reason := "owned_inode_absent_port_unoccupied"
	slot.retired, slot.retirementReason = true, &reason
}

func (slot *peerRelaySlot) matches(inode string) bool {
	return !slot.retired && inode != "" && inode == slot.inode
}

// Only retirement needs a timed wait. The observer keeps the same ordered
// access to its identity state while inspecting the owned process.
type peerRelayStateGate chan struct{}

func (gate peerRelayStateGate) lock()   { gate <- struct{}{} }
func (gate peerRelayStateGate) unlock() { <-gate }

type peerRelay struct {
	front, port, target  int
	stateGate            peerRelayStateGate
	stop, ready, done    chan struct{}
	owner                *peerNativeProcess
	sources              map[int]*peerRelaySlot
	ordered              []*peerRelaySlot
	received             [2]int
	forwarded            [2]atomic.Int64
	retired, quarantined [2]int

	// Socket custody is independent of procfs inspection. A stopped or
	// timed-out worker cannot touch the raw descriptors after revocation.
	socketMu       sync.Mutex
	sockets        []int
	socketCloseErr error

	expectedExit, seenExit, pendingExit, retirementConfirmed, identityUncertain bool
	phase, operation, direction, terminal, failureClass, identityOperation      string
	readStart, readEnd, signalAtStart, gateStart, gateEnd                       any
	predicates, gap                                                             map[string]any
	failures                                                                    []map[string]any
	closeFaults                                                                 []string
}

func startPeerRelay(target int) (*peerRelay, error) {
	fd, port, err := peerBoundSocket(unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	relay := &peerRelay{
		front: fd, port: port, target: target, sockets: []int{fd},
		stateGate: make(peerRelayStateGate, 1),
		stop:      make(chan struct{}), ready: make(chan struct{}), done: make(chan struct{}),
		sources: make(map[int]*peerRelaySlot), phase: "setup", operation: "socket", direction: "none", terminal: "starting",
		failures: []map[string]any{}, closeFaults: []string{},
	}
	go relay.run()
	return relay, nil
}

var errPeerRelayStopped = errors.New("UDP observer socket custody revoked")

func (relay *peerRelay) withSockets(operation func() error) error {
	relay.socketMu.Lock()
	defer relay.socketMu.Unlock()
	if relay.sockets == nil {
		return errPeerRelayStopped
	}
	return operation()
}

func (relay *peerRelay) revokeSockets() error {
	relay.socketMu.Lock()
	defer relay.socketMu.Unlock()
	for _, fd := range relay.sockets {
		relay.socketCloseErr = errors.Join(relay.socketCloseErr, unix.Close(fd))
	}
	relay.sockets = nil
	return relay.socketCloseErr
}

func (relay *peerRelay) bind(owner *peerNativeProcess) error {
	relay.stateGate.lock()
	defer relay.stateGate.unlock()
	if relay.identityUncertain || relay.owner != nil {
		relay.identityUncertain = true
		return fmt.Errorf("UDP observer owner cannot be rebound")
	}
	unlock, err := owner.inspect()
	if err != nil {
		relay.identityUncertain = true
		return err
	}
	defer unlock()
	actual, err := readPeerProc(owner.identity.PID)
	if err != nil || actual.peerProcessIdentity != owner.identity || owner.exited() != nil || owner.pidfd < 0 {
		relay.identityUncertain = true
		return fmt.Errorf("UDP observer exact child identity unavailable")
	}
	relay.owner = owner
	close(relay.ready)
	return nil
}

func (relay *peerRelay) prepareRetirement() error {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case relay.stateGate <- struct{}{}:
	case <-timer.C:
		return fmt.Errorf("UDP observer retirement state unavailable")
	}
	defer relay.stateGate.unlock()
	if relay.identityUncertain {
		return fmt.Errorf("UDP observer owner identity is uncertain")
	}
	if relay.expectedExit || relay.owner == nil {
		return nil
	}
	unlock, err := relay.owner.inspect()
	if err != nil {
		relay.identityUncertain = true
		return err
	}
	defer unlock()
	row, err := readPeerProc(relay.owner.identity.PID)
	if err != nil || relay.owner.exited() != nil || row.peerProcessIdentity != relay.owner.identity {
		relay.identityUncertain = true
		return fmt.Errorf("UDP observer owner retirement identity unavailable")
	}
	relay.expectedExit = true
	return nil
}

func peerSocketRowDiagnostics(rows []peerUDPRow, owned map[string]bool, local, remote string, previous *peerRelaySlot) map[string]any {
	tuples, inodes, categories := map[[4]string]bool{}, map[string]bool{}, map[string]int{}
	for _, row := range rows {
		tuples[[4]string{row.family, row.local, row.remote, row.inode}] = true
		if row.inode != "0" {
			inodes[row.inode] = true
		}
		left, right, custody, prior := "other", "other", "_foreign", "_new"
		ip, _, _ := strings.Cut(row.local, ":")
		if row.local == local {
			left = "exact"
		} else if ip == "00000000" || ip == strings.Repeat("0", 32) {
			left = "wildcard"
		}
		if row.remote == remote {
			right = "relay"
		} else if row.remote == "00000000:0000" || row.remote == strings.Repeat("0", 32)+":0000" {
			right = "unconnected"
		}
		if owned[row.inode] {
			custody = "_owned"
		}
		if previous != nil && previous.inode == row.inode {
			prior = "_prior"
		}
		categories[row.family+"_"+left+"_"+right+custody+prior]++
	}
	return map[string]any{"rows": len(rows), "distinctTuples": len(tuples), "distinctNonzeroInodes": len(inodes), "jointCategories": categories}
}

func (relay *peerRelay) sourceInode(port int, previous *peerRelaySlot) (inode string, err error) {
	owner := relay.owner
	relay.identityOperation = "ordering_gate"
	relay.predicates = map[string]any{
		"slotPresent": previous != nil, "priorSlotRetired": nil,
		"ownerBeforeMatches": nil, "ownerAfterMatches": nil, "sampledSocketInodes": nil, "samePortRows": nil,
		"ipv4Rows": nil, "ipv6Rows": nil, "uniqueIPv4": nil, "localExpected": nil, "rowInOwnerFdSet": nil,
		"remoteAllowed": nil, "priorInodeMatches": nil, "failedPredicate": nil,
	}
	if previous != nil {
		relay.predicates["priorSlotRetired"] = previous.retired
	}
	relay.gateStart = peerMonotonic()
	unlock, err := owner.inspect()
	relay.gateEnd = peerMonotonic()
	if err != nil {
		return "", err
	}
	defer unlock()
	start := peerMonotonic()
	relay.readStart = start
	signal := owner.termSignal
	if signal != nil {
		relay.signalAtStart = signal.MonotonicSec
	}
	defer func() {
		relay.readEnd = peerMonotonic()
		if err == nil || previous == nil || !relay.expectedExit || signal == nil ||
			signal.MonotonicSec == 0 || signal.MonotonicSec > start {
			return
		}
		const permission = "permission"
		allowed := map[unix.Errno]string{unix.EACCES: permission, unix.EPERM: permission, unix.ENOENT: "not_found", unix.ESRCH: "process_missing"}
		var errno unix.Errno
		if !errors.As(err, &errno) || allowed[errno] == "" {
			return
		}
		relay.gap = map[string]any{
			"actor": "udp_observer", "category": "retirement_inspection_unavailable",
			"identityOperation": relay.identityOperation, "errnoClass": allowed[errno], "errno": int(errno),
			"readStartedMonotonic": start, "readFinishedMonotonic": relay.readEnd,
			"sigtermSucceededMonotonic": signal.MonotonicSec, "expectedOwnerExitAtReadStart": true,
			"ownerPID": owner.identity.PID, "ownerStartTicks": owner.identity.StartTicks,
			"previouslyProvenInode": previous.inode, "resolution": "pending_owned_retirement",
			"forwardingDisabled": true, "newSourceAdmissionDisabled": true,
		}
		relay.pendingExit, inode, err = true, "", nil
	}()
	relay.identityOperation = "owner_poll"
	if exited := owner.exited(); exited != nil {
		if !relay.expectedExit || signal == nil || *exited != 0 {
			return "", fmt.Errorf("UDP observer owner exited without exact requested retirement")
		}
		relay.seenExit = true
		return "", nil
	}
	relay.identityOperation = "owner_stat_before"
	before, err := readPeerProc(owner.identity.PID)
	if err != nil {
		return "", err
	}
	relay.predicates["ownerBeforeMatches"] = before.peerProcessIdentity == owner.identity
	if before.peerProcessIdentity != owner.identity {
		relay.predicates["failedPredicate"] = "owner_birth_before"
		return "", fmt.Errorf("UDP observer owner identity changed")
	}
	inodes, operation, err := peerOwnedSocketInodes(owner.identity.PID)
	relay.identityOperation = operation
	if err != nil {
		return "", err
	}
	relay.predicates["sampledSocketInodes"] = len(inodes)
	rows, operation, err := peerUDPPortRows(owner.identity.PID, port, "udp", "udp6")
	relay.identityOperation = operation
	if err != nil {
		return "", err
	}
	relay.identityOperation = "owner_stat_after"
	after, err := readPeerProc(owner.identity.PID)
	if err != nil {
		return "", err
	}
	relay.predicates["ownerAfterMatches"] = after.peerProcessIdentity == owner.identity
	if after.peerProcessIdentity != owner.identity {
		relay.predicates["failedPredicate"] = "owner_birth_after"
		return "", fmt.Errorf("UDP observer owner identity changed")
	}

	relay.identityOperation = "socket_row_cardinality"
	local, remote := fmt.Sprintf("0100007F:%04X", port), fmt.Sprintf("0100007F:%04X", relay.port)
	v4 := 0
	for _, row := range rows {
		if row.family == "udp" {
			v4++
		}
	}
	relay.predicates["samePortRows"], relay.predicates["ipv4Rows"], relay.predicates["ipv6Rows"] = len(rows), v4, len(rows)-v4
	relay.predicates["rowDiagnostics"] = peerSocketRowDiagnostics(rows, inodes, local, remote, previous)
	if len(rows) == 0 {
		previous.observeEmptyPort(inodes)
		return "", nil
	}
	relay.identityOperation = "socket_identity_deduplicate"
	distinct := make(map[peerUDPRow]bool, len(rows))
	for _, row := range rows {
		id, idErr := strconv.ParseUint(row.inode, 10, 64)
		_, uidErr := strconv.ParseUint(row.uid, 10, 64)
		if idErr != nil || uidErr != nil || id == 0 {
			return "", fmt.Errorf("UDP observer malformed socket identity")
		}
		distinct[row] = true
	}
	relay.predicates["distinctSocketRows"], relay.predicates["duplicateSocketRows"] = len(distinct), len(rows)-len(distinct)
	row := rows[0]
	for _, predicate := range []struct {
		name, field string
		good        bool
	}{
		{"single_socket_row", "", len(distinct) == 1},
		{"socket_family", "uniqueIPv4", row.family == "udp"},
		{"socket_local", "localExpected", row.local == local},
		{"socket_owner_inode", "rowInOwnerFdSet", inodes[row.inode]},
		{"socket_remote", "remoteAllowed", row.remote == remote || row.remote == "00000000:0000"},
	} {
		relay.identityOperation = predicate.name
		if predicate.name == "socket_owner_inode" && previous != nil {
			relay.predicates["priorInodeMatches"] = previous.inode == row.inode
		}
		if predicate.field != "" {
			relay.predicates[predicate.field] = predicate.good
		}
		if !predicate.good {
			relay.predicates["failedPredicate"], relay.failureClass = predicate.name, "source_port_occupied_or_unowned"
			return "", fmt.Errorf("UDP observer source is not the exact child socket")
		}
	}
	return row.inode, nil
}

func (relay *peerRelay) source(port int, ipv4 [4]byte, create bool) (*peerRelaySlot, error) {
	relay.identityOperation = "source_address"
	relay.readStart, relay.readEnd, relay.signalAtStart, relay.gateStart, relay.gateEnd = nil, nil, nil, nil, nil
	slot := relay.sources[port]
	relay.predicates = map[string]any{"sourceLoopback": ipv4 == peerLoopbackIP, "slotPresent": slot != nil, "failedPredicate": nil}
	reject := func(operation, predicate, category string) (*peerRelaySlot, error) {
		relay.identityOperation, relay.predicates["failedPredicate"], relay.failureClass = operation, predicate, category
		return nil, fmt.Errorf("UDP observer source identity rejected")
	}
	if ipv4 != peerLoopbackIP {
		return reject("source_address", "source_loopback", "non_loopback_source")
	}
	if relay.gap != nil {
		if slot == nil {
			return reject("quarantine_new_source", "quarantine_new_source", "unowned_source_during_quarantine")
		}
		return nil, nil
	}
	inode, err := relay.sourceInode(port, slot)
	if err != nil {
		return nil, err
	}
	if relay.seenExit || relay.pendingExit {
		if slot == nil {
			return reject("retirement_source_admission", "unowned_retirement_source", "unowned_retirement_source")
		}
		return nil, nil
	}
	relay.identityOperation = "source_slot_continuity"
	if slot != nil {
		if inode == "" {
			return nil, nil
		}
		if !slot.matches(inode) {
			return reject("source_slot_continuity", "source_slot_reused", "source_socket_reused")
		}
		return slot, nil
	}
	if !create || inode == "" {
		return reject("source_slot_continuity", "new_source_unowned", "unowned_source")
	}
	if len(relay.sources) >= peerRelayMaxSources {
		return reject("source_slot_continuity", "source_limit", "source_limit")
	}
	relay.operation = "back_socket"
	err = relay.withSockets(func() error {
		fd, _, err := peerBoundSocket(unix.SOCK_DGRAM, 0)
		if err != nil {
			return err
		}
		relay.sockets = append(relay.sockets, fd)
		if err := unix.Connect(fd, &unix.SockaddrInet4{Addr: peerLoopbackIP, Port: relay.target}); err != nil {
			return err
		}
		slot = &peerRelaySlot{fd: fd, port: port, inode: inode}
		relay.sources[port], relay.ordered = slot, append(relay.ordered, slot)
		return nil
	})
	return slot, err
}

func (relay *peerRelay) forward(fd int, back *peerRelaySlot, buffer []byte) error {
	direction := 0
	relay.direction = "client_to_peer"
	if back != nil {
		direction, relay.direction = 1, "peer_to_client"
	}
	relay.operation, relay.failureClass = "receive", "operation_error"
	var n int
	var source unix.Sockaddr
	err := relay.withSockets(func() error {
		var err error
		n, source, err = unix.Recvfrom(fd, buffer, 0)
		return err
	})
	if err != nil {
		return err
	}
	relay.received[direction]++
	relay.operation = "source_identity"
	sourceAddress, ok := source.(*unix.SockaddrInet4)
	if !ok || back != nil && (sourceAddress.Port != relay.target || sourceAddress.Addr != peerLoopbackIP) {
		relay.identityOperation, relay.failureClass = "peer_address", "unexpected_peer"
		relay.predicates = map[string]any{"peerEndpointMatches": false, "failedPredicate": "peer_endpoint"}
		return fmt.Errorf("UDP observer peer identity changed")
	}
	port, ipv4 := sourceAddress.Port, sourceAddress.Addr
	if back != nil {
		port, ipv4 = back.port, peerLoopbackIP
	}
	slot, err := relay.source(port, ipv4, back == nil)
	if err != nil {
		return err
	}
	if slot == nil {
		if relay.gap != nil {
			relay.quarantined[direction]++
		} else {
			relay.retired[direction]++
		}
		return nil
	}
	slot.received[direction]++
	relay.operation = "send"
	to, fd := unix.Sockaddr(nil), slot.fd
	if back != nil {
		to, fd = &unix.SockaddrInet4{Addr: peerLoopbackIP, Port: slot.port}, relay.front
	}
	var sent int
	err = relay.withSockets(func() error {
		var err error
		sent, err = unix.SendmsgN(fd, buffer[:n], nil, to, 0)
		return err
	})
	if err != nil {
		return err
	}
	if sent != n {
		relay.failureClass = "short_datagram"
		return io.ErrShortWrite
	}
	relay.forwarded[direction].Add(1)
	slot.forwarded[direction]++
	return nil
}

func (relay *peerRelay) run() {
	defer func() {
		_ = relay.revokeSockets()
		close(relay.done)
	}()
	select {
	case <-relay.ready:
	case <-relay.stop:
		relay.stateGate.lock()
		relay.terminal = "stopped"
		relay.stateGate.unlock()
		return
	}
	buffer := make([]byte, 65535)
	for {
		select {
		case <-relay.stop:
			relay.stateGate.lock()
			relay.terminal = "stopped"
			relay.stateGate.unlock()
			return
		default:
		}
		relay.stateGate.lock()
		relay.phase, relay.operation, relay.direction = "active", "selector_select", "none"
		fds := []unix.PollFd{{Fd: int32(relay.front), Events: unix.POLLIN}}
		slots := append([]*peerRelaySlot(nil), relay.ordered...)
		for _, slot := range slots {
			fds = append(fds, unix.PollFd{Fd: int32(slot.fd), Events: unix.POLLIN})
		}
		relay.stateGate.unlock()
		err := relay.withSockets(func() error {
			_, err := unix.Poll(fds, 100)
			return err
		})
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err == nil {
			for index, fd := range fds {
				if fd.Revents == 0 {
					continue
				}
				select {
				case <-relay.stop:
					continue
				default:
				}
				var back *peerRelaySlot
				if index > 0 {
					back = slots[index-1]
				}
				relay.stateGate.lock()
				err = relay.forward(int(fd.Fd), back, buffer)
				relay.stateGate.unlock()
				if err != nil {
					break
				}
			}
		}
		if err == nil {
			continue
		}
		relay.stateGate.lock()
		if errors.Is(err, errPeerRelayStopped) {
			relay.terminal = "stopped"
		} else {
			relay.recordFailure(err)
			relay.terminal = "failed"
		}
		relay.stateGate.unlock()
		return
	}
}

func (relay *peerRelay) recordFailure(err error) {
	var errno unix.Errno
	var code any
	class := "not_os_error"
	if errors.As(err, &errno) {
		code = int(errno)
		class = map[unix.Errno]string{
			unix.ECONNREFUSED: "connection_refused", unix.EBADF: "bad_fd", unix.EINTR: "interrupted",
			unix.EPERM: "permission", unix.EACCES: "permission", unix.ENETUNREACH: "network_unreachable", unix.ETIMEDOUT: "timeout",
		}[errno]
		if class == "" {
			class = "other_os_error"
		}
	}
	failure := relay.failureClass
	if failure == "" {
		failure = "operation_error"
	}
	relay.failures = append(relay.failures, map[string]any{
		"actor": "udp_observer", "phase": relay.phase, "operation": relay.operation,
		"direction": relay.direction, "category": failure, "errnoClass": class, "errno": code, "monotonicSeconds": peerMonotonic(),
		"identityOperation": relay.identityOperation, "identityReadStartedMonotonic": relay.readStart,
		"identityReadFinishedMonotonic": relay.readEnd, "sigtermSucceededAtReadStart": relay.signalAtStart, "expectedOwnerExit": relay.expectedExit,
		"identityGateWaitStartedMonotonic": relay.gateStart, "identityGateWaitFinishedMonotonic": relay.gateEnd, "sourcePredicates": relay.predicates,
	})
}

func (relay *peerRelay) datagrams() [2]int {
	return [2]int{int(relay.forwarded[0].Load()), int(relay.forwarded[1].Load())}
}

func (relay *peerRelay) close(wait time.Duration) (map[string]any, error) {
	close(relay.stop)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-relay.done:
	case <-timer.C:
		faults := []string{"join_failed"}
		closed := relay.revokeSockets() == nil
		if !closed {
			faults = append(faults, "socket_close_failed")
		}
		return map[string]any{
				"actor": "udp_observer", "snapshotUnavailable": true,
				"threadJoined": false, "terminalAcknowledged": false, "allSocketsClosed": closed, "closeFaults": faults,
			},
			fmt.Errorf("UDP observer did not join")
	}

	relay.stateGate.lock()
	defer relay.stateGate.unlock()
	allClosed := relay.revokeSockets() == nil
	if !allClosed {
		relay.closeFaults = append(relay.closeFaults, "socket_close_failed")
	}
	var pid, ticks any
	if relay.owner != nil {
		owner := relay.owner
		pid, ticks = owner.identity.PID, owner.identity.StartTicks
		if relay.pendingExit && relay.expectedExit {
			exit := owner.exited()
			if exit != nil && *exit == 0 {
				relay.pendingExit, relay.seenExit = false, true
			}
		}
		if relay.expectedExit {
			fact := owner.result
			relay.retirementConfirmed = fact != nil && fact.PID == owner.identity.PID && fact.StartIdentity != nil &&
				*fact.StartIdentity == owner.identity && fact.BoundCoreSHA256 != nil && *fact.BoundCoreSHA256 == owner.core &&
				fact.ExitBeforeTerminate == nil && fact.GracefulCleanupProven && len(fact.TerminationActions) == 1 &&
				owner.termSignal != nil && fact.TerminationActions[0] == *owner.termSignal
			if !relay.retirementConfirmed {
				relay.closeFaults = append(relay.closeFaults, "owner_actual_signaled_retirement_not_proven")
			}
		}
	}
	if relay.gap != nil {
		if relay.retirementConfirmed && relay.terminal == "stopped" && allClosed && len(relay.failures) == 0 && len(relay.closeFaults) == 0 {
			relay.gap["resolution"] = "verified_owned_retirement"
		} else {
			relay.closeFaults = append(relay.closeFaults, "retirement_inspection_gap_unresolved")
		}
	}
	sources, retired := []map[string]any{}, 0
	for index, slot := range relay.ordered {
		if slot.retired {
			retired++
		}
		sources = append(sources, map[string]any{
			"ordinal": index, "inode": slot.inode, "retired": slot.retired,
			"retirementReason": slot.retirementReason, "receivedDatagrams": slot.received, "forwardedDatagrams": slot.forwarded,
		})
	}
	observation := map[string]any{
		"actor": "udp_observer", "atomic": false, "identityUncertain": relay.identityUncertain,
		"maximumSources": peerRelayMaxSources, "maximumSockets": peerRelayMaxSources + 1, "sourceCount": len(sources),
		"sourceIdentities": sources, "allSocketsClosed": allClosed, "retiredSources": retired,
		"receivedDatagrams": relay.received, "forwardedDatagrams": relay.datagrams(), "retiredSourceDrops": relay.retired,
		"quarantinedDatagramsNotForwarded": relay.quarantined, "inspectionGap": relay.gap, "expectedOwnerExit": relay.expectedExit,
		"ownerExitObserved": relay.seenExit, "ownerExitPending": relay.pendingExit, "ownerRetirementConfirmed": relay.retirementConfirmed,
		"ownerPID": pid, "ownerStartTicks": ticks, "terminal": relay.terminal, "terminalAcknowledged": true, "threadJoined": true,
		"errors": relay.failures, "closeFaults": relay.closeFaults,
	}
	if relay.terminal != "stopped" || len(relay.failures) != 0 || relay.pendingExit || len(relay.closeFaults) != 0 || relay.identityUncertain {
		return observation, fmt.Errorf("UDP observer cleanup or transport failed")
	}
	return observation, nil
}
