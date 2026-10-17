//go:build with_tailscale && windows

package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/directorywindows"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"golang.org/x/sys/windows"
)

const windowsProcessTimeout = 70 * time.Second

// The fixture uses the same real strict decoder, source/VCS/envelope validation,
// whole-config activation and path resolver as box.New before native acquisition.
// This covers activation + directory IO, not tsnet/network/helper end-to-end.
type windowsTestEndpointRegistry struct{}

func (windowsTestEndpointRegistry) OptionTypes() []string { return []string{C.TypeTailscale} }
func (windowsTestEndpointRegistry) CreateOptions(kind string) (any, bool) {
	if kind == C.TypeTailscale {
		return new(option.TailscaleEndpointOptions), true
	}
	return nil, false
}

func windowsTestManagedWriter(root, server string) (*directoryLease, error) {
	nonce, err := newDirectoryNonce()
	if err != nil {
		return nil, err
	}
	logical := filepath.Join(root, "tailscale", server)
	taildrop := filepath.Join(logical, "Taildrop")
	raw, err := json.Marshal(map[string]any{"polaris_windows_directory": map[string]any{"version": 1, "root": root, "run_nonce": nonce, "expected_source": C.SourceRevision}, "endpoints": []any{map[string]any{"type": C.TypeTailscale, "tag": server, "state_directory": logical, "taildrop_directory": taildrop}}})
	if err != nil {
		return nil, err
	}
	ctx := service.ContextWith[option.EndpointOptionsRegistry](context.Background(), windowsTestEndpointRegistry{})
	var options option.Options
	if err := options.UnmarshalJSONContext(ctx, raw); err != nil {
		return nil, fmt.Errorf("test activation decode: %w", err)
	}
	prepared, err := directorywindows.Prepare(ctx, options, PoisonDirectoryDomain)
	if err != nil {
		return nil, fmt.Errorf("test activation: %w", err)
	}
	mapping := adapter.TailscaleDirectoryMappingFromContext(prepared)
	if mapping == nil || !mapping.Domain().Active() {
		return nil, fmt.Errorf("test activation produced no capability")
	}
	physical, _, ok := mapping.Resolve(logical, taildrop)
	if !ok || physical != filepath.Join(root, "tailscale-windows-v1", server) {
		return nil, fmt.Errorf("test activation mapping mismatch")
	}
	actual, lease, err := acquireMappedDirectory(logical, physical)
	if err != nil {
		return nil, err
	}
	if actual != physical || !lease.Managed {
		_ = lease.releaseHandles()
		return nil, fmt.Errorf("test activation did not select managed target")
	}
	return lease, nil
}

func windowsTestSignal(path, nonce string) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(nonce), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func windowsTestHasSignal(path, nonce string) (bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return string(data) == nonce, nil
}

func windowsProcessFile(root, nonce, phase string) string {
	return filepath.Join(root, "process-"+nonce+"."+phase)
}

type (
	windowsProcessReady  struct{ Nonce, Mode, Identity, Incarnation, Epoch, ControlName, LockName string }
	windowsProcessOutput struct {
		mu     sync.Mutex
		buffer bytes.Buffer
	}
)

func (b *windowsProcessOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}
func (b *windowsProcessOutput) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type windowsTestProcess struct {
	cmd         *exec.Cmd
	cancel      context.CancelFunc
	done        chan struct{}
	err         error
	output      *windowsProcessOutput
	root, nonce string
	ready       windowsProcessReady
}

func windowsTestStartProcess(t *testing.T, root, mode string, extra ...string) *windowsTestProcess {
	t.Helper()
	nonce, err := newDirectoryNonce()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), windowsProcessTimeout)
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestWindowsDirectoryProcessChild$", "-test.v", "-test.timeout=65s")
	for _, e := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(e), "POLARIS_DIRECTORY_CHILD_") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "POLARIS_DIRECTORY_CHILD_ROOT="+root, "POLARIS_DIRECTORY_CHILD_NONCE="+nonce, "POLARIS_DIRECTORY_CHILD_MODE="+mode)
	cmd.Env = append(cmd.Env, extra...)
	output := new(windowsProcessOutput)
	cmd.Stdout, cmd.Stderr = output, output
	p := &windowsTestProcess{cmd: cmd, cancel: cancel, done: make(chan struct{}), output: output, root: root, nonce: nonce}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-p.done:
		case <-time.After(10 * time.Second):
			t.Error("test child did not terminate after cancellation")
		}
	})
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(windowsProcessFile(root, nonce, "ready"))
		if err == nil {
			if err := json.Unmarshal(data, &p.ready); err != nil {
				t.Fatal(err)
			}
			if p.ready.Nonce != nonce || p.ready.Mode != mode {
				t.Fatal("child ready did not bind request")
			}
			if mode != "reject" && (p.ready.Identity == "" || !validDirectoryNonce(p.ready.Incarnation) || !validDirectoryNonce(p.ready.Epoch)) {
				t.Fatal("child ready lacked physical generation")
			}
			return p
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-p.done:
			if _, err := os.Stat(windowsProcessFile(root, nonce, "ready")); err == nil {
				continue
			}
			t.Fatalf("child exited without native ready: %v\n%s", p.err, output.text())
		case <-deadline.C:
			t.Fatalf("child ready timeout\n%s", output.text())
		case <-ticker.C:
		}
	}
}

func (p *windowsTestProcess) signal(t *testing.T, phase string) {
	t.Helper()
	if err := windowsTestSignal(windowsProcessFile(p.root, p.nonce, phase), p.nonce); err != nil {
		t.Fatal(err)
	}
}

func (p *windowsTestProcess) awaitSignal(t *testing.T, phase string) {
	t.Helper()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	path := windowsProcessFile(p.root, p.nonce, phase)
	for {
		ready, err := windowsTestHasSignal(path, p.nonce)
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		select {
		case <-p.done:
			if ready, err := windowsTestHasSignal(path, p.nonce); err == nil && ready {
				return
			}
			t.Fatalf("child exited without %s: %v\n%s", phase, p.err, p.output.text())
		case <-deadline.C:
			t.Fatalf("child %s timeout\n%s", phase, p.output.text())
		case <-ticker.C:
		}
	}
}

func (p *windowsTestProcess) wait(t *testing.T, killed bool) {
	t.Helper()
	select {
	case <-p.done:
		if killed && p.err == nil {
			t.Fatal("crash returned ordinary success")
		}
		if !killed && p.err != nil {
			t.Fatalf("child failed: %v\n%s", p.err, p.output.text())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("child exit timeout\n%s", p.output.text())
	}
}

func (p *windowsTestProcess) close(t *testing.T) {
	t.Helper()
	p.signal(t, "close")
	p.awaitSignal(t, "closed")
	p.wait(t, false)
}

func (p *windowsTestProcess) kill(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	p.wait(t, true)
}

// Real test-only retirement custody: root admission EX + lifetime EX + original
// target DELETE handle. It performs no deletion or synthetic production receipt.
func windowsTestRetirementCustody(path string) (_ *directoryLease, resultErr error) {
	l, err := openDirectoryAdmission(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, l.releaseHandles())
		}
	}()
	if unsafe, err := l.domainUnsafe(); err != nil || unsafe {
		return nil, fmt.Errorf("retirement revoked/unknown: %v", err)
	}
	l.targetName = filepath.Base(path)
	read, err := l.openPrivate(l.root, l.targetName, true, windows.FILE_OPEN, false)
	if err != nil {
		return nil, err
	}
	l.targetID, err = windowsInspect(read, true)
	err = errors.Join(err, windows.CloseHandle(read))
	if err != nil {
		return nil, err
	}
	marker, err := l.readMarker(directoryControlStem(l.targetName) + ".jsonl")
	if err != nil {
		return nil, err
	}
	if marker.Phase != "Open" || marker.DirectoryVolume != l.targetID.Volume || marker.DirectoryFileID != l.targetID.hex() {
		return nil, fmt.Errorf("retirement generation mismatch")
	}
	l.lockName = "directory-" + l.targetID.key() + ".lock"
	l.lifetime, err = l.openPrivate(l.control, l.lockName, false, windows.FILE_OPEN, true)
	if err != nil {
		return nil, err
	}
	l.lifetimeID, err = windowsInspect(l.lifetime, false)
	if err != nil {
		return nil, err
	}
	if err := windowsLock(l.lifetime, true); err != nil {
		return nil, err
	}
	l.lifetimeHeld = true
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	l.target, err = windows.CreateFile(wide, windows.DELETE|windows.READ_CONTROL|windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	id, err := windowsInspect(l.target, true)
	if err != nil {
		return nil, err
	}
	if id != l.targetID {
		return nil, fmt.Errorf("retirement target replaced")
	}
	if err := windowsRequirePrivate(l.target, l.ownerSID); err != nil {
		return nil, err
	}
	stamp, err := l.readPrivate(l.target, directoryIncarnationStamp, 34)
	if err != nil {
		return nil, err
	}
	if string(stamp) != marker.Incarnation+"\n" {
		return nil, fmt.Errorf("retirement stamp mismatch")
	}
	l.Identity = windowsDirectoryIdentity(l.rootID, l.targetID)
	l.Incarnation, l.Epoch = marker.Incarnation, marker.DirectoryEpoch
	return l, nil
}

func TestWindowsDirectoryProcessChild(t *testing.T) {
	root, nonce, mode := os.Getenv("POLARIS_DIRECTORY_CHILD_ROOT"), os.Getenv("POLARIS_DIRECTORY_CHILD_NONCE"), os.Getenv("POLARIS_DIRECTORY_CHILD_MODE")
	if root == "" {
		t.Skip("independent process entry needs explicit fixture")
	}
	if !validDirectoryNonce(nonce) {
		t.Fatal("invalid process nonce")
	}
	path := filepath.Join(root, "tailscale-windows-v1", "node")
	var lease *directoryLease
	var err error
	switch mode {
	case "writer", "reject":
		lease, err = windowsTestManagedWriter(root, "node")
	case "retirement":
		lease, err = windowsTestRetirementCustody(path)
	default:
		t.Fatal("invalid child mode")
	}
	ready := windowsProcessReady{Nonce: nonce, Mode: mode}
	if mode == "reject" {
		if err == nil {
			_ = lease.releaseHandles()
			t.Fatal("expected actual admission rejection")
		}
		if strings.Contains(err.Error(), "test activation") {
			t.Fatal("activation failure cannot substitute for native negative control", err)
		}
		if want := os.Getenv("POLARIS_DIRECTORY_CHILD_REJECT_CONTAINS"); want != "" && !strings.Contains(err.Error(), want) {
			t.Fatalf("wrong native rejection: %v", err)
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		defer lease.releaseHandles()
		ready.Identity, ready.Incarnation, ready.Epoch = lease.Identity, lease.Incarnation, lease.Epoch
		ready.ControlName, ready.LockName = lease.controlName, lease.lockName
	}
	data, err := json.Marshal(ready)
	if err != nil {
		t.Fatal(err)
	}
	if err := windowsTestSignal(windowsProcessFile(root, nonce, "ready"), string(data)); err != nil {
		t.Fatal(err)
	}
	if mode == "reject" {
		return
	}
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	blocked, poisoned := false, false
	for {
		has := func(phase string) bool {
			yes, err := windowsTestHasSignal(windowsProcessFile(root, nonce, phase), nonce)
			if err != nil {
				t.Fatal(err)
			}
			return yes
		}
		if has("failed-revoke") && !blocked {
			if err := prepareDirectoryLeaseClose(lease, errors.New("injected drain failure")); err == nil {
				t.Fatal("another process's admission EX did not block revoke")
			}
			if lease.target == 0 || lease.lifetime == 0 || !lease.lifetimeHeld {
				t.Fatal("failed revoke released writer custody")
			}
			blocked = true
			if err := windowsTestSignal(windowsProcessFile(root, nonce, "revoke-blocked"), nonce); err != nil {
				t.Fatal(err)
			}
		}
		if has("poison") && !poisoned {
			if err := PoisonDirectoryDomain(filepath.Dir(path)); err != nil {
				t.Fatal(err)
			}
			poisoned = true
			if err := windowsTestSignal(windowsProcessFile(root, nonce, "poisoned"), nonce); err != nil {
				t.Fatal(err)
			}
		}
		if has("close") {
			if mode == "retirement" {
				err = lease.releaseHandles()
			} else {
				if blocked {
					if err := prepareDirectoryLeaseClose(lease, errors.New("retry failed drain revocation")); err != nil {
						t.Fatal(err)
					}
					poisoned = true
				}
				err = lease.Close()
				wantError := poisoned || os.Getenv("POLARIS_DIRECTORY_CHILD_EXPECT_CLOSE_ERROR") == "1"
				if (err != nil) != wantError {
					t.Fatalf("unexpected real Close result: %v", err)
				}
				err = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			if lease.target != 0 || lease.lifetime != 0 {
				t.Fatal("close retained uncertain custody")
			}
			if err := windowsTestSignal(windowsProcessFile(root, nonce, "closed"), nonce); err != nil {
				t.Fatal(err)
			}
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("child command deadline expired")
		case <-ticker.C:
		}
	}
}

func TestWindowsDirectoryCrossProcessWriterAndRetirementExclude(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tailscale-windows-v1", "node")
	writer := windowsTestStartProcess(t, root, "writer")
	if l, err := windowsTestRetirementCustody(path); err == nil {
		_ = l.releaseHandles()
		t.Fatal("retirement passed live independent writer")
	}
	writer.close(t)
	retired := windowsTestStartProcess(t, root, "retirement")
	if l, err := acquireDirectoryLease(path); err == nil {
		_ = l.Close()
		t.Fatal("writer passed independent retirement")
	}
	retired.close(t)
	next := windowsTestStartProcess(t, root, "writer")
	next.close(t)
}

func TestWindowsDirectoryCrossProcessRevokeFailureRetainsOldLease(t *testing.T) {
	root := t.TempDir()
	writer := windowsTestStartProcess(t, root, "writer")
	admission, err := openDirectoryAdmission(filepath.Join(root, "tailscale-windows-v1"))
	if err != nil {
		t.Fatal(err)
	}
	defer admission.releaseHandles()
	writer.signal(t, "failed-revoke")
	writer.awaitSignal(t, "revoke-blocked")
	h, err := admission.openPrivate(admission.control, writer.ready.LockName, false, windows.FILE_OPEN, true)
	if err != nil {
		t.Fatal(err)
	}
	lockErr := windowsLock(h, true)
	if lockErr == nil {
		_ = windowsUnlock(h)
	}
	closeErr := windows.CloseHandle(h)
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if lockErr == nil {
		t.Fatal("old writer lease released after failed revoke")
	}
	if err := admission.releaseHandles(); err != nil {
		t.Fatal(err)
	}
	writer.close(t)
	rejected := windowsTestStartProcess(t, root, "reject", "POLARIS_DIRECTORY_CHILD_REJECT_CONTAINS=permanently revoked")
	rejected.wait(t, false)
}

func TestWindowsDirectoryCrossProcessCrashReopensSameGeneration(t *testing.T) {
	root := t.TempDir()
	old := windowsTestStartProcess(t, root, "writer")
	before := old.ready
	old.kill(t)
	next := windowsTestStartProcess(t, root, "writer")
	if next.ready.Identity != before.Identity || next.ready.Incarnation != before.Incarnation || next.ready.Epoch == before.Epoch {
		t.Fatal("crash reopen changed generation or reused epoch")
	}
	next.close(t)
}

func TestWindowsDirectoryCrossProcessCrashCannotUndoRevocation(t *testing.T) {
	root := t.TempDir()
	old := windowsTestStartProcess(t, root, "writer")
	old.signal(t, "poison")
	old.awaitSignal(t, "poisoned")
	old.kill(t)
	rejected := windowsTestStartProcess(t, root, "reject", "POLARIS_DIRECTORY_CHILD_REJECT_CONTAINS=permanently revoked")
	rejected.wait(t, false)
}

func TestWindowsDirectoryCrossProcessReplacementCannotAdoptOldIdentity(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tailscale-windows-v1", "node")
	old := windowsTestStartProcess(t, root, "writer")
	identity := old.ready.Identity
	old.close(t)
	if err := os.Rename(path, path+"-original"); err != nil {
		t.Fatal(err)
	}
	admission, err := openDirectoryAdmission(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	h, err := admission.openPrivate(admission.root, "node", true, windows.FILE_CREATE, false)
	if err != nil {
		_ = admission.releaseHandles()
		t.Fatal(err)
	}
	id, err := windowsInspect(h, true)
	err = errors.Join(err, windows.CloseHandle(h), admission.releaseHandles())
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(identity, ":"+fmt.Sprint(id.Volume)+":"+id.hex()) {
		t.Fatal("replacement fixture reused physical identity")
	}
	rejected := windowsTestStartProcess(t, root, "reject")
	rejected.wait(t, false)
}

func windowsTestBroadenDACL(t *testing.T, path string) {
	t.Helper()
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(wide, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	original, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := windowsCurrentSID()
	if err != nil {
		t.Fatal(err)
	}
	changed, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)(A;;FW;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := changed.DACL()
	if err != nil {
		t.Fatal(err)
	}
	flags := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, flags, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		acl, _, err := original.DACL()
		if err != nil {
			t.Error(err)
			return
		}
		h, err := windows.CreateFile(wide, windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			t.Error(err)
			return
		}
		if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, flags, nil, nil, acl, nil); err != nil {
			t.Error(err)
		}
		if err := windows.CloseHandle(h); err != nil {
			t.Error(err)
		}
	})
}

func TestWindowsDirectoryCrossProcessDACLRejectsNewOwner(t *testing.T) {
	root := t.TempDir()
	writer := windowsTestStartProcess(t, root, "writer")
	lock := filepath.Join(root, writer.ready.ControlName, writer.ready.LockName)
	writer.close(t)
	windowsTestBroadenDACL(t, lock)
	rejected := windowsTestStartProcess(t, root, "reject", "POLARIS_DIRECTORY_CHILD_REJECT_CONTAINS=unexpected access grants")
	rejected.wait(t, false)
}

func TestWindowsDirectoryCrossProcessOldLeasePoisonsOnDACLChange(t *testing.T) {
	root := t.TempDir()
	writer := windowsTestStartProcess(t, root, "writer", "POLARIS_DIRECTORY_CHILD_EXPECT_CLOSE_ERROR=1")
	windowsTestBroadenDACL(t, filepath.Join(root, writer.ready.ControlName, writer.ready.LockName))
	writer.close(t)
	rejected := windowsTestStartProcess(t, root, "reject", "POLARIS_DIRECTORY_CHILD_REJECT_CONTAINS=permanently revoked")
	rejected.wait(t, false)
}

// Artifact SHA256 is verified by Rust/PowerShell before this exact entry. Ready
// requires actual production activation and native acquisition, not exit code.
func TestWindowsDirectoryInteropChild(t *testing.T) {
	root, nonce := os.Getenv("POLARIS_DIRECTORY_INTEROP_ROOT"), os.Getenv("POLARIS_DIRECTORY_INTEROP_NONCE")
	if root == "" {
		t.Skip("Rust entry requires explicit root and nonce")
	}
	if !validDirectoryNonce(nonce) {
		t.Fatal("invalid interop nonce")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		t.Fatal("interop root must exist")
	}
	lease, err := windowsTestManagedWriter(root, "node")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.releaseHandles()
	if err := windowsTestSignal(filepath.Join(root, "interop-ready"), nonce); err != nil {
		t.Fatal(err)
	}
	t.Log("WINDOWS_DIRECTORY_INTEROP_READY", nonce)
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		closeRequested, err := windowsTestHasSignal(filepath.Join(root, "interop-close"), nonce)
		if err != nil {
			t.Fatal(err)
		}
		if closeRequested {
			poison := os.Getenv("POLARIS_DIRECTORY_INTEROP_POISON") == "1"
			if poison {
				if err := PoisonDirectoryDomain(filepath.Join(root, "tailscale-windows-v1")); err != nil {
					t.Fatal(err)
				}
			}
			err := lease.Close()
			if (err != nil) != poison {
				t.Fatalf("unexpected interop Close: %v", err)
			}
			if lease.target != 0 || lease.lifetime != 0 {
				t.Fatal("interop Close retained uncertain custody")
			}
			if err := windowsTestSignal(filepath.Join(root, "interop-closed"), nonce); err != nil {
				t.Fatal(err)
			}
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("interop close deadline expired")
		case <-ticker.C:
		}
	}
}
