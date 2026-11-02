//go:build windows && amd64

package main

// A single durable, SYSTEM-only custody slot survives adapter/owner death.
// This is not another execution purpose or a caller-selected cleanup path.
// Unknown identity gaps retain debt; no timeout/PID disappearance authorizes
// deletion. Reconciliation never emits a positive execution proof.
import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const custodySchema = "polaris-windows-native-custody-v1"
const custodyLimit = 256 << 10
const custodyDirectory = "polaris-native-execution-custody"

var errCustodyReconciled = errors.New("prior native custody exactly reconciled; this invocation issues no proof")

type custodyJob struct {
	Name string `json:"name"`
}
type custodyDirectoryID struct {
	NativePath   string `json:"nativePath"`
	VolumeSerial string `json:"volumeSerial"`
	FileID       string `json:"fileId"`
}
type custodyRecord struct {
	Schema       string             `json:"schema"`
	SourceCommit string             `json:"sourceCommit"`
	SourceTree   string             `json:"sourceTree"`
	RunID        uint64             `json:"runId"`
	RunAttempt   uint64             `json:"runAttempt"`
	Owner        actorFact          `json:"owner"`
	Parent       custodyDirectoryID `json:"parent"`
	Store        custodyDirectoryID `json:"store"`
	CohortID     string             `json:"cohortId"`
	Cohort       *cohortFact        `json:"cohort"`
	Objects      []objectFact       `json:"objects"`
	Jobs         []custodyJob       `json:"jobs"`
	Closed       bool               `json:"closed"`
}
type custody struct {
	parent, directory, lock windows.Handle
	path                    string
	record                  custodyRecord
}

func directoryIdentity(handle windows.Handle) (custodyDirectoryID, error) {
	id, err := handleIdentity(handle)
	if err != nil {
		return custodyDirectoryID{}, err
	}
	name, err := handlePath(handle)
	return custodyDirectoryID{name, fmt.Sprintf("%016x", id.Volume), hex.EncodeToString(id.ID[:])}, err
}

func systemAttributes(directory bool) (*windows.SecurityAttributes, error) {
	text := "O:SYG:SYD:P(A;;FA;;;SY)"
	if directory {
		text = "O:SYG:SYD:P(A;OICI;FA;;;SY)"
	}
	sd, err := windows.SecurityDescriptorFromString(text)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func validateCustody(r custodyRecord, parent string) error {
	if r.Schema != custodySchema || !exactHex(r.SourceCommit, 40) || !exactHex(r.SourceTree, 40) || r.RunID == 0 || r.RunAttempt == 0 || !exactHex(r.CohortID, 32) || r.Owner.SID != systemSID || r.Owner.TokenType != "primary" || r.Owner.ThreadImpersonation || r.Owner.ProcessID == 0 || !exactHex(r.Owner.CreationTime, 16) || len(r.Jobs) > 256 || len(r.Objects) > 2 {
		return errors.New("native custody record identity/bound differs")
	}
	if r.Objects == nil || r.Jobs == nil || r.Owner.CreationTime == strings.Repeat("0", 16) {
		return errors.New("native custody missing typed members/owner incarnation")
	}
	for _, identity := range []custodyDirectoryID{r.Parent, r.Store} {
		if identity.NativePath == "" || !nonzeroCustodyHex(identity.FileID, 32) || !nonzeroCustodyHex(identity.VolumeSerial, 16) {
			return errors.New("native custody parent/store identity missing")
		}
	}
	if r.Cohort == nil {
		if len(r.Objects) != 0 || len(r.Jobs) != 0 {
			return errors.New("custody objects precede recorded cohort identity")
		}
		return nil
	}
	c := r.Cohort
	if c.ID != r.CohortID || c.Path != filepath.Join(parent, "polaris-native-"+r.CohortID) || !nonzeroCustodyHex(c.FileID, 32) || !nonzeroCustodyHex(c.VolumeSerial, 16) || c.OwnerSID != systemSID || !c.ProtectedDACL || !c.SystemOnlyDACL || c.ReparsePoint || !c.CreatedNew || c.FileSystem != "NTFS" {
		return errors.New("native custody cohort identity differs")
	}
	if !strings.EqualFold(filepath.Dir(c.NativePath), r.Parent.NativePath) || c.VolumeSerial != r.Parent.VolumeSerial {
		return errors.New("native custody cohort physical parent/volume differs")
	}
	seen := map[string]bool{}
	ids := map[string]bool{c.FileID: true}
	for _, obj := range r.Objects {
		name := filepath.Base(obj.Path)
		if (name != "sing-box.exe" && name != "libcronet.dll") || seen[name] || ids[obj.FileID] || obj.Path != filepath.Join(c.Path, name) || !strings.EqualFold(filepath.Dir(obj.NativePath), c.NativePath) || obj.VolumeSerial != c.VolumeSerial || !nonzeroCustodyHex(obj.FileID, 32) || !exactHex(obj.SHA256, 64) || obj.Bytes <= 0 || obj.Bytes > objectLimit || obj.OwnerSID != systemSID || !obj.ProtectedDACL || !obj.SystemOnlyDACL || obj.ReparsePoint || obj.LinkCount != 1 || !obj.ShareReadOnly {
			return errors.New("native custody object identity differs")
		}
		seen[name] = true
		ids[obj.FileID] = true
	}
	if len(r.Jobs) > 0 && len(r.Objects) != 2 {
		return errors.New("native process precedes complete held object identities")
	}
	for index, job := range r.Jobs {
		if job.Name != fmt.Sprintf("Global\\PolarisNative-%s-%d", r.CohortID, index) {
			return errors.New("native custody job namespace differs")
		}
	}
	return nil
}

func nonzeroCustodyHex(value string, length int) bool {
	return exactHex(value, length) && value != strings.Repeat("0", length)
}

func openCustody(r request, actor actorFact) (_ *custody, failure error) {
	win, err := windows.GetWindowsDirectory()
	if err != nil {
		return nil, err
	}
	parent := filepath.Join(win, "SystemTemp")
	path := filepath.Join(parent, custodyDirectory)
	parentName, _ := utf16(parent)
	parentHandle, err := windows.CreateFile(parentName, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	c := &custody{parent: parentHandle, path: path}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, c.close())
		}
	}()
	if _, _, _, err = security(parentHandle, false); err != nil {
		return nil, err
	}
	var parentInfo windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(parentHandle, &parentInfo); err != nil || parentInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("custody parent reparse/identity differs")
	}
	fs := make([]uint16, 64)
	if err = windows.GetVolumeInformationByHandle(parentHandle, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))); err != nil || windows.UTF16ToString(fs) != "NTFS" {
		return nil, errors.New("native custody requires the actual NTFS SystemTemp parent")
	}
	attributes, err := systemAttributes(true)
	if err != nil {
		return nil, err
	}
	name, _ := utf16(path)
	err = windows.CreateDirectory(name, attributes)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, err
	}
	directory, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	c.directory = directory
	if _, _, _, err = security(directory, true); err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(directory, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("native custody store reparsed")
	}
	parentID, err := directoryIdentity(parentHandle)
	if err != nil {
		return nil, err
	}
	storeID, err := directoryIdentity(directory)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(filepath.Dir(storeID.NativePath), parentID.NativePath) || storeID.VolumeSerial != parentID.VolumeSerial {
		return nil, errors.New("native custody store left its held physical parent")
	}
	// A fixed finite slot, not a growing per-run archive. Reject alien members.
	entries, err := boundedDirectory(path, 3)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Name() != "owner.lock" && entry.Name() != "custody.json" && entry.Name() != "custody-next.json" {
			return nil, errors.New("native custody store has an unknown member")
		}
	}
	attributes, err = systemAttributes(false)
	if err != nil {
		return nil, err
	}
	lockName, _ := utf16(filepath.Join(path, "owner.lock"))
	c.lock, err = windows.CreateFile(lockName, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, 0, attributes, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("native custody owner/debt is locked: %w", err)
	}
	if _, _, _, err = security(c.lock, true); err != nil {
		return nil, err
	}
	if err = windows.GetFileInformationByHandle(c.lock, &info); err != nil || info.NumberOfLinks != 1 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileSizeHigh != 0 || info.FileSizeLow != 0 {
		return nil, errors.New("native custody lock object differs")
	}
	old, err := c.read("custody.json")
	if err == nil {
		if err = validateCustody(old, parent); err != nil {
			return nil, err
		}
		if old.Parent != parentID || old.Store != storeID {
			return nil, errors.New("native custody physical parent/store changed; debt retained")
		}
		return nil, reconcileBeforeAdmission(func() error { return c.reconcile(old, parent) })
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if _, err = os.Lstat(filepath.Join(path, "custody-next.json")); err == nil || !os.IsNotExist(err) {
		return nil, errors.New("native custody pending record has no trusted current owner; debt blocks admission")
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return nil, err
	}
	c.record = custodyRecord{Schema: custodySchema, SourceCommit: r.SourceCommit, SourceTree: r.SourceTree, RunID: r.RunID, RunAttempt: r.RunAttempt, Owner: actor, Parent: parentID, Store: storeID, CohortID: hex.EncodeToString(random), Objects: []objectFact{}, Jobs: []custodyJob{}}
	if err = c.write(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *custody) read(name string) (r custodyRecord, failure error) {
	file, err := openReadOnlyObject(filepath.Join(c.path, name))
	if err != nil {
		return r, err
	}
	defer func() { failure = errors.Join(failure, file.Close()) }()
	if _, _, _, err = security(windows.Handle(file.Fd()), true); err != nil {
		return r, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil || info.NumberOfLinks != 1 {
		return r, errors.New("custody record is not a single-link object")
	}
	raw, err := io.ReadAll(io.LimitReader(file, custodyLimit+1))
	if err != nil {
		return r, err
	}
	return decodeCustody(raw)
}
func decodeCustody(raw []byte) (r custodyRecord, err error) {
	if len(raw) > custodyLimit || uniqueJSON(raw) != nil {
		return r, errors.New("custody record byte/JSON bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&r)
	if err != nil {
		return r, err
	}
	var original, encoded map[string]any
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&original); err != nil {
		return r, err
	}
	roundtrip, _ := json.Marshal(r)
	decoder = json.NewDecoder(bytes.NewReader(roundtrip))
	decoder.UseNumber()
	if err = decoder.Decode(&encoded); err != nil {
		return r, err
	}
	left, _ := json.Marshal(original)
	right, _ := json.Marshal(encoded)
	if !bytes.Equal(left, right) {
		return r, errors.New("native custody JSON fields/aliases differ")
	}
	return r, nil
}
func reconcileBeforeAdmission(reconcile func() error) error {
	if err := reconcile(); err != nil {
		return fmt.Errorf("native cleanup debt remains: %w", err)
	}
	return errCustodyReconciled
}
func (c *custody) write() error {
	raw, err := json.Marshal(c.record)
	if err != nil || len(raw) > custodyLimit {
		return errors.New("native custody serialization bound")
	}
	next := filepath.Join(c.path, "custody-next.json")
	name, _ := utf16(next)
	attributes, err := systemAttributes(false)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), next)
	n, writeErr := file.Write(raw)
	if n != len(raw) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
	}
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	current, _ := utf16(filepath.Join(c.path, "custody.json"))
	return windows.MoveFileEx(name, current, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func (c *custody) close() error {
	var failures []error
	if c.lock != 0 {
		failures = append(failures, windows.CloseHandle(c.lock))
		c.lock = 0
	}
	if c.directory != 0 {
		failures = append(failures, windows.CloseHandle(c.directory))
		c.directory = 0
	}
	if c.parent != 0 {
		failures = append(failures, windows.CloseHandle(c.parent))
		c.parent = 0
	}
	return errors.Join(failures...)
}

func (c *custody) bindCohort(fact cohortFact) error { c.record.Cohort = &fact; return c.write() }
func (c *custody) bindObjects(core, sidecar objectFact) error {
	c.record.Objects = []objectFact{core, sidecar}
	return c.write()
}
func (c *custody) finish(cleanup cleanupFact) error {
	if !cleanup.AllChildrenWaited || !cleanup.ReadersJoined || cleanup.JobActiveProcesses != 0 || !cleanup.HeldObjectsClosed || !cleanup.CohortRemoved {
		return errors.New("native custody debt retained; cleanup incomplete")
	}
	c.record.Closed = true
	if err := c.write(); err != nil {
		return err
	}
	// No remaining native resources; clearing this slot permits the next owner.
	return os.Remove(filepath.Join(c.path, "custody.json"))
}

func ownerExited(actor actorFact) (exited bool, failure error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, actor.ProcessID)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { failure = errors.Join(failure, windows.CloseHandle(process)) }()
	var birth, exit, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(process, &birth, &exit, &kernel, &user); err != nil {
		return false, err
	}
	if hexTime(birth) != actor.CreationTime {
		return true, nil
	}
	state, err := windows.WaitForSingleObject(process, 0)
	return err == nil && state == windows.WAIT_OBJECT_0, err
}

func jobSecurity(job windows.Handle) error {
	sd, err := windows.GetSecurityInfo(job, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if owner.String() != systemSID || acl == nil || acl.AceCount != 1 || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("owned native job security differs")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err = windows.GetAce(acl, 0, &ace); err != nil {
		return err
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || sid.String() != systemSID || uint32(ace.Mask)&0x001f003f != 0x001f003f {
		return errors.New("owned native job DACL differs")
	}
	return nil
}

func (c *custody) newJob() (windows.Handle, error) {
	if len(c.record.Jobs) >= 256 || len(c.record.Objects) != 2 {
		return 0, errors.New("native job custody identity/count bound")
	}
	name := fmt.Sprintf("Global\\PolarisNative-%s-%d", c.record.CohortID, len(c.record.Jobs))
	c.record.Jobs = append(c.record.Jobs, custodyJob{name})
	if err := c.write(); err != nil {
		return 0, err
	}
	sd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;;GA;;;SY)")
	if err != nil {
		return 0, err
	}
	attributes := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	jobName, _ := utf16(name)
	value, _, createErr := kernel.NewProc("CreateJobObjectW").Call(uintptr(unsafe.Pointer(attributes)), uintptr(unsafe.Pointer(jobName)))
	if value == 0 {
		return 0, createErr
	}
	job := windows.Handle(value)
	if errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(job)
		return 0, errors.New("native job nonce already exists")
	}
	if err = jobSecurity(job); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func reconcileJob(name string, deadline time.Time) (failure error) {
	pointer, _ := utf16(name)
	value, _, openErr := kernel.NewProc("OpenJobObjectW").Call(0x001f003f, 0, uintptr(unsafe.Pointer(pointer)))
	if value == 0 {
		if errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		return openErr
	}
	job := windows.Handle(value)
	defer func() { failure = errors.Join(failure, windows.CloseHandle(job)) }()
	if err := jobSecurity(job); err != nil {
		return err
	}
	if err := windows.TerminateJobObject(job, 1); err != nil {
		return err
	}
	for {
		active, err := jobActive(job)
		if err != nil {
			return err
		}
		if active == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("owned native job remains active; debt retained")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (c *custody) reconcile(r custodyRecord, parent string) error {
	exited, err := ownerExited(r.Owner)
	if err != nil || !exited {
		return errors.Join(err, errors.New("previous exact native owner has not exited"))
	}
	deadline := time.Now().Add(30 * time.Second)
	for _, job := range r.Jobs {
		if !time.Now().Before(deadline) {
			return errors.New("native custody reconciliation total deadline")
		}
		if err = reconcileJob(job.Name, deadline); err != nil {
			return err
		}
	}
	path := filepath.Join(parent, "polaris-native-"+r.CohortID)
	if _, err = os.Lstat(path); err == nil {
		if r.Cohort == nil {
			return errors.New("cohort creation identity was not durably observed; unknown debt cannot authorize deletion")
		}
		pointer, _ := utf16(path)
		handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return err
		}
		id, identityErr := handleIdentity(handle)
		native, pathErr := handlePath(handle)
		_, _, _, securityErr := security(handle, true)
		var info windows.ByHandleFileInformation
		statErr := windows.GetFileInformationByHandle(handle, &info)
		closeErr := windows.CloseHandle(handle)
		if errors.Join(identityErr, pathErr, securityErr, statErr, closeErr) != nil || hex.EncodeToString(id.ID[:]) != r.Cohort.FileID || fmt.Sprintf("%016x", id.Volume) != r.Cohort.VolumeSerial || native != r.Cohort.NativePath || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("exact owned cohort identity differs; debt retained")
		}
		entries, err := boundedDirectory(path, 2)
		if err != nil {
			return err
		}
		known := map[string]objectFact{}
		for _, obj := range r.Objects {
			known[filepath.Base(obj.Path)] = obj
		}
		for _, entry := range entries {
			obj, ok := known[entry.Name()]
			if !ok || entry.IsDir() {
				return errors.New("unknown cohort member identity; debt retained")
			}
			file, err := openReadOnlyObject(obj.Path)
			if err != nil {
				return err
			}
			handle := windows.Handle(file.Fd())
			id, idErr := handleIdentity(handle)
			actualPath, pathErr := handlePath(handle)
			_, _, _, sdErr := security(handle, true)
			var info windows.ByHandleFileInformation
			statErr := windows.GetFileInformationByHandle(handle, &info)
			hash := sha256.New()
			size, readErr := io.Copy(hash, io.LimitReader(file, objectLimit+1))
			closeErr := file.Close()
			if errors.Join(idErr, pathErr, sdErr, statErr, readErr, closeErr) != nil || info.NumberOfLinks != 1 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || actualPath != obj.NativePath || hex.EncodeToString(id.ID[:]) != obj.FileID || fmt.Sprintf("%016x", id.Volume) != obj.VolumeSerial || size != obj.Bytes || hex.EncodeToString(hash.Sum(nil)) != obj.SHA256 {
				return errors.New("exact owned member bytes/FileID differ; debt retained")
			}
		}
		for _, entry := range entries {
			if err = removeOwned(filepath.Join(path, entry.Name())); err != nil {
				return err
			}
		}
		if err = removeOwned(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	// All known jobs are actually inactive/absent and the exact cohort is absent.
	// Pending metadata writes precede effects; they cannot extend this resource set.
	if err = removeOwned(filepath.Join(c.path, "custody-next.json")); err != nil {
		return err
	}
	return os.Remove(filepath.Join(c.path, "custody.json"))
}

func boundedDirectory(path string, limit int) (entries []os.DirEntry, failure error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { failure = errors.Join(failure, file.Close()) }()
	entries, err = file.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > limit {
		return nil, errors.New("native custody directory member bound")
	}
	return entries, nil
}
