//go:build with_purego && windows

package cronet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var sealedFDSelectorPresent = func() bool {
	_, present := os.LookupEnv("POLARIS_CRONET_LIBRARY_FD")
	return present
}()

type windowsFileID struct {
	Volume uint64
	ID     [16]byte
}

const windowsImageMemoryType uint32 = 0x01000000 // MEM_IMAGE from the actual mapping query
type windowsLibraryCapture struct {
	file   *os.File
	parent windows.Handle
	path   string
	sha256 string
}

func (capture *windowsLibraryCapture) close() error {
	var failures []error
	if capture.file != nil {
		failures = append(failures, capture.file.Close())
	}
	if capture.parent != 0 {
		failures = append(failures, windows.CloseHandle(capture.parent))
	}
	return errors.Join(failures...)
}

func windowsObjectID(handle windows.Handle) (windowsFileID, error) {
	var result windowsFileID
	err := windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&result)), uint32(unsafe.Sizeof(result)))
	return result, err
}

func windowsNativePath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 2)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(buffer)) {
		return "", errors.New("cronet: native object name is truncated")
	}
	return windows.UTF16ToString(buffer[:n]), nil
}

func captureWindowsLibrary(path string) (_ *windowsLibraryCapture, failure error) {
	parentPath, err := windows.UTF16PtrFromString(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	parent, err := windows.CreateFile(parentPath, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("cronet: hold selected parent: %w", err)
	}
	capture := &windowsLibraryCapture{parent: parent, path: path}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, capture.close())
		}
	}()
	var parentInfo windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(parent, &parentInfo); err != nil {
		return nil, err
	}
	if parentInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("cronet: selected parent is a reparse point")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if err != nil {
		return nil, fmt.Errorf("cronet: hold selected object: %w", err)
	}
	capture.file = os.NewFile(uintptr(handle), path)
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return nil, errors.New("cronet: selected DLL must be a single-link non-reparse file")
	}
	var existing windows.Handle
	err = windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, name, &existing)
	if err == nil {
		return nil, errors.New("cronet: selected path was already mapped before object capture")
	}
	if !errors.Is(err, windows.ERROR_MOD_NOT_FOUND) {
		return nil, fmt.Errorf("cronet: query preexisting selected module: %w", err)
	}
	digest := sha256.New()
	if _, err = io.Copy(digest, capture.file); err != nil {
		return nil, err
	}
	capture.sha256 = hex.EncodeToString(digest.Sum(nil))
	return capture, nil
}

func observeWindowsLibrary(module uintptr, capture *windowsLibraryCapture) (LibraryObservation, error) {
	if module == 0 || capture == nil || capture.file == nil || capture.parent == 0 {
		return LibraryObservation{}, errors.New("cronet: selected native object is not retained")
	}
	handle := windows.Handle(capture.file.Fd())
	id, err := windowsObjectID(handle)
	if err != nil {
		return LibraryObservation{}, err
	}
	parentID, err := windowsObjectID(capture.parent)
	if err != nil {
		return LibraryObservation{}, err
	}
	native, err := windowsNativePath(handle)
	if err != nil {
		return LibraryObservation{}, err
	}
	parentNative, err := windowsNativePath(capture.parent)
	if err != nil {
		return LibraryObservation{}, err
	}
	if !strings.EqualFold(filepath.Dir(native), parentNative) {
		return LibraryObservation{}, errors.New("cronet: selected object left its held parent")
	}
	moduleName := make([]uint16, 32768)
	n, err := windows.GetModuleFileName(windows.Handle(module), &moduleName[0], uint32(len(moduleName)))
	if err != nil || n == 0 || n >= uint32(len(moduleName)) {
		return LibraryObservation{}, fmt.Errorf("cronet: actual selected module name unavailable: %w", err)
	}
	modulePath := windows.UTF16ToString(moduleName[:n])
	mappedName := make([]uint16, 32768)
	query := windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetMappedFileNameW")
	count, _, queryErr := query.Call(uintptr(windows.CurrentProcess()), module, uintptr(unsafe.Pointer(&mappedName[0])), uintptr(len(mappedName)))
	if count == 0 || count >= uintptr(len(mappedName)) {
		return LibraryObservation{}, fmt.Errorf("cronet: actual image mapping unavailable: %w", queryErr)
	}
	mappedPath := windows.UTF16ToString(mappedName[:count])
	var memory windows.MemoryBasicInformation
	if err = windows.VirtualQueryEx(windows.CurrentProcess(), module, &memory, unsafe.Sizeof(memory)); err != nil {
		return LibraryObservation{}, err
	}
	if memory.Type != windowsImageMemoryType || memory.AllocationBase != module || !strings.EqualFold(mappedPath, native) || !sameWindowsLibraryPath(modulePath, capture.path) {
		return LibraryObservation{}, errors.New("cronet: actual loaded image differs from the retained selected object")
	}
	if _, err = capture.file.Seek(0, io.SeekStart); err != nil {
		return LibraryObservation{}, err
	}
	digest := sha256.New()
	size, err := io.Copy(digest, capture.file)
	if err != nil {
		return LibraryObservation{}, err
	}
	stat, err := capture.file.Stat()
	if err != nil {
		return LibraryObservation{}, err
	}
	if !stat.Mode().IsRegular() || size != stat.Size() || size <= 0 {
		return LibraryObservation{}, errors.New("cronet: selected object changed while observed")
	}
	if hex.EncodeToString(digest.Sum(nil)) != capture.sha256 {
		return LibraryObservation{}, errors.New("cronet: retained selected object changed across native image load")
	}
	return LibraryObservation{Path: modulePath, Bytes: size, SHA256: hex.EncodeToString(digest.Sum(nil)), Selection: "captured-windows-module-v1", Windows: &WindowsLibraryObservation{
		VolumeSerial: fmt.Sprintf("%016x", id.Volume), FileID: hex.EncodeToString(id.ID[:]), NativePath: native, ModulePath: modulePath, MappedPath: mappedPath,
		ModuleBase: fmt.Sprintf("%016x", module), MemoryType: memory.Type, LoadFlags: uint32(cronetLibrarySearchFlags), ParentFileID: hex.EncodeToString(parentID.ID[:]),
		ParentVolumeSerial: fmt.Sprintf("%016x", parentID.Volume), ShareReadOnly: true,
	}}, nil
}

func ObserveSelectedLibrary(path string) (LibraryObservation, bool, error) {
	return observeSelectedWindowsLibrary(path, "")
}

// The diagnostic's expected digest is checked on the retained object before a
// first native load. Observing an actual module must not execute mismatched DLL
// bytes merely to discover that a user's verification request was invalid.
func ObserveSelectedLibraryVerified(path, expected string) (LibraryObservation, bool, error) {
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		return LibraryObservation{}, true, errors.New("cronet: verified module requires a SHA-256 digest")
	}
	return observeSelectedWindowsLibrary(path, hex.EncodeToString(decoded))
}

func captureWindowsLibraryVerified(name, expected string) (*windowsLibraryCapture, error) {
	capture, err := captureWindowsLibrary(name)
	if err != nil {
		return nil, err
	}
	if expected != "" && capture.sha256 != expected {
		return nil, errors.Join(errors.New("cronet: selected retained DLL digest differs before load"), capture.close())
	}
	return capture, nil
}

func observeSelectedWindowsLibrary(path, expected string) (LibraryObservation, bool, error) {
	if sealedFDSelectorPresent {
		return LibraryObservation{}, true, fmt.Errorf("cronet: explicit sealed library FD is unsupported on this platform")
	}
	_, explicit := os.LookupEnv(cronetLibraryPathEnv)
	if !explicit {
		return LibraryObservation{}, false, nil
	}
	ops := nativeWindowsLibraryOps()
	ops.capture = func(name string) (*windowsLibraryCapture, error) {
		return captureWindowsLibraryVerified(name, expected)
	}
	if err := processWindowsLibrary.load(path, ops); err != nil {
		return LibraryObservation{}, true, err
	}
	processWindowsLibrary.observeMu.Lock()
	defer processWindowsLibrary.observeMu.Unlock()
	observed, err := observeWindowsLibrary(processWindowsLibrary.handle, processWindowsLibrary.capture)
	if err == nil && expected != "" && observed.SHA256 != expected {
		return LibraryObservation{}, true, errors.New("cronet: selected retained DLL digest differs after load")
	}
	return observed, true, err
}
