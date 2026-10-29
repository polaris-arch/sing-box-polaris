package certificate

import (
	"context"
	"errors"
	"os"
	"runtime"
)

const RuntimeDirectoryStorageAvailable = runtime.GOOS != "js" && runtime.GOOS != "plan9"

// RuntimeDirectoryIdentity snapshots the opened object, never a lazy pathname
// FileInfo. In particular, Windows os.Stat may defer its file-ID lookup until
// SameFile, when this pathname may already name a replacement or be gone.
func RuntimeDirectoryIdentity(path string) (os.FileInfo, error) {
	file, err := os.OpenFile(path, runtimeStorageDirectoryOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	info, err := runtimeStorageIdentity(file)
	if err == nil && !info.IsDir() {
		return nil, errors.New("certificate storage path is not a directory")
	}
	return info, err
}

// RuntimeRootIdentity resolves relative to the actual retained capability,
// including after its original pathname or alias has changed.
func RuntimeRootIdentity(root *os.Root, name string) (os.FileInfo, error) {
	file, err := root.OpenFile(name, runtimeStorageOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	return runtimeStorageIdentity(file)
}

func runtimeStorageIdentity(file *os.File) (os.FileInfo, error) {
	info, err := file.Stat()
	err = errors.Join(err, file.Close())
	if err != nil {
		return nil, err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return nil, errors.New("certificate storage identity requires a regular file or directory")
	}
	return info, nil
}

// RuntimeStorageBinding reports the actual directory opened by a staged
// provider before cache IO. The owner records it even when validation fails.
type runtimeStorageBindingKey struct{}

func ContextWithRuntimeStorageBinding(ctx context.Context, bind func(os.FileInfo) error) context.Context {
	return context.WithValue(ctx, runtimeStorageBindingKey{}, bind)
}

func BindRuntimeStorage(ctx context.Context, identity os.FileInfo) error {
	bind, _ := ctx.Value(runtimeStorageBindingKey{}).(func(os.FileInfo) error)
	if bind == nil {
		return nil
	} // provider-level fixtures may own their storage directly
	return bind(identity)
}
