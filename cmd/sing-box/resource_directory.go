package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

// The Windows helper supplies its registered drive-absolute configuration
// directory. The process itself stays in the separately protected -D directory.
func withResourceDirectory(ctx context.Context, directory string) (context.Context, error) {
	if directory == "" {
		return ctx, nil
	}
	volume := filepath.VolumeName(directory)
	if runtime.GOOS != "windows" || len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(directory) {
		return nil, errors.New("resource-directory requires an absolute Windows drive directory")
	}
	manager := service.FromContext[filemanager.Manager](ctx)
	if manager == nil {
		ctx = filemanager.WithDefault(ctx, "", "", os.Getuid(), os.Getgid())
		manager = service.FromContext[filemanager.Manager](ctx)
	}
	return service.ContextWith[filemanager.Manager](ctx, &resourceFileManager{
		Manager: manager, directory: filepath.Clean(directory),
	}), nil
}

type resourceFileManager struct {
	filemanager.Manager
	directory string
}

func (m *resourceFileManager) ConfigurationDirectoryPath(name string) string {
	if name == "" {
		name = "."
	}
	return m.BasePath(name)
}

func (m *resourceFileManager) BasePath(name string) string {
	if name == "" || filepath.IsAbs(name) {
		return name
	}
	volume := filepath.VolumeName(name)
	if volume != "" {
		if strings.EqualFold(volume, filepath.VolumeName(m.directory)) {
			return filepath.Join(m.directory, name[len(volume):])
		}
		// The helper's fixed environment has no per-drive (=C:) entries.
		// A different drive therefore used its root before -D was relocated.
		return volume + `\` + name[len(volume):]
	}
	if os.IsPathSeparator(name[0]) {
		return filepath.VolumeName(m.directory) + name
	}
	return filepath.Join(m.directory, name)
}

func (m *resourceFileManager) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return m.Manager.OpenFile(m.BasePath(name), flag, perm)
}

func (m *resourceFileManager) Create(name string) (*os.File, error) {
	return m.Manager.Create(m.BasePath(name))
}

func (m *resourceFileManager) Chown(name string) error {
	return m.Manager.Chown(m.BasePath(name))
}

func (m *resourceFileManager) Mkdir(name string, perm os.FileMode) error {
	return m.Manager.Mkdir(m.BasePath(name), perm)
}

func (m *resourceFileManager) MkdirAll(name string, perm os.FileMode) error {
	return m.Manager.MkdirAll(m.BasePath(name), perm)
}

func (m *resourceFileManager) Remove(name string) error {
	return m.Manager.Remove(m.BasePath(name))
}

func (m *resourceFileManager) RemoveAll(name string) error {
	return m.Manager.RemoveAll(m.BasePath(name))
}

func (m *resourceFileManager) Rename(oldPath string, newPath string) error {
	return m.Manager.Rename(m.BasePath(oldPath), m.BasePath(newPath))
}
