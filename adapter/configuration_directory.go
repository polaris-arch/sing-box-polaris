package adapter

import (
	"context"

	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

// ConfigurationDirectoryPath preserves a directory's old cwd meaning when the
// CLI installs a separate resource directory. File paths must keep empty values.
// Callers retain their existing BasePath resolution before using this helper.
func ConfigurationDirectoryPath(ctx context.Context, path string) string {
	if manager, ok := service.FromContext[filemanager.Manager](ctx).(interface {
		ConfigurationDirectoryPath(string) string
	}); ok {
		return manager.ConfigurationDirectoryPath(path)
	}
	return path
}
