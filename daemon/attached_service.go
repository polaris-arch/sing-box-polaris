package daemon

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/service/oomkiller"
)

const defaultAttachedLogMaxLines = 3000

// StartOrReloadService and CloseService must not be called on an attached service.
func NewAttachedService(ctx context.Context) *StartedService {
	instance := attachInstance(ctx)
	// Plans re-prepare candidates through this service; keep the host OOM policy
	// already frozen in the attached Box context instead of resetting it.
	hostOOM, _ := oomkiller.HostOptionsFromContext(ctx)
	s := NewStartedService(ServiceOptions{
		Context:           ctx,
		LogMaxLines:       defaultAttachedLogMaxLines,
		OOMKillerEnabled:  hostOOM.Enabled,
		OOMKillerDisabled: hostOOM.KillerDisabled,
		OOMMemoryLimit:    hostOOM.MemoryLimitOverride,
	})
	s.instance = instance
	s.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTED}
	s.startedAt = time.Now()
	instance.urlTestHistoryStorage.AddUpdateHook(s.urlTestSubscriber)
	if instance.clashMode != nil {
		instance.clashMode.AddUpdateHook(s.clashModeSubscriber)
	}
	instance.logFactory.AttachPlatformWriter(s)
	return s
}
