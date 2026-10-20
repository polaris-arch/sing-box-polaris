package route

import (
 "context"
 "github.com/sagernet/sing-box/adapter"
)

// runtimeTask reserves all inherited ownership before publishing a worker.
// Resource-only callers (including retained DNS/transport operations) need the
// same protection as graph callers. The constructor source is intentionally not
// admitted here: this helper continues its caller, it does not create a new root.
func runtimeTask(ctx context.Context, task func(context.Context)) error {
 owned, release, err := adapter.AcquireRuntimeOperation(ctx, nil)
 if err != nil { return err }
 go func() {
  defer release()
  task(owned)
 }()
 return nil
}
