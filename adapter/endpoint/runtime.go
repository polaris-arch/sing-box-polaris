package endpoint

import "github.com/sagernet/sing-box/adapter"

// Endpoint preparation must leave native listeners, external registration and
// system mutations behind its separately owned staged-effect/activation gate.
// Existing foreground sessions retain the exact endpoint and captured graph.
// RuntimeValidate rejects a legacy instance; a method name alone is insufficient.
type RuntimePreparedEndpoint interface {
 adapter.Endpoint
 RuntimeValidate() error
 RuntimeResourceID() adapter.RuntimeResourceID
 PrepareRuntime(adapter.StartStage,*adapter.Scope) error
}
