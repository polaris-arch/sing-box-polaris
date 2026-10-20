package adapter

import (
 "context"
 "path/filepath"
)

type runtimeRecoveryRootKey struct{}

// ContextWithRuntimeRecoveryRoot records an explicit host state root. This is
// not a custody proof: the journal opener must verify identity, private access,
// symlink/replacement boundaries and exclusive writer ownership. Empty/relative
// roots deliberately provide no capability; process cwd is never a fallback.
func ContextWithRuntimeRecoveryRoot(ctx context.Context, root string) context.Context {
 if root == "" || !filepath.IsAbs(root) { root = "" } else { root = filepath.Clean(root) }
 return context.WithValue(ctx,runtimeRecoveryRootKey{},root)
}
func RuntimeRecoveryRootFromContext(ctx context.Context)(string,bool){
 root,_:=ctx.Value(runtimeRecoveryRootKey{}).(string)
 return root,root!=""
}
