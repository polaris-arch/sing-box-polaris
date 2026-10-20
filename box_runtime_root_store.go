package box

import (
 "context"
 "errors"
 "math"

 "github.com/sagernet/sing-box/adapter"
 roots "github.com/sagernet/sing-box/common/certificate"
 "github.com/sagernet/sing-box/internal/runtimegraph"
 "github.com/sagernet/sing/common"
 "github.com/sagernet/sing/common/json"
 C "github.com/sagernet/sing-box/constant"
)

// Watcher allocation follows configured inputs; immutable consumer generations
// follow the one captured snapshot. Recreating the watcher for every revision
// would change its namespace digest indefinitely and lose old anchor ownership.
func(s *Box)prepareRuntimeRootStore(ctx context.Context,g *preparedRuntimeGraph,identity RuntimeIdentity)error{
 options:=common.PtrValueOrDefault(g.options.Certificate)
 encoded,err:=json.Marshal(options);if err!=nil{return err}
 fingerprint:="certificate-store:"+runtimeDigest(encoded)
 c:=s.runtime
 c.access.Lock()
 var resource *runtimeResource
 for _,old:=range c.resources{if old.kind=="certificate-store"&&old.fingerprint==fingerprint{resource=old;break}}
 if resource==nil&&(c.stopped||len(c.catalog)>=runtimeResourceLimit||c.resourceSequence==math.MaxUint64){c.access.Unlock();return errors.New("certificate store resource capacity exhausted")}
 var id adapter.RuntimeResourceID
 if resource==nil{c.resourceSequence++;id=adapter.RuntimeResourceID{Incarnation:identity.Incarnation,Sequence:c.resourceSequence}}
 c.access.Unlock()
 created:=resource==nil
 if created{
  dependency,err:=c.stable.owner.Acquire();if err!=nil{return err}
  resource=&runtimeResource{id:id,kind:"certificate-store",fingerprint:fingerprint,components:make(map[string]*runtimeComponent)}
  resource.owner,err=runtimegraph.NewResourceOwner(c.ctx,id,[]adapter.RuntimeResourceLease{dependency},func()error{return resource.scope.Close()})
  dependency.Release();if err!=nil{return err}
  resource.scope=adapter.NewScope(resource.owner.Context(),s.logger)
  g.created=append(g.created,resource)
  c.access.Lock();c.catalog[id]=resource;c.access.Unlock()
 }
 reservation,err:=resource.owner.Acquire();if err!=nil{return err}
 g.construction=append(g.construction,reservation)
 g.rootResource=resource
 if created{
  receiver:=adapter.ContextWithConstructionScope(resource.owner.Context(),resource.scope)
  receiver=adapter.ContextWithRuntimeResourceSource(receiver,resource.owner)
  receiver=adapter.ContextWithRuntimePreparation(receiver)
  store,err:=roots.NewStore(receiver,s.logFactory.NewLogger("certificate"),options);if err!=nil{return err}
  resource.rootStore=store
  resource.addRuntimeStop(store.RuntimeStop,nil)
  for _,stage:=range adapter.ListStartStages{if err:=ctx.Err();err!=nil{return err};if err:=store.PrepareRuntime(stage,resource.scope);err!=nil{return err}}
 }
 snapshot,err:=resource.rootStore.Snapshot(ctx);if err!=nil{return err}
 g.rootSnapshot=snapshot;g.rootDigest=snapshot.Digest()
 return nil
}

// TLS-bearing constructors snapshot roots. Their reverse dependency closures
// then rebuild through normal cohort hashing. Physical TUN inputs do not capture
// certificate pools and must not be replaced merely for a trust-store refresh.
func runtimeBindRootFingerprints(nodes []runtimeDependencyNode,configs map[string]runtimeNodeOptions,digest [32]byte){
 for i:=range nodes{
  config:=configs[nodes[i].name]
  consumes:=nodes[i].name=="http-manager"||config.service!=nil||config.provider!=nil||(config.endpoint!=nil&&config.endpoint.Type!=C.TypeWireGuard)||config.outbound!=nil||config.transport!=nil
  if config.inbound!=nil&&config.inbound.Type!=C.TypeTun{consumes=true}
  if consumes{nodes[i].fingerprint=runtimeDigest(append(append([]byte(nodes[i].fingerprint),0),digest[:]...))}
 }
}

