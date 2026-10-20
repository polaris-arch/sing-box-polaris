package box

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "fmt"
 "github.com/sagernet/sing-box/option"
)

// The same immutable cohort fingerprints and dependency resource identities used
// by construction decide whether a physical node is actually replaced. Merely
// being present in a candidate is not a replacement.
func runtimeReplacementNames(ctx context.Context, options option.Options, intents []RuntimeSelectorIntent, rootDigest [32]byte, current []*runtimeResource) (map[string]bool,error) {
 nodes,configs,err:=runtimeConfigNodes(ctx,runtimeResolveGraphDefaults(options));if err!=nil{return nil,err}
 runtimeBindRootFingerprints(nodes,configs,rootDigest)
 runtimeBindSelectorIntentFingerprints(nodes,intents)
 // Explicit selector intents always create a fresh selection generation. Do
 // not claim its downstream closure can reuse an existing physical resource.
 selected:=make(map[string]bool);for _,intent:=range intents{selected["outbound:"+intent.Group]=true}
 cohorts,err:=runtimeCohorts(nodes);if err!=nil{return nil,err}
 byFingerprint:=make(map[string]*runtimeResource)
 for _,resource:=range current{byFingerprint[resource.fingerprint]=resource}
 reused:=make([]*runtimeResource,len(cohorts));replace:=make(map[string]bool)
 for index,cohort:=range cohorts{
  hash:=sha256.New();runtimeHashField(hash,cohort.fingerprint);eligible:=true
  for _,name:=range cohort.members{if selected[name]{eligible=false}}
  for _,dependency:=range cohort.dependencies{
   if reused[dependency]==nil{eligible=false;continue}
   runtimeHashField(hash,fmt.Sprint(reused[dependency].id.Sequence))
  }
  if eligible{reused[index]=byFingerprint[hex.EncodeToString(hash.Sum(nil))]}
  for _,name:=range cohort.members{if reused[index]==nil{replace[name]=true}}
 }
 return replace,nil
}
