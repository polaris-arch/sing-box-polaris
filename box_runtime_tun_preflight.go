package box

import (
 "context"
 "crypto/sha256"
 "encoding/hex"

 C "github.com/sagernet/sing-box/constant"
 "github.com/sagernet/sing-box/option"
)

// Save constructor-time closure identities, including actual host inputs.
// Recomputing both sides against today's host would conceal external drift.
func runtimeTunDependencySignatures(ctx context.Context, options option.Options) (map[string]string,error) {
 nodes,configs,err:=runtimeConfigNodes(ctx,runtimeResolveGraphDefaults(options));if err!=nil{return nil,err}
 cohorts,err:=runtimeCohorts(nodes);if err!=nil{return nil,err}
 hashes:=make([]string,len(cohorts));result:=make(map[string]string)
 for index,cohort:=range cohorts{
  hash:=sha256.New();runtimeHashField(hash,cohort.fingerprint)
  for _,dependency:=range cohort.dependencies{runtimeHashField(hash,hashes[dependency])}
  hashes[index]=hex.EncodeToString(hash.Sum(nil))
  for _,name:=range cohort.members{config:=configs[name];if config.inbound!=nil&&config.inbound.Type==C.TypeTun{result[name]=hashes[index]}}
 }
 return result,nil
}
func runtimeTunDependencyChanges(before,after map[string]string) bool {
 if len(before)!=len(after){return true}
 for name,identity:=range before{if after[name]!=identity{return true}}
 return false
}
