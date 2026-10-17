package rule

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "sync"
 "testing"

 "github.com/sagernet/sing-box/adapter"
 C "github.com/sagernet/sing-box/constant"
 "github.com/sagernet/sing/common/logger"
)

func TestRuleSetSnapshotPublicationAndClose(t *testing.T) {
 var s ruleSetPublication
 _, err := s.publish(nil, adapter.RuleSetMetadata{ContainsIPCIDRRule:true}, "first")
 if err != nil { t.Fatal(err) }
 retained := s.loadSnapshot()
 _, err = s.publish(nil, adapter.RuleSetMetadata{}, "second")
 if err != nil { t.Fatal(err) }
 if retained.digest != "first" || !retained.metadata.ContainsIPCIDRRule || retained.revision != 1 { t.Fatal("retired snapshot mutated") }
 if s.loadSnapshot().digest != "second" || s.loadSnapshot().revision != 2 { t.Fatal("new publication missing") }
 s.closePublication()
 if _, err = s.publish(nil, adapter.RuleSetMetadata{}, "late"); err == nil { t.Fatal("publish after Close") }
 if !s.RuleSetStatus().Closed || s.RuleSetStatus().ActiveDigest != "" { t.Fatal("closed snapshot acknowledged") }
 if retained.digest != "first" { t.Fatal("Close mutated reader snapshot") }
}

func TestRuleSetSnapshotConcurrentReadPublishCleanupClose(t *testing.T) {
 var s ruleSetPublication
 var wg sync.WaitGroup
 for worker:=0; worker<4; worker++ { wg.Add(1); go func() { defer wg.Done(); for i:=0;i<1000;i++ {
  p:=s.loadSnapshot()
  if p.digest == "ip" && !p.metadata.ContainsIPCIDRRule { t.Error("mixed generation") }
  _=s.RuleSetStatus()
 } }() }
 for i:=0;i<100;i++ { _, _=s.publish(nil, adapter.RuleSetMetadata{ContainsIPCIDRRule:true}, "ip"); s.cleanupPublication() }
 s.closePublication(); wg.Wait()
}

func TestLocalRuleSetDigestRetainsAcceptedBytesOnInvalidReload(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"rules.json")
 content:=[]byte(`{"version":3,"rules":[{"domain":["old.invalid"]}]}`)
 if err:=os.WriteFile(path,content,0600);err!=nil {t.Fatal(err)}
 s:=&LocalRuleSet{ctx:context.Background(), logger:logger.NOP(), tag:"test", fileFormat:C.RuleSetFormatSource}
 if err:=s.reloadFile(path);err!=nil {t.Fatal(err)}
 sum:=sha256.Sum256(content)
 before:=s.RuleSetStatus()
 if before.ActiveDigest!=hex.EncodeToString(sum[:]) || before.Revision!=1 {t.Fatal(before)}
 if err:=os.WriteFile(path,[]byte(`{"broken"`),0600);err!=nil {t.Fatal(err)}
 if err:=s.reloadFile(path);err==nil {t.Fatal("invalid update accepted")}
 after:=s.RuleSetStatus()
 if after.ActiveDigest!=before.ActiveDigest || after.Revision!=before.Revision || after.LastError=="" {t.Fatal(after)}
 if err:=s.Close();err!=nil {t.Fatal(err)}
 if err:=os.WriteFile(path,content,0600);err!=nil {t.Fatal(err)}
 if err:=s.reloadFile(path);err==nil {t.Fatal("closed set revived")}
}
