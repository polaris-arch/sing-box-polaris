package cachefile

import (
 "context"
 "encoding/json"
 "net/netip"
 "time"

 "github.com/sagernet/bbolt"
 "github.com/sagernet/sing-box/adapter"
)

var bucketRuntimeAuthority = []byte("retained_authority_v1")
type runtimeAuthorityRecord struct { Version uint8; AnchorDatabaseID string; Answer adapter.FakeIPRuntimeAnswer }
func decodeRuntimeAuthority(raw []byte, anchorID string) (adapter.FakeIPRuntimeAnswer,error) {
 var record runtimeAuthorityRecord
 if err:=json.Unmarshal(raw,&record); err!=nil { return record.Answer,err }
 if record.Version!=1 { return record.Answer,ErrFakeIPRuntimeVersion }
 if record.AnchorDatabaseID!=anchorID || !record.Answer.Address.IsValid() || record.Answer.Domain=="" || record.Answer.Revision==0 { return record.Answer,ErrFakeIPRuntimeIdentity }
 return record.Answer,nil
}
func mergeRetainedAuthority(old, next adapter.FakeIPRuntimeAnswer) (adapter.FakeIPRuntimeAnswer,error) {
 if old.Revision>next.Revision { return old,nil }
 if old.Revision==next.Revision { if old.Domain!=next.Domain||old.Address!=next.Address { return old,ErrFakeIPRuntimeConflict }; next.Superseded=next.Superseded||old.Superseded }
 next.Obsolete=true; next.Token=0; next.Pending=0; next.PendingTTL=0; next.ExpiresAt=time.Time{}
 return next,nil
}
func (c *CacheFile) RetainFakeIPRuntimeAuthority(ctx context.Context, records []adapter.FakeIPRuntimeAnswer) error {
 if err:=ctx.Err(); err!=nil { return err }; if len(records)==0 { return nil }
 return c.runtimeUpdate(func(tx *bbolt.Tx) error {
  root,err:=runtimeRoot(tx); if err!=nil { return err }; anchorID:=string(root.Get(keyRuntimeIdentity))
  bucket,err:=root.CreateBucketIfNotExists(bucketRuntimeAuthority); if err!=nil { return err }
  for _,next:=range records {
   if !next.Address.IsValid()||next.Domain==""||next.Revision==0 { return ErrFakeIPRuntimeConflict }
   var old adapter.FakeIPRuntimeAnswer
   if raw:=bucket.Get(next.Address.AsSlice()); len(raw)!=0 { old,err=decodeRuntimeAuthority(raw,anchorID); if err!=nil { return err }; if old.Address!=next.Address { return ErrFakeIPRuntimeIdentity } }
   merged,err:=mergeRetainedAuthority(old,next); if err!=nil { return err }
   if err=putRuntimeJSON(bucket,next.Address.AsSlice(),runtimeAuthorityRecord{1,anchorID,merged}); err!=nil { return err }
  }; return nil
 })
}
func (c *CacheFile) FakeIPRuntimeAuthority(ctx context.Context) ([]adapter.FakeIPRuntimeAnswer,error) {
 if err:=ctx.Err(); err!=nil { return nil,err }; var records []adapter.FakeIPRuntimeAnswer
 err:=c.runtimeView(func(tx *bbolt.Tx) error {
  root,err:=runtimeRoot(tx); if err!=nil { return err }; bucket:=root.Bucket(bucketRuntimeAuthority); if bucket==nil { return nil }
  return bucket.ForEach(func(key,raw []byte) error { answer,err:=decodeRuntimeAuthority(raw,string(root.Get(keyRuntimeIdentity))); if err!=nil { return err }; address,valid:=netip.AddrFromSlice(key); if !valid||address.Unmap()!=answer.Address { return ErrFakeIPRuntimeIdentity }; records=append(records,answer); return nil })
 }); return records,err
}
func (c *CacheFile) PruneFakeIPRuntimeAuthority(ctx context.Context, ranges []netip.Prefix) error {
 if err:=ctx.Err(); err!=nil { return err }
 return c.runtimeUpdate(func(tx *bbolt.Tx) error {
  root,err:=runtimeRoot(tx); if err!=nil { return err }; bucket:=root.Bucket(bucketRuntimeAuthority); if bucket==nil { return nil }; var remove [][]byte
  if err=bucket.ForEach(func(key,raw []byte) error {
   answer,err:=decodeRuntimeAuthority(raw,string(root.Get(keyRuntimeIdentity))); if err!=nil { return err }
   address,valid:=netip.AddrFromSlice(key); if !valid||address.Unmap()!=answer.Address { return ErrFakeIPRuntimeIdentity }
   for _,prefix:=range ranges { if prefix.Contains(answer.Address) { return nil } }; remove=append(remove,append([]byte(nil),key...)); return nil
  }); err!=nil { return err }
  for _,key:=range remove { if err=bucket.Delete(key); err!=nil { return err } }; return nil
 })
}
