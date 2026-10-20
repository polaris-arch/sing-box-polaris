package daemon

import (
 "context"
 "testing"

 box "github.com/sagernet/sing-box"
 "google.golang.org/grpc/codes"
 "google.golang.org/grpc/status"
)

func TestRuntimePersistenceAcknowledgementAuthenticatesFirst(t *testing.T) {
 service:=new(StartedService)
 if _,err:=service.AcknowledgeRuntimePersistence(context.Background(),nil);status.Code(err)!=codes.Unauthenticated { t.Fatalf("authentication: %v",err) }
 ctx:=ContextWithRuntimeActor(context.Background(),"owner")
 if _,err:=service.AcknowledgeRuntimePersistence(ctx,nil);status.Code(err)!=codes.InvalidArgument { t.Fatalf("nil request: %v",err) }
}
func TestRuntimePersistenceOperationMapsOwnerEvidence(t *testing.T) {
 result:=runtimeOperation(box.RuntimeConfigOperation{PersistenceMode:"app_authoritative_regeneration",OwnerReloadAcknowledged:true,DesiredStateDigest:"digest",DesiredStateRevision:"version"})
 if result.PersistenceMode!="app_authoritative_regeneration" || !result.OwnerReloadAcknowledged || result.DesiredStateDigest!="digest" || result.DesiredStateRevision!="version" { t.Fatal("owner evidence dropped") }
}
