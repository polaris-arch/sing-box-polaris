//go:build darwin && cgo

package certificate

import (
 "crypto/x509"
 "testing"

 "github.com/sagernet/sing-box/adapter"
 C "github.com/sagernet/sing-box/constant"
)

func TestRootSnapshotNativeAnchorFailureDoesNotInvalidateExistingGeneration(t *testing.T){
 first,_:=rootFixturePEMs(t);pool:=x509.NewCertPool();pool.AppendCertsFromPEM(first)
 id:=adapter.RuntimeResourceID{Incarnation:"apple-root-fixture",Sequence:1}
 active,err:=newRootSnapshot(id,1,C.CertificateStoreNone,pool,first);if err!=nil{t.Fatal(err)};defer active.Release()
 anchors:=active.AppleAnchors();if anchors==nil||anchors.Ref()==nil{t.Fatal("valid native anchors absent")};defer anchors.Release()
 candidate,err:=newRootSnapshot(id,2,C.CertificateStoreNone,pool,[]byte("invalid native anchor PEM"))
 if err==nil||candidate!=nil{if candidate!=nil{candidate.Release()};t.Fatal("failed native generation accepted")}
 retained:=active.AppleAnchors();if retained==nil||retained.Ref()!=anchors.Ref(){t.Fatal("native candidate failure replaced active anchors")};retained.Release()
 active.Release()
 if anchors.Ref()==nil{t.Fatal("snapshot release invalidated retained native handle")}
}
