//go:build darwin && cgo

package certificate

import "github.com/sagernet/sing-box/adapter"

type snapshotPlatform struct{anchors *appleAnchors}
func newSnapshotPlatform(pemBytes []byte)(snapshotPlatform,error){anchors,err:=newAppleAnchors(pemBytes);return snapshotPlatform{anchors:anchors},err}
func(p snapshotPlatform)release(){if p.anchors!=nil{p.anchors.Release()}}
var _ adapter.AppleCertificateStore = (*RootSnapshot)(nil)
func(s *RootSnapshot)AppleAnchors()adapter.AppleAnchors{
 s.mu.Lock();defer s.mu.Unlock()
 if s.released||s.state.platform.anchors==nil{return nil}
 return s.state.platform.anchors.Retain()
}
