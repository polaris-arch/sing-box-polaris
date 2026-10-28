package tun

import (
 "net/netip"
 "testing"

 "github.com/sagernet/sing-tun/gtcpip/header"
)

type natIdentityPort struct { *ownershipPort; physical Port }
func (p *natIdentityPort) NATIdentity() Port { return p.physical }

func TestPhysicalNATIdentitySharesNamespace(t *testing.T) {
 physical:=&ownershipPort{}
 first:=&natIdentityPort{ownershipPort:&ownershipPort{},physical:physical}
 second:=&natIdentityPort{ownershipPort:&ownershipPort{},physical:physical}
 a,b:=acquirePortNAT(first),acquirePortNAT(second)
 defer releasePortNAT(a);defer releasePortNAT(b)
 if a!=b||a.port!=physical{t.Fatal("logical generations did not share physical NAT")}
 d,_:=ownershipDispatcher(&ownershipHandler{},&ownershipWriteback{});defer d.Close()
 for _,protocol:=range []uint8{uint8(header.TCPProtocolNumber),uint8(header.UDPProtocolNumber),uint8(header.ICMPv4ProtocolNumber)} {
  address:=netip.MustParseAddr("192.0.2.1")
  peer:=netip.MustParseAddrPort("203.0.113.1:443")
  one,ok:=a.reserve(d,protocol,address,netip.MustParseAddrPort("198.18.0.1:1234"),peer)
  if !ok{t.Fatal("first reservation")}
  two,ok:=b.reserve(d,protocol,address,netip.MustParseAddrPort("198.18.0.2:1234"),peer)
  if !ok{a.cancelReservation(protocol,one);t.Fatal("second reservation")}
  if one.selectorKey.selector==two.selectorKey.selector{t.Fatal("physical selector collision")}
  a.cancelReservation(protocol,one);b.cancelReservation(protocol,two)
 }
}

func TestPhysicalNATAttachmentsDetachExactLogicalPort(t *testing.T) {
 physical:=&ownershipPort{detach:func(Return)error{t.Error("detached canonical identity instead of logical attachment");return nil}}
 d,_:=ownershipDispatcher(&ownershipHandler{},&ownershipWriteback{});defer d.Close()
 f1,f2:=newOwnershipFixture(),newOwnershipFixture()
 p1:=&natIdentityPort{ownershipPort:&ownershipPort{fixture:f1},physical:physical}
 p2:=&natIdentityPort{ownershipPort:&ownershipPort{fixture:f2},physical:physical}
 f1.port=p1;f2.port=p2
 detached1,detached2:=make(chan struct{}),make(chan struct{})
 p1.detach=func(Return)error{close(detached1);return nil};p2.detach=func(Return)error{close(detached2);return nil}
 root1,root2:=f1.flow(),f2.flow()
 u1,u2:=d.natFor(p1,root1),d.natFor(p2,root2)
 if u1==nil||u2==nil{t.Fatal("attach")}
 if u1.returnPath.nat!=u2.returnPath.nat{t.Fatal("NAT split")}
 f1.retire();root1.Release();u1.release();waitOwnership(t,u1.returnPath.completion);waitOwnership(t,detached1);waitOwnership(t,f1.closed)
 d.portsAccess.Lock();firstGone:=d.ports[p1]==nil;secondKept:=d.ports[p2]==u2.returnPath;d.portsAccess.Unlock()
 if !firstGone||!secondKept{t.Fatal("logical attachment census corrupted")}
 portNATAccess.Lock();kept:=portNATs[physical]==u2.returnPath.nat;portNATAccess.Unlock();if !kept{t.Fatal("first detach removed shared NAT")}
 f2.retire();root2.Release();u2.release();waitOwnership(t,u2.returnPath.completion);waitOwnership(t,detached2);waitOwnership(t,f2.closed)
 portNATAccess.Lock();_,exists:=portNATs[physical];portNATAccess.Unlock();if exists{t.Fatal("last detach retained shared NAT")}
}

func TestNilPhysicalNATIdentityKeepsLogicalNamespace(t *testing.T) {
 first:=&natIdentityPort{ownershipPort:&ownershipPort{}}
 second:=&natIdentityPort{ownershipPort:&ownershipPort{}}
 a,b:=acquirePortNAT(first),acquirePortNAT(second);defer releasePortNAT(a);defer releasePortNAT(b)
 if a==b||a.port!=first||b.port!=second{t.Fatal("nil identity merged unrelated ports")}
}

func TestPhysicalNATReturnRequiresExactAttachment(t *testing.T) {
 first,second:=&portReturn{},&portReturn{}
 flow:=&forwardFlow{attachment:&attachmentUse{returnPath:second}}
 use:=&forwardUse{flow:flow}
 if first.ownsReturnUse(use){t.Fatal("another logical return accepted flow")}
 if !second.ownsReturnUse(use){t.Fatal("original logical return rejected flow")}
 if first.ownsReturnUse(nil){t.Fatal("missing flow accepted")}
}

func TestSharedPhysicalNATKeepsLogicalUDPMappingAuthority(t *testing.T) {
 physical:=&ownershipPort{}
 p1:=&natIdentityPort{ownershipPort:&ownershipPort{},physical:physical}
 p2:=&natIdentityPort{ownershipPort:&ownershipPort{},physical:physical}
 n:=acquirePortNAT(p1);defer releasePortNAT(n)
 d,_:=ownershipDispatcher(&ownershipHandler{},&ownershipWriteback{});defer d.Close()
 // Endpoint-independent mode normally shares one mapping across peer servers,
 // but a different logical graph must retain its own filtering/anchor authority.
 d.udpMapping=NATMappingEndpointIndependent
 protocol:=uint8(header.UDPProtocolNumber);address:=netip.MustParseAddr("192.0.2.1");client:=netip.MustParseAddrPort("198.18.0.1:1234")
 first,ok:=n.reserveForPort(d,p1,protocol,address,client,netip.MustParseAddrPort("203.0.113.1:443"));if !ok{t.Fatal("first reservation")};defer n.cancelReservation(protocol,first)
 second,ok:=n.reserveForPort(d,p2,protocol,address,client,netip.MustParseAddrPort("203.0.113.2:443"));if !ok{t.Fatal("second reservation")};defer n.cancelReservation(protocol,second)
 if first.mapping==second.mapping||first.selectorKey.selector==second.selectorKey.selector{t.Fatal("logical UDP mapping authority merged")}
 if first.mapping.key.logicalPort!=p1||second.mapping.key.logicalPort!=p2{t.Fatal("logical UDP owner missing")}
}

func TestSharedPhysicalNATStagesEachLogicalWriter(t *testing.T) {
 physical:=&ownershipPort{write:func([][]byte)error{t.Error("raw physical writer bypassed logical binding");return nil}}
 d,stage:=ownershipDispatcher(&ownershipHandler{},&ownershipWriteback{});defer d.Close()
 f1,f2:=newOwnershipFixture(),newOwnershipFixture();writes1,writes2:=0,0
 p1:=&natIdentityPort{ownershipPort:&ownershipPort{fixture:f1,write:func(p [][]byte)error{writes1+=len(p);return nil}},physical:physical}
 p2:=&natIdentityPort{ownershipPort:&ownershipPort{fixture:f2,write:func(p [][]byte)error{writes2+=len(p);return nil}},physical:physical};f1.port=p1;f2.port=p2
 root1,root2:=f1.flow(),f2.flow();u1,u2:=d.natFor(p1,root1),d.natFor(p2,root2);if u1==nil||u2==nil{t.Fatal("attach")}
 stage.stagePort(&forwardFlow{nat:u1.returnPath.nat,attachment:u1},[]byte{1})
 stage.stagePort(&forwardFlow{nat:u2.returnPath.nat,attachment:u2},[]byte{2})
 stage.stagePort(&forwardFlow{nat:u1.returnPath.nat,attachment:u1},[]byte{3})
 f1.retire();f2.retire();root1.Release();root2.Release();u1.release();u2.release()
 assertStillOwned(t,f1);assertStillOwned(t,f2)
 stage.Flush()
 if writes1!=2||writes2!=1{t.Fatalf("logical batches lost: %d %d",writes1,writes2)}
 waitOwnership(t,u1.returnPath.completion);waitOwnership(t,u2.returnPath.completion);waitOwnership(t,f1.closed);waitOwnership(t,f2.closed)
}
