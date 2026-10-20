package service

import (
 "errors"
 "fmt"
 "slices"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/common/listener"
)

type RuntimePreparedService interface{
 adapter.Service
 RuntimeValidate()error
 RuntimeResourceID()adapter.RuntimeResourceID
 PrepareRuntime(adapter.StartStage,*adapter.Scope)error
 RuntimeListeners()[]*listener.Listener
}
type runtimeStage struct{done chan struct{};err error}
func NewRuntimeManager(registry adapter.ServiceRegistry)*Manager{
 m:=NewManager(registry);m.runtime=true;m.owned=make(map[string]*adapter.Scope);m.stages=make(map[adapter.StartStage]*runtimeStage);return m
}
func(m *Manager)Insert(member adapter.Service,scope *adapter.Scope)error{
 if member==nil||member.Tag()==""{return errors.New("runtime service requires a tagged member")}
 prepared,ok:=member.(RuntimePreparedService);if !ok{return fmt.Errorf("service %s/%s lacks staged lifecycle",member.Type(),member.Tag())}
 if err:=prepared.RuntimeValidate();err!=nil{return err}
 m.access.Lock();defer m.access.Unlock()
 if !m.runtime||m.frozen{return errors.New("service inventory is immutable")}
 if _,exists:=m.serviceByTag[member.Tag()];exists{return errors.New("duplicate service tag")}
 m.services=append(m.services,member);m.serviceByTag[member.Tag()]=member
 if scope!=nil{m.owned[member.Tag()]=scope};return nil
}
func(m *Manager)Freeze()error{m.access.Lock();defer m.access.Unlock();if !m.runtime{return errors.New("not a runtime service manager")};m.frozen=true;return nil}
func(m *Manager)RuntimeFrozen()bool{m.access.Lock();defer m.access.Unlock();return m.runtime&&m.frozen}
func(m *Manager)startRuntime(stage adapter.StartStage)error{
 m.access.Lock()
 if !m.frozen{m.access.Unlock();return errors.New("service inventory is not frozen")}
 if previous:=m.stages[stage];previous!=nil{m.access.Unlock();<-previous.done;return previous.err}
 current:=&runtimeStage{done:make(chan struct{}),err:errors.New("runtime service preparation did not complete")};m.stages[stage]=current
 members:=slices.Clone(m.services);owned:=make(map[string]*adapter.Scope,len(m.owned));for tag,scope:=range m.owned{owned[tag]=scope}
 m.access.Unlock();defer close(current.done)
 for _,member:=range members{if scope:=owned[member.Tag()];scope!=nil{if err:=member.(RuntimePreparedService).PrepareRuntime(stage,scope);err!=nil{current.err=err;return err}}}
 current.err=nil;return nil
}
