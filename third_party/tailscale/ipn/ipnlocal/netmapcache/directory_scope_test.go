package netmapcache

import (
 "context"
 "errors"
 "iter"
 "testing"
 "github.com/sagernet/tailscale/util/dirscope"
)

type forbiddenDirectoryStore struct{ t *testing.T }
func (s forbiddenDirectoryStore) List(context.Context,string) iter.Seq2[string,error] { s.t.Fatal("late List reached disk"); return nil }
func (s forbiddenDirectoryStore) Load(context.Context,string)([]byte,error) { s.t.Fatal("late Load reached disk"); return nil,nil }
func (s forbiddenDirectoryStore) Store(context.Context,string,[]byte)error { s.t.Fatal("late Store reached disk"); return nil }
func (s forbiddenDirectoryStore) Remove(context.Context,string)error { s.t.Fatal("late Remove reached disk"); return nil }
func TestDirectoryStoreSealsLazyIterationAndLateCallbacks(t *testing.T) {
 scope:=new(dirscope.Scope)
 store:=WithDirectoryScope(forbiddenDirectoryStore{t},scope)
 seq:=store.List(context.Background(),"")
 scope.Seal()
 for _,err:=range seq { if !errors.Is(err,dirscope.ErrSealed) {t.Fatal(err)} }
 if _,err:=store.Load(context.Background(),"x"); !errors.Is(err,dirscope.ErrSealed){t.Fatal(err)}
 if err:=store.Store(context.Background(),"x",nil); !errors.Is(err,dirscope.ErrSealed){t.Fatal(err)}
 if err:=store.Remove(context.Background(),"x"); !errors.Is(err,dirscope.ErrSealed){t.Fatal(err)}
}
