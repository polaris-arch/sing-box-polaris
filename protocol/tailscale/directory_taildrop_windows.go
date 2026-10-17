//go:build with_tailscale && windows

package tailscale

import (
 "strings"
 "path/filepath"
 "golang.org/x/sys/windows"
 "github.com/sagernet/sing/service/filemanager"
)
func(t *Endpoint)prepareTaildropDirectory()error{
 relative,err:=ownedTaildropRelative(t.server.Dir,t.taildrop.directory);if err!=nil{return err}
 d:=t.directory;d.mu.Lock();defer d.mu.Unlock();l:=d.lease
 if l==nil||l.root==0{return filemanager.MkdirAll(t.ctx,t.taildrop.directory,0o700)}
 if err:=l.checkAnchors();err!=nil{return err};parent:=l.target
 for _,name:=range strings.Split(relative,string(filepath.Separator)){
  h,err:=l.openPrivate(parent,name,true,windows.FILE_OPEN_IF,false);if err!=nil{return err};l.children=append(l.children,h);parent=h
 }
 return nil
}
