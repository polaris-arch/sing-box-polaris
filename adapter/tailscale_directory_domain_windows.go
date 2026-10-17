//go:build windows

package adapter

import "path/filepath"

func NewTailscaleWindowsDirectoryDomain(base,ownerNonce string)(*TailscaleDirectoryDomain,error){
 domain,err:=NewTailscaleDirectoryDomain(base,ownerNonce);if err!=nil{return nil,err}
 domain.physicalRoot=filepath.Join(base,"tailscale-windows-v1");return domain,nil
}
