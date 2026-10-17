//go:build with_tailscale && windows

package tailscale

import "fmt"

// Called after actual scope/SDK drain, before releasing any writer custody.
// A failed poison deliberately keeps all original handles until process exit.
func prepareDirectoryLeaseClose(lease *directoryLease,failure error)error{
 if lease==nil||lease.root==0||failure==nil{return nil}
 if err:=lease.revoke();err!=nil{return fmt.Errorf("directory lease: failed drain revocation; original custody retained: %w",err)}
 return nil
}
