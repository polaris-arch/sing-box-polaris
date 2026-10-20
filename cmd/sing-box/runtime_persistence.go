package main

import (
 "os"

 box "github.com/sagernet/sing-box"
 "github.com/sagernet/sing-box/daemon"
)

func cliRuntimePersistence(entries []*OptionsEntry) (func(box.RuntimeIdentity, []byte) error, error) {
 // Even one discovered directory entry is a merge-owned source: adding a
 // second file later changes its meaning. No file is chosen on its behalf.
 if len(configDirectories) != 0 || len(configPaths) != 1 || len(entries) != 1 || entries[0].path == "stdin" { return nil, nil }
 info, err := os.Lstat(entries[0].path)
 if err != nil { return nil, err }
 if !info.Mode().IsRegular() { return nil, nil }
 return daemon.NewRuntimeFilePersistence(entries[0].path, entries[0].content)
}
