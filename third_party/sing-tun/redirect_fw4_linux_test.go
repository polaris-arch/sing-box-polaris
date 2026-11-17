//go:build linux

package tun

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFW4ExclusiveInclude(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "new"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "include.nft")
			original := []byte("external rules")
			target := path
			if kind == "symlink" {
				target = filepath.Join(dir, "external.nft")
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "new" {
				if err := os.WriteFile(target, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			r := &autoRedirect{}
			err := r.createFW4Rules(path, []byte("new rules"))
			if kind == "new" {
				if err != nil || r.fw4RulesPath != path {
					t.Fatalf("err=%v receipt=%q", err, r.fw4RulesPath)
				}
				if err = r.createFW4Rules(path, []byte("replacement")); err == nil {
					t.Fatal("duplicate creation succeeded")
				}
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "new rules" {
					t.Fatalf("content=%q err=%v", data, err)
				}
			} else {
				if !errors.Is(err, os.ErrExist) || r.fw4RulesPath != "" {
					t.Fatalf("err=%v receipt=%q", err, r.fw4RulesPath)
				}
				// No receipt: cleanup returns before any netlink, file, or fw4 command.
				if err = r.configureOpenWRTFirewall4(nil, true); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(target)
				if err != nil || string(data) != string(original) {
					t.Fatalf("external content=%q err=%v", data, err)
				}
			}
		})
	}
}
