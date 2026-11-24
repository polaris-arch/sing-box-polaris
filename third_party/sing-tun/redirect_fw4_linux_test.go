//go:build linux

package tun

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/nftables"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
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
				if err := os.WriteFile(target, original, 0o600); err != nil {
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

func TestFW4MissingPrerequisitePreservesCleanupReceipt(t *testing.T) {
	for _, tableMissing := range []bool{true, false} {
		for _, cleanup := range []bool{true, false} {
			name := "executable-missing"
			if tableMissing {
				name = "table-query-failed"
			}
			if cleanup {
				name += "/cleanup"
			} else {
				name += "/startup"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				t.Setenv("PATH", dir)
				path := filepath.Join(dir, "include.nft")
				if err := os.WriteFile(path, []byte("retained rules"), 0o600); err != nil {
					t.Fatal(err)
				}
				r := &autoRedirect{}
				if cleanup {
					r.fw4RulesPath = path
				}
				calls := 0
				nft := fw4TestTable(t, func() error {
					calls++
					if tableMissing {
						return unix.EPERM
					}
					return nil
				})
				err := r.configureOpenWRTFirewall4(nft, cleanup)
				if cleanup {
					expected := error(exec.ErrNotFound)
					if tableMissing {
						expected = unix.EPERM
					}
					if !errors.Is(err, expected) || !strings.Contains(err.Error(), "fw4 cleanup pending") {
						t.Fatalf("cleanup failure hidden: %v", err)
					}
					if r.fw4RulesPath != path || r.fw4RulesRemoved {
						t.Fatal("cleanup receipt changed")
					}
				} else if err != nil {
					t.Fatalf("optional fw4 startup changed: %v", err)
				}
				if calls != 1 {
					t.Fatalf("unexpected query count: %d", calls)
				}
				body, readErr := os.ReadFile(path)
				if readErr != nil || string(body) != "retained rules" {
					t.Fatalf("include changed: %q %v", body, readErr)
				}
			})
		}
	}
}

func TestFW4CleanupRetriesOnlyReload(t *testing.T) {
	for _, mode := range []string{"transient", "persistent"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "include.nft")
			t.Setenv("PATH", dir)
			t.Setenv("FW4_TEST_INCLUDE", path)
			t.Setenv("FW4_TEST_MODE", mode)
			shim := `#!/bin/sh
set -eu
[ "$1" = reload ]
if [ ! -e "$FW4_TEST_INCLUDE" ]; then
	printf '%s\n' external > "$FW4_TEST_INCLUDE"
	echo 'first reload failed'
	exit 73
fi
read -r content < "$FW4_TEST_INCLUDE"
[ "$content" = external ]
if [ "$FW4_TEST_MODE" = persistent ]; then
	echo 'second reload failed'
	exit 74
fi
`
			if err := os.WriteFile(filepath.Join(dir, "fw4"), []byte(shim), 0o700); err != nil {
				t.Fatal(err)
			}
			r := &autoRedirect{}
			if err := r.createFW4Rules(path, []byte("owned")); err != nil {
				t.Fatal(err)
			}
			err := r.configureOpenWRTFirewall4(fw4TestTable(t, func() error { return nil }), true)
			if mode == "transient" {
				if err != nil || r.fw4RulesPath != "" || r.fw4RulesRemoved {
					t.Fatalf("successful cleanup retained receipt: err=%v path=%q removed=%v", err, r.fw4RulesPath, r.fw4RulesRemoved)
				}
			} else if err == nil || !strings.Contains(err.Error(), "first reload failed") ||
				!strings.Contains(err.Error(), "second reload failed") || r.fw4RulesPath != path || !r.fw4RulesRemoved {
				t.Fatalf("failed cleanup lost errors or receipt: err=%v path=%q removed=%v", err, r.fw4RulesPath, r.fw4RulesRemoved)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "external\n" {
				t.Fatalf("replacement include changed: content=%q err=%v", data, err)
			}
		})
	}
}

func fw4TestTable(t *testing.T, query func() error) *nftables.Conn {
	t.Helper()
	nft, err := nftables.New(nftables.WithTestDial(func(messages []netlink.Message) ([]netlink.Message, error) {
		if len(messages) != 1 || uint16(messages[0].Header.Type) != unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETTABLE {
			t.Fatalf("unexpected netlink operation: %v", messages)
		}
		if err := query(); err != nil {
			return nil, err
		}
		data, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_TABLE_NAME, Data: []byte("fw4\x00")}})
		if err != nil {
			return nil, err
		}
		return []netlink.Message{{
			Header: netlink.Header{
				Type:     netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWTABLE),
				Sequence: messages[0].Header.Sequence,
				PID:      messages[0].Header.PID,
			},
			Data: append([]byte{byte(nftables.TableFamilyINet), 0, 0, 0}, data...),
		}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nft.CloseLasting() })
	return nft
}

func TestFW4CleanupWithoutReceiptDoesNotQuery(t *testing.T) {
	r := &autoRedirect{}
	if err := r.configureOpenWRTFirewall4(nil, true); err != nil {
		t.Fatal(err)
	}
}
