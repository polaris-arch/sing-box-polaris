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
				nft, err := nftables.New(nftables.WithTestDial(func(messages []netlink.Message) ([]netlink.Message, error) {
					calls++
					if len(messages) != 1 || uint16(messages[0].Header.Type) != unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETTABLE {
						t.Fatalf("unexpected netlink operation: %v", messages)
					}
					if tableMissing {
						return nil, unix.EPERM
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
				defer nft.CloseLasting()
				err = r.configureOpenWRTFirewall4(nft, cleanup)
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

func TestFW4CleanupWithoutReceiptDoesNotQuery(t *testing.T) {
	r := &autoRedirect{}
	if err := r.configureOpenWRTFirewall4(nil, true); err != nil {
		t.Fatal(err)
	}
}
