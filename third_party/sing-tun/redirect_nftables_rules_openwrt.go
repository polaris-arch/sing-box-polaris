//go:build linux

package tun

import (
	"errors"
	"os"
	"os/exec"

	"github.com/sagernet/nftables"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/shell"
)

func (r *autoRedirect) configureOpenWRTFirewall4(nft *nftables.Conn, cleanup bool) error {
	// Never remove a pre-existing include merely because its name matches.
	if cleanup && r.fw4RulesPath == "" {
		return nil
	}
	_, err := nft.ListTableOfFamily("fw4", nftables.TableFamilyINet)
	if err != nil {
		if cleanup {
			return E.Cause(err, "fw4 cleanup pending: query firewall table")
		}
		return nil
	}
	fw4Path, err := exec.LookPath("fw4")
	if err != nil {
		if cleanup {
			return E.Cause(err, "fw4 cleanup pending: locate fw4 executable")
		}
		return nil
	}
	rulePath := "/etc/nftables.d/0-" + r.tableName + "-auto-redirect.nft"
	if !cleanup {
		err = r.createFW4Rules(rulePath, []byte(`chain input {
	type filter hook input priority filter; policy accept;
	iifname "`+r.tunOptions.Name+`" counter accept comment "!`+r.tableName+`: Accept traffic from tun"
	oifname "`+r.tunOptions.Name+`" counter accept comment "!`+r.tableName+`: Accept traffic from tun"
}
chain forward {
	type filter hook forward priority filter; policy accept;
	iifname "`+r.tunOptions.Name+`" counter accept comment "!`+r.tableName+`: Accept traffic from tun"
	oifname "`+r.tunOptions.Name+`" counter accept comment "!`+r.tableName+`: Accept traffic from tun"
}
`))
		if err != nil {
			return E.Cause(err, "write fw4 rules")
		}
	} else if !r.fw4RulesRemoved {
		err = os.Remove(r.fw4RulesPath)
		if err != nil && !os.IsNotExist(err) {
			return E.Cause(err, "clean fw4 rules")
		}
		r.fw4RulesRemoved = true
	}
	reload := func() error {
		output, reloadErr := shell.Exec(fw4Path, "reload").Read()
		if reloadErr == nil {
			return nil
		}
		return E.Extend(E.Cause(reloadErr, "reload fw4 rules"), output)
	}
	err = reload()
	if err != nil {
		var exitErr *exec.ExitError
		if !cleanup || !errors.As(err, &exitErr) || !exitErr.Exited() {
			return err
		}
		// Retry only the reload while the owner is still open. The include is
		// already gone, and an external process may have recreated that path.
		if retryErr := reload(); retryErr != nil {
			return E.Errors(err, E.Cause(retryErr, "retry fw4 cleanup"))
		}
		if r.logger != nil {
			r.logger.Warn("fw4 cleanup reload succeeded on retry after: ", err)
		}
	}
	if cleanup {
		r.fw4RulesPath = ""
		r.fw4RulesRemoved = false
	}
	return nil
}

// Exclusive creation protects unknown includes (including symlinks). This
// receipt is process-local, not a lock against later external path replacement.
func (r *autoRedirect) createFW4Rules(path string, content []byte) error {
	if r.fw4RulesPath != "" {
		return E.New("fw4 rules already created by this instance")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return E.Cause(err, "fw4 include already exists; preserve it and resolve its ownership before retrying")
		}
		return err
	}
	// Retain the receipt even if writing/closing fails, so rollback can remove
	// this instance's incomplete file rather than touching an existing include.
	r.fw4RulesPath = path
	_, writeErr := file.Write(content)
	return E.Errors(writeErr, file.Close())
}
