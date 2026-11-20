package tun

import (
	"errors"
	"fmt"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// Keep the exact selectors successfully installed by this instance. Priority
// ranges are not ownership: another interface may use the same priorities.
// Callers serialize access with NativeTun.ruleAccess.
type ownedLinuxRules struct {
	rules  []*netlink.Rule
	closed bool
}

func (o *ownedLinuxRules) install(rules []*netlink.Rule, add func(*netlink.Rule) error) error {
	if o.closed {
		return errors.New("routing rule owner is closed")
	}
	if len(o.rules) != 0 {
		return errors.New("previous owned routing rules have not been removed")
	}
	for i, rule := range rules {
		if rule.Priority < 0 {
			return fmt.Errorf("rule %d has no explicit priority", i)
		}
		if err := add(rule); err != nil {
			return fmt.Errorf("add rule %d/%d: %w", i, len(rules), err)
		}
		// The builder creates fresh rules; retain a private value, not a priority
		// or a regenerated rule that may differ after an interface update.
		installed := *rule
		o.rules = append(o.rules, &installed)
	}
	return nil
}

func (o *ownedLinuxRules) clear(remove func(*netlink.Rule) error) error {
	var failures []error
	remaining := o.rules[:0]
	for _, rule := range o.rules {
		err := remove(rule)
		if err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			continue
		}
		remaining = append(remaining, rule)
		failures = append(failures, fmt.Errorf("remove owned rule priority %d family %d: %w", rule.Priority, rule.Family, err))
	}
	// Release successfully removed rule objects rather than retaining them in
	// the backing array across repeated reconfiguration.
	clear(o.rules[len(remaining):])
	o.rules = remaining
	return errors.Join(failures...)
}

func (o *ownedLinuxRules) reset(build func() []*netlink.Rule, add, remove func(*netlink.Rule) error) error {
	if o.closed {
		return errors.New("routing rule owner is closed")
	}
	if err := o.clear(remove); err != nil {
		return err
	}
	if err := o.install(build(), add); err != nil {
		return errors.Join(err, o.clear(remove))
	}
	return nil
}
