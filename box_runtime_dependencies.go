package box

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"sort"
)

// runtimeDependencyNode describes actual constructor-captured dependencies,
// including lazy resolver/detour bindings. Tags identify configuration nodes;
// the allocator later binds their condensation to incarnation resource IDs.
type runtimeDependencyNode struct {
	name         string
	fingerprint  string
	dependencies []string
}
type runtimeCohort struct {
	members      []string
	dependencies []int
	fingerprint  string
}

// runtimeCohorts groups only actual ownership cycles. Dependencies are emitted
// before their consumers, so a new owner's outgoing reservations already exist.
func runtimeCohorts(nodes []runtimeDependencyNode) ([]runtimeCohort, error) {
	byName := make(map[string]runtimeDependencyNode, len(nodes))
	for _, node := range nodes {
		if node.name == "" {
			return nil, errors.New("empty runtime dependency name")
		}
		if _, exists := byName[node.name]; exists {
			return nil, errors.New("duplicate runtime dependency name")
		}
		copyNode := node
		copyNode.dependencies = append([]string(nil), node.dependencies...)
		sort.Strings(copyNode.dependencies)
		byName[node.name] = copyNode
	}
	for _, node := range byName {
		for _, dependency := range node.dependencies {
			if _, exists := byName[dependency]; !exists {
				return nil, errors.New("missing runtime dependency: " + dependency)
			}
		}
	}
	index, low := map[string]int{}, map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	var result []runtimeCohort
	sequence := 0
	var visit func(string)
	visit = func(name string) {
		sequence++
		index[name] = sequence
		low[name] = sequence
		stack = append(stack, name)
		onStack[name] = true
		for _, dependency := range byName[name].dependencies {
			if index[dependency] == 0 {
				visit(dependency)
				if low[dependency] < low[name] {
					low[name] = low[dependency]
				}
			} else if onStack[dependency] && index[dependency] < low[name] {
				low[name] = index[dependency]
			}
		}
		if low[name] != index[name] {
			return
		}
		var members []string
		for {
			last := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[last] = false
			members = append(members, last)
			if last == name {
				break
			}
		}
		sort.Strings(members)
		result = append(result, runtimeCohort{members: members})
	}
	var names []string
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if index[name] == 0 {
			visit(name)
		}
	}
	membership := map[string]int{}
	for i, cohort := range result {
		for _, name := range cohort.members {
			membership[name] = i
		}
	}
	for i := range result {
		seen := map[int]bool{}
		hash := sha256.New()
		for _, name := range result[i].members {
			runtimeHashField(hash, name)
			runtimeHashField(hash, byName[name].fingerprint)
			for _, dependency := range byName[name].dependencies {
				other := membership[dependency]
				if other != i {
					seen[other] = true
				}
				// Internal edge shape is part of the identity, not just its members.
				runtimeHashField(hash, dependency)
			}
		}
		result[i].fingerprint = hex.EncodeToString(hash.Sum(nil))
		for dependency := range seen {
			result[i].dependencies = append(result[i].dependencies, dependency)
		}
		sort.Ints(result[i].dependencies)
		for _, dependency := range result[i].dependencies {
			if dependency >= i {
				return nil, errors.New("invalid runtime dependency condensation")
			}
		}
	}
	return result, nil
}

func runtimeHashField(h hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	h.Write(size[:])
	h.Write([]byte(value))
}
